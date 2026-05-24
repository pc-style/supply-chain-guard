import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { analyzeDirectory, isRegistryVersionSpec, resolveNpmVersion } from "./analysis";
import { classifyPackageCommand, findPackageSubcommand, nonOptionTokens, planLockfileSelection } from "./commands";
import { parseNpm } from "./lockfile";

describe("security regressions", () => {
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "scguard-sec-"));
    await mkdir(tmpDir, { recursive: true });
    await writeFile(join(tmpDir, "package.json"), JSON.stringify({ name: "demo", version: "1.0.0" }));
  });

  afterAll(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  test("rejects non-registry version specs", () => {
    expect(isRegistryVersionSpec("file:/tmp/evil.tgz")).toBe(false);
    expect(isRegistryVersionSpec("github:attacker/repo")).toBe(false);
    expect(isRegistryVersionSpec("git+https://evil.example/pkg.git")).toBe(false);
    expect(isRegistryVersionSpec("^4.0.0")).toBe(true);
    expect(isRegistryVersionSpec("latest")).toBe(true);
  });

  test("resolveNpmVersion fails closed for protocol specs", () => {
    const versions = ["1.0.0", "2.0.0"];
    expect(resolveNpmVersion(versions, { latest: "2.0.0" }, "file:/tmp/evil.tgz")).toBeUndefined();
    expect(resolveNpmVersion(versions, { latest: "2.0.0" }, "^1")).toBe("1.0.0");
  });

  test("findPackageSubcommand skips leading directory options", () => {
    expect(findPackageSubcommand(["--prefix", "/tmp/proj", "install", "lodash"])).toBe("install");
    expect(findPackageSubcommand(["-C", "/tmp/proj", "add", "lodash"])).toBe("add");
    expect(findPackageSubcommand(["--cwd", "/tmp/proj", "add", "lodash"])).toBe("add");
  });

  test("npm stage approve is detected with leading global options", () => {
    const result = classifyPackageCommand("npm", ["--otp=123456", "stage", "approve", "stage-abc"]);
    expect(result.packageOperation).toBe(true);
    expect(result.kind).toBe("npm-stage");
    expect(result.specs).toEqual(["stage-abc"]);
  });

  test("npm install with --prefix is still a guarded package operation", () => {
    const result = classifyPackageCommand("npm", ["--prefix", "/tmp/app", "install", "lodash"]);
    expect(result.packageOperation).toBe(true);
    expect(result.action).toBe("install");
    expect(result.specs).toEqual(["lodash"]);
  });

  test("workspace selector is not treated as a package spec", () => {
    expect(nonOptionTokens(["install", "--workspace", "react"])).toEqual(["install"]);
    const result = classifyPackageCommand("npm", ["install", "--workspace", "react"]);
    expect(result.packageOperation).toBe(true);
    expect(result.specs).toEqual([]);
  });

  test("--workspaces is a boolean flag, not value-taking", () => {
    expect(findPackageSubcommand(["--workspaces", "install", "lodash"])).toBe("install");
    const result = classifyPackageCommand("npm", ["--workspaces", "install", "lodash"]);
    expect(result.packageOperation).toBe(true);
    expect(result.action).toBe("install");
    expect(result.specs).toEqual(["lodash"]);
  });

  test("default preset scans entire lockfile when no baseline exists", () => {
    const selection = planLockfileSelection(
      [{ name: "old-pkg", version: "9.9.9" }],
      null,
      "default",
      new Map([["old-pkg@9.9.9", { status: "checked", versionAgeHours: 24 * 365 }]]),
    );
    expect(selection.selected).toHaveLength(1);
    expect(selection.selected[0]?.reason).toBe("policy");
  });

  test("socket elevated supplyChainRisk produces a finding", async () => {
    const report = await analyzeDirectory("demo@1.0.0", "npm", tmpDir, "local", undefined, {
      socket: { status: "checked", supplyChainRisk: 0.9 },
    });
    expect(report.findings.some((f) => f.id === "socket.supply-chain-risk")).toBe(true);
    expect(report.findings.find((f) => f.id === "socket.supply-chain-risk")?.severity).toBe("high");
  });

  test("parseNpm preserves resolved tarball URL and integrity", () => {
    const text = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "node_modules/evil": {
          version: "1.0.0",
          resolved: "https://evil.example/evil-1.0.0.tgz",
          integrity: "sha512-deadbeef",
        },
      },
    });
    const entries = parseNpm(text);
    expect(entries[0]).toEqual({
      name: "evil",
      version: "1.0.0",
      resolved: "https://evil.example/evil-1.0.0.tgz",
      integrity: "sha512-deadbeef",
    });
  });
});
