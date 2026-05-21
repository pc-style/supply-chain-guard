import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildInstallCommand,
  detectPackageManager,
  isPackageManager,
  readPmFlag,
} from "./pm";

let workDir = "";

beforeAll(async () => {
  workDir = await mkdtemp(join(tmpdir(), "scguard-pm-"));
});

afterAll(async () => {
  if (workDir) await rm(workDir, { recursive: true, force: true });
});

async function fixture(name: string, files: Record<string, string>) {
  const dir = await mkdtemp(join(workDir, `${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    await writeFile(join(dir, rel), content);
  }
  return dir;
}

describe("readPmFlag", () => {
  test("parses --pm <value>", () => {
    expect(readPmFlag(["--pm", "npm"])).toBe("npm");
  });
  test("parses --pm=<value>", () => {
    expect(readPmFlag(["--pm=pnpm"])).toBe("pnpm");
  });
  test("returns undefined when missing", () => {
    expect(readPmFlag(["--dev"])).toBeUndefined();
  });
});

describe("isPackageManager", () => {
  test("accepts known names", () => {
    for (const pm of ["bun", "npm", "pnpm", "yarn"]) {
      expect(isPackageManager(pm)).toBe(true);
    }
  });
  test("rejects unknown names", () => {
    expect(isPackageManager("rush")).toBe(false);
    expect(isPackageManager(undefined)).toBe(false);
  });
});

describe("detectPackageManager", () => {
  test("explicit --pm flag wins over everything", async () => {
    const dir = await fixture("flag-wins", { "bun.lock": "", "package.json": "{}" });
    const detected = detectPackageManager(dir, ["--pm", "pnpm"]);
    expect(detected.pm).toBe("pnpm");
    expect(detected.source).toBe("flag");
  });

  test("rejects invalid --pm flag value", async () => {
    const dir = await fixture("flag-invalid", {});
    expect(() => detectPackageManager(dir, ["--pm", "rush"])).toThrow();
  });

  test("bun.lock => bun", async () => {
    const dir = await fixture("lock-bun", { "bun.lock": "" });
    expect(detectPackageManager(dir).pm).toBe("bun");
  });

  test("bun.lockb => bun", async () => {
    const dir = await fixture("lock-bunb", { "bun.lockb": "" });
    expect(detectPackageManager(dir).pm).toBe("bun");
  });

  test("pnpm-lock.yaml => pnpm", async () => {
    const dir = await fixture("lock-pnpm", { "pnpm-lock.yaml": "" });
    expect(detectPackageManager(dir).pm).toBe("pnpm");
  });

  test("yarn.lock => yarn", async () => {
    const dir = await fixture("lock-yarn", { "yarn.lock": "" });
    expect(detectPackageManager(dir).pm).toBe("yarn");
  });

  test("package-lock.json => npm", async () => {
    const dir = await fixture("lock-npm", { "package-lock.json": "{}" });
    expect(detectPackageManager(dir).pm).toBe("npm");
  });

  test("packageManager field used when no lockfile", async () => {
    const dir = await fixture("pkg-mgr", {
      "package.json": JSON.stringify({ packageManager: "pnpm@9.0.0" }),
    });
    const detected = detectPackageManager(dir);
    expect(detected.pm).toBe("pnpm");
    expect(detected.source).toBe("packageManager");
  });

  test("ignores unknown packageManager value", async () => {
    const dir = await fixture("pkg-mgr-unknown", {
      "package.json": JSON.stringify({ packageManager: "rush@1.0.0" }),
    });
    const detected = detectPackageManager(dir);
    expect(detected.source).toBe("default");
    expect(detected.pm).toBe("bun");
  });

  test("default falls back to bun", async () => {
    const dir = await fixture("default", {});
    const detected = detectPackageManager(dir);
    expect(detected.pm).toBe("bun");
    expect(detected.source).toBe("default");
  });
});

describe("buildInstallCommand", () => {
  test("bun add", () => {
    expect(buildInstallCommand("bun", ["react"]))
      .toEqual({ cmd: "bun", args: ["add", "react"] });
  });
  test("bun add --dev", () => {
    expect(buildInstallCommand("bun", ["react"], { dev: true }))
      .toEqual({ cmd: "bun", args: ["add", "--dev", "react"] });
  });
  test("npm install --save-dev", () => {
    expect(buildInstallCommand("npm", ["react"], { dev: true }))
      .toEqual({ cmd: "npm", args: ["install", "--save-dev", "react"] });
  });
  test("pnpm add --save-dev", () => {
    expect(buildInstallCommand("pnpm", ["react"], { dev: true }))
      .toEqual({ cmd: "pnpm", args: ["add", "--save-dev", "react"] });
  });
  test("yarn add --dev", () => {
    expect(buildInstallCommand("yarn", ["react"], { dev: true }))
      .toEqual({ cmd: "yarn", args: ["add", "--dev", "react"] });
  });
  test("multiple specs", () => {
    expect(buildInstallCommand("npm", ["react", "lodash@4"]))
      .toEqual({ cmd: "npm", args: ["install", "react", "lodash@4"] });
  });
});
