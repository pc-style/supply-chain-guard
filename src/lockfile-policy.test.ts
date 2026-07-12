import { afterEach, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  lockfileBaselinePath,
  planLockfileSelection,
  scanLockfileCommand,
  shouldBlockLockfileInstall,
} from "./commands";
import { readLockfileBaseline, writeLockfileBaseline } from "./core";

function age(hours: number) {
  return { status: "checked" as const, versionAgeHours: hours };
}

function ageError() {
  return { status: "error" as const, message: "registry unavailable" };
}

const originalCwd = process.cwd();
const originalNoColor = Bun.env.SCGUARD_NO_COLOR;

afterEach(() => {
  process.chdir(originalCwd);
  restoreEnv("SCGUARD_NO_COLOR", originalNoColor);
});

function restoreEnv(name: string, value: string | undefined) {
  if (value === undefined) {
    delete Bun.env[name];
  } else {
    Bun.env[name] = value;
  }
}

async function writeTestBunLock(dir: string) {
  await writeFile(
    join(dir, "bun.lock"),
    `{
  "lockfileVersion": 1,
  "packages": {
    "@scguard-plan/never-published-alpha": ["@scguard-plan/never-published-alpha@1.0.0", ""],
    "scguard-plan-never-published-beta": ["scguard-plan-never-published-beta@2.0.0", ""]
  }
}
`,
  );
}

async function captureStdout(run: () => Promise<unknown>) {
  const original = console.log;
  const lines: string[] = [];
  console.log = (...args: unknown[]) => {
    lines.push(args.map(String).join(" "));
  };
  try {
    await run();
  } finally {
    console.log = original;
  }
  return lines.join("\n");
}

function stripAnsi(text: string) {
  return text.replace(/\x1b\[[0-9;]*m/g, "");
}

describe("lockfile policy selection", () => {
  test("default skips old unchanged packages when baseline matches", () => {
    const selection = planLockfileSelection(
      [{ name: "stable-pkg", version: "1.0.0" }],
      {
        schemaVersion: 1,
        generatedAt: "2026-05-22T00:00:00Z",
        entries: [{ name: "stable-pkg", version: "1.0.0" }],
      },
      "default",
      new Map([["stable-pkg@1.0.0", age(240)]]),
    );
    expect(selection.selected).toHaveLength(0);
    expect(selection.skipped).toHaveLength(1);
    expect(selection.skipped[0]?.reason).toBe("baseline-unchanged");
  });

  test("default selects changed packages from the saved baseline", () => {
    const selection = planLockfileSelection(
      [{ name: "changed-pkg", version: "1.0.1" }],
      {
        schemaVersion: 1,
        generatedAt: "2026-05-22T00:00:00Z",
        entries: [{ name: "changed-pkg", version: "1.0.0" }],
      },
      "default",
      new Map([["changed-pkg@1.0.1", age(240)]]),
    );
    expect(selection.selected).toHaveLength(1);
    expect(selection.selected[0]?.reason).toBe("changed-lockfile-entry");
  });

  test("selects the same version when the resolved URL changes", () => {
    const selection = planLockfileSelection(
      [
        {
          name: "swapped-pkg",
          version: "1.0.0",
          resolved: "https://registry.npmjs.org/swapped-pkg/-/new.tgz",
          integrity: "sha512-same",
        },
      ],
      {
        schemaVersion: 1,
        generatedAt: "2026-05-22T00:00:00Z",
        entries: [
          {
            name: "swapped-pkg",
            version: "1.0.0",
            resolved: "https://registry.npmjs.org/swapped-pkg/-/old.tgz",
            integrity: "sha512-same",
          },
        ],
      },
      "default",
      new Map([["swapped-pkg@1.0.0", age(240)]]),
    );
    expect(selection.selected[0]?.reason).toBe("changed-lockfile-entry");
  });

  test("selects the same version when integrity changes", () => {
    const selection = planLockfileSelection(
      [
        {
          name: "swapped-pkg",
          version: "1.0.0",
          resolved: "https://registry.npmjs.org/swapped-pkg/-/pkg.tgz",
          integrity: "sha512-new",
        },
      ],
      {
        schemaVersion: 1,
        generatedAt: "2026-05-22T00:00:00Z",
        entries: [
          {
            name: "swapped-pkg",
            version: "1.0.0",
            resolved: "https://registry.npmjs.org/swapped-pkg/-/pkg.tgz",
            integrity: "sha512-old",
          },
        ],
      },
      "default",
      new Map([["swapped-pkg@1.0.0", age(240)]]),
    );
    expect(selection.selected[0]?.reason).toBe("changed-lockfile-entry");
  });

  test("treats legacy name and version baselines as unchanged", () => {
    const selection = planLockfileSelection(
      [
        {
          name: "legacy-pkg",
          version: "1.0.0",
          resolved: "https://registry.npmjs.org/legacy-pkg/-/pkg.tgz",
          integrity: "sha512-current",
        },
      ],
      {
        schemaVersion: 1,
        generatedAt: "2026-05-22T00:00:00Z",
        entries: [{ name: "legacy-pkg", version: "1.0.0" }],
      },
      "default",
      new Map([["legacy-pkg@1.0.0", age(240)]]),
    );
    expect(selection.selected).toHaveLength(0);
    expect(selection.skipped[0]?.reason).toBe("baseline-unchanged");
  });

  test("strict uses a 30-day freshness window once a baseline exists", () => {
    const baseline = {
      schemaVersion: 1 as const,
      generatedAt: "2026-05-22T00:00:00Z",
      entries: [{ name: "borderline-pkg", version: "1.0.0" }],
    };
    const selected = planLockfileSelection(
      [{ name: "borderline-pkg", version: "1.0.0" }],
      baseline,
      "strict",
      new Map([["borderline-pkg@1.0.0", age(29 * 24)]]),
    );
    const skipped = planLockfileSelection(
      [{ name: "borderline-pkg", version: "1.0.0" }],
      baseline,
      "strict",
      new Map([["borderline-pkg@1.0.0", age(31 * 24)]]),
    );
    expect(selected.selected).toHaveLength(1);
    expect(selected.selected[0]?.reason).toBe("fresh-version");
    expect(skipped.selected).toHaveLength(0);
    expect(skipped.skipped).toHaveLength(1);
  });

  test("strict scans the full lockfile when no baseline exists", () => {
    const selection = planLockfileSelection(
      [{ name: "old-pkg", version: "1.0.0" }],
      null,
      "strict",
      new Map([["old-pkg@1.0.0", age(400 * 24)]]),
    );
    expect(selection.selected).toHaveLength(1);
    expect(selection.selected[0]?.reason).toBe("policy");
  });

  test("selects packages when freshness lookup fails", () => {
    const selection = planLockfileSelection(
      [{ name: "unknown-age-pkg", version: "1.0.0" }],
      null,
      "default",
      new Map([["unknown-age-pkg@1.0.0", ageError()]]),
    );
    expect(selection.selected).toHaveLength(1);
    expect(selection.selected[0]?.reason).toBe("policy");
  });

  test("blocking findings block under supported presets", () => {
    expect(shouldBlockLockfileInstall("default", 1)).toBe(true);
    expect(shouldBlockLockfileInstall("strict", 1)).toBe(true);
  });

  test("scan failures always block", () => {
    expect(shouldBlockLockfileInstall("default", 0, 1)).toBe(true);
    expect(shouldBlockLockfileInstall("strict", 0, 1)).toBe(true);
  });
});

describe("lockfile baseline persistence", () => {
  test("scopes the default scan baseline under the requested cwd", () => {
    expect(lockfileBaselinePath("/tmp/project-a")).toBe(
      "/tmp/project-a/.scguard/lockfile-baseline.json",
    );
    expect(lockfileBaselinePath("/tmp/project-b")).toBe(
      "/tmp/project-b/.scguard/lockfile-baseline.json",
    );
  });

  test("round-trips a saved baseline file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "scguard-baseline-"));
    const path = join(dir, "baseline.json");
    const baseline = {
      schemaVersion: 1 as const,
      generatedAt: "2026-05-22T00:00:00Z",
      kind: "bun",
      entries: [
        { name: "alpha", version: "1.0.0" },
        { name: "beta", version: "2.0.0" },
      ],
    };
    try {
      await writeLockfileBaseline(baseline, path);
      expect(await readLockfileBaseline(path)).toEqual(baseline);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("scan-lockfile plan mode", () => {
  test("previews a directory scan without scanning packages, writing reports, or updating baseline", async () => {
    const dir = await mkdtemp(join(tmpdir(), "scguard-plan-"));
    Bun.env.SCGUARD_NO_COLOR = "1";
    process.chdir(dir);
    try {
      await writeTestBunLock(dir);
      let summary: Awaited<ReturnType<typeof scanLockfileCommand>> | undefined;
      const output = await captureStdout(async () => {
        summary = await scanLockfileCommand(["--plan", "--offline"]);
      });
      const plainOutput = stripAnsi(output);

      expect(summary).toBeDefined();
      expect(summary?.selected).toBe(2);
      expect(summary?.skipped).toBe(0);
      expect(summary?.scanned).toBe(0);
      expect(summary?.failed).toEqual([]);
      expect(summary?.blocked).toEqual([]);
      expect(summary?.warnings).toEqual([]);
      expect(summary?.baselineUpdated).toBe(false);
      expect(summary?.blockInstall).toBe(false);
      expect(existsSync(join(dir, ".scguard", "lockfile-baseline.json"))).toBe(
        false,
      );
      expect(existsSync(join(dir, ".scguard", "reports"))).toBe(false);
      expect(plainOutput).toContain("selected: 2");
      expect(plainOutput).toContain("skipped: 0");
      expect(plainOutput).toContain(
        "@scguard-plan/never-published-alpha@1.0.0 reason=policy",
      );
      expect(plainOutput).toContain(
        "preview only; no package scans, reports, or baseline updates were run",
      );
      expect(plainOutput).toContain("next: scguard scan-lockfile . --offline");
      expect(plainOutput).not.toContain("scanned  2/2");
      expect(plainOutput).not.toContain("baseline updated");
      expect(plainOutput).not.toContain("packages could not be analyzed");
    } finally {
      process.chdir(originalCwd);
      await rm(dir, { recursive: true, force: true });
    }
  });
});
