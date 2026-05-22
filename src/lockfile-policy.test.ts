import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { lockfileBaselinePath, planLockfileSelection, shouldBlockLockfileInstall } from "./commands";
import { readLockfileBaseline, writeLockfileBaseline } from "./core";

function age(hours: number) {
  return { status: "checked" as const, versionAgeHours: hours };
}

function ageError() {
  return { status: "error" as const, message: "registry unavailable" };
}

describe("lockfile policy selection", () => {
  test("quiet selects only fresh versions under 24h", () => {
    const selection = planLockfileSelection(
      [{ name: "fresh-pkg", version: "1.0.0" }],
      null,
      "quiet",
      new Map([["fresh-pkg@1.0.0", age(12)]]),
    );
    expect(selection.selected).toHaveLength(1);
    expect(selection.selected[0]?.reason).toBe("fresh-version");
    expect(selection.skipped).toHaveLength(0);
  });

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

  test("strict-ci uses a 30-day freshness window", () => {
    const selected = planLockfileSelection(
      [{ name: "borderline-pkg", version: "1.0.0" }],
      null,
      "strict-ci",
      new Map([["borderline-pkg@1.0.0", age(29 * 24)]]),
    );
    const skipped = planLockfileSelection(
      [{ name: "borderline-pkg", version: "1.0.0" }],
      null,
      "strict-ci",
      new Map([["borderline-pkg@1.0.0", age(31 * 24)]]),
    );
    expect(selected.selected).toHaveLength(1);
    expect(selected.selected[0]?.reason).toBe("fresh-version");
    expect(skipped.selected).toHaveLength(0);
    expect(skipped.skipped).toHaveLength(1);
  });

  test("selects packages when freshness lookup fails", () => {
    const selection = planLockfileSelection(
      [{ name: "unknown-age-pkg", version: "1.0.0" }],
      null,
      "quiet",
      new Map([["unknown-age-pkg@1.0.0", ageError()]]),
    );
    expect(selection.selected).toHaveLength(1);
    expect(selection.selected[0]?.reason).toBe("fresh-version");
  });

  test("advisory never blocks even when high-risk findings exist", () => {
    expect(shouldBlockLockfileInstall("advisory", 1)).toBe(false);
    expect(shouldBlockLockfileInstall("default", 1)).toBe(true);
  });

  test("scan failures block unless explicitly allowed", () => {
    expect(shouldBlockLockfileInstall("default", 0, 1, false)).toBe(true);
    expect(shouldBlockLockfileInstall("advisory", 0, 1, false)).toBe(true);
    expect(shouldBlockLockfileInstall("default", 0, 1, true)).toBe(false);
  });
});

describe("lockfile baseline persistence", () => {
  test("scopes the default scan baseline under the requested cwd", () => {
    expect(lockfileBaselinePath("/tmp/project-a")).toBe("/tmp/project-a/.scguard/lockfile-baseline.json");
    expect(lockfileBaselinePath("/tmp/project-b")).toBe("/tmp/project-b/.scguard/lockfile-baseline.json");
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
