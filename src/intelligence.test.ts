import { describe, expect, test } from "bun:test";
import {
  checkOsv,
  checkPackageAge,
  checkSocket,
  checkTyposquat,
  computeCvssV3BaseScore,
  levenshtein,
  verifyNpmSignatures,
} from "./integrations";

// ---------------------------------------------------------------------------
// computeCvssV3BaseScore — CVSS v3 vector parsing
// ---------------------------------------------------------------------------
describe("computeCvssV3BaseScore", () => {
  test("CVE-2017-5638 vector → 10.0 (critical)", () => {
    // CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H — published score 10.0
    expect(
      computeCvssV3BaseScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    ).toBe(10);
  });
  test("CVSS:3.1 high vector (~7.5)", () => {
    // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — published score 7.5
    expect(
      computeCvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ).toBe(7.5);
  });
  test("CVSS:3.1 medium vector (~4.3)", () => {
    // CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N — published score 4.3
    expect(
      computeCvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    ).toBe(4.3);
  });
  test("zero-impact vector → 0", () => {
    expect(
      computeCvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    ).toBe(0);
  });
  test("non-CVSS string → undefined", () => {
    expect(computeCvssV3BaseScore("not a vector")).toBeUndefined();
    expect(
      computeCvssV3BaseScore("CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C"),
    ).toBeUndefined();
  });
  test("missing metric → undefined", () => {
    expect(computeCvssV3BaseScore("CVSS:3.1/AV:N/AC:L")).toBeUndefined();
  });

  test("invalid scope metric → undefined", () => {
    expect(
      computeCvssV3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H"),
    ).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// levenshtein — distance correctness
// ---------------------------------------------------------------------------
describe("levenshtein", () => {
  test("identical strings → 0", () => {
    expect(levenshtein("react", "react")).toBe(0);
  });
  test("single substitution → 1", () => {
    expect(levenshtein("react", "rezct")).toBe(1);
  });
  test("single insertion → 1", () => {
    expect(levenshtein("react", "reactt")).toBe(1);
  });
  test("single deletion → 1", () => {
    expect(levenshtein("react", "reac")).toBe(1);
  });
  test("transposition is 2 edits", () => {
    expect(levenshtein("lodash", "lodahs")).toBe(2);
  });
  test("empty vs string", () => {
    expect(levenshtein("", "abc")).toBe(3);
    expect(levenshtein("abc", "")).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// checkTyposquat — name-similarity vs. bundled top-package list
// ---------------------------------------------------------------------------
describe("checkTyposquat", () => {
  test("exact match against popular package", () => {
    const r = checkTyposquat("react");
    expect(r.status).toBe("checked");
    expect(r.exactMatch).toBe(true);
    expect(r.suspiciousMatches).toEqual([]);
  });

  test("close match for an off-by-one name (reactt)", () => {
    const r = checkTyposquat("reactt");
    expect(r.exactMatch).toBe(false);
    expect(r.suspiciousMatches?.length).toBeGreaterThan(0);
    expect(r.suspiciousMatches?.[0].name).toBe("react");
    expect(r.suspiciousMatches?.[0].distance).toBe(1);
  });

  test("transposition match (lodahs vs lodash)", () => {
    const r = checkTyposquat("lodahs");
    expect(r.exactMatch).toBe(false);
    expect(r.suspiciousMatches?.some((m) => m.name === "lodash")).toBe(true);
  });

  test("unrelated short name → no match", () => {
    const r = checkTyposquat("zzqx");
    expect(r.exactMatch).toBe(false);
    expect(r.suspiciousMatches).toEqual([]);
  });

  test("very short input is treated as no-match", () => {
    expect(checkTyposquat("a").suspiciousMatches).toEqual([]);
  });

  test("returns at most 5 close matches", () => {
    const r = checkTyposquat("react");
    expect((r.suspiciousMatches ?? []).length).toBeLessThanOrEqual(5);
  });
});

// ---------------------------------------------------------------------------
// checkOsv / checkPackageAge / verifyNpmSignatures — offline shortcircuit
// ---------------------------------------------------------------------------
describe("offline mode shortcircuits", () => {
  test("checkSocket offline returns skipped without fetching", async () => {
    const r = await checkSocket("react", "18.3.1", { offline: true });
    expect(r.status).toBe("skipped");
    expect(r.message).toContain("Offline");
  });

  test("checkOsv offline returns skipped without fetching", async () => {
    const r = await checkOsv("react", "18.3.1", { offline: true });
    expect(r.status).toBe("skipped");
    expect(r.message).toContain("Offline");
  });

  test("checkPackageAge offline returns skipped without fetching", async () => {
    const r = await checkPackageAge("react", "18.3.1", { offline: true });
    expect(r.status).toBe("skipped");
  });

  test("verifyNpmSignatures offline returns skipped without fetching", async () => {
    const r = await verifyNpmSignatures(
      "react",
      "18.3.1",
      { integrity: "sha512-xxx", signatures: [{ keyid: "k", sig: "s" }] },
      { offline: true },
    );
    expect(r.status).toBe("skipped");
  });
});

// ---------------------------------------------------------------------------
// top-npm-packages.json — no duplicates
// ---------------------------------------------------------------------------
import topNpmPackages from "./data/top-npm-packages.json";

describe("top-npm-packages.json", () => {
  test("contains no duplicates", () => {
    const list = topNpmPackages as string[];
    const seen = new Set<string>();
    const dupes: string[] = [];
    for (const name of list) {
      if (seen.has(name)) dupes.push(name);
      else seen.add(name);
    }
    expect(dupes).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// verifyNpmSignatures — input validation paths (no network needed)
// ---------------------------------------------------------------------------
describe("verifyNpmSignatures input validation", () => {
  test("no signatures → no-signature status", async () => {
    const r = await verifyNpmSignatures("anything", "1.0.0", {});
    expect(r.status).toBe("no-signature");
  });

  test("empty signatures array → no-signature status", async () => {
    const r = await verifyNpmSignatures("anything", "1.0.0", {
      signatures: [],
    });
    expect(r.status).toBe("no-signature");
  });
});
