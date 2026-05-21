import { describe, test, expect } from "bun:test";
import {
  checkOsv,
  checkPackageAge,
  checkTyposquat,
  levenshtein,
  verifyNpmSignatures,
} from "./integrations";

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
// verifyNpmSignatures — input validation paths (no network needed)
// ---------------------------------------------------------------------------
describe("verifyNpmSignatures input validation", () => {
  test("no signatures → no-signature status", async () => {
    const r = await verifyNpmSignatures("anything", "1.0.0", {});
    expect(r.status).toBe("no-signature");
  });

  test("empty signatures array → no-signature status", async () => {
    const r = await verifyNpmSignatures("anything", "1.0.0", { signatures: [] });
    expect(r.status).toBe("no-signature");
  });
});
