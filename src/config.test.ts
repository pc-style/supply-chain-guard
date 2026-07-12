import { describe, expect, test } from "bun:test";
import { DEFAULT_CONFIG, normalizeConfig, readOption } from "./core";

describe("config normalization", () => {
  test("defaults are minimal", () => {
    expect(normalizeConfig(undefined)).toEqual(DEFAULT_CONFIG);
  });

  test("removed both agent mode fails closed", () => {
    expect(() => normalizeConfig({ agentReview: "both" } as never)).toThrow(
      "agentReview 'both' was removed",
    );
  });

  test("keeps explicit supported policy fields", () => {
    expect(
      normalizeConfig({
        agentReview: "codex",
        preset: "strict",
      }),
    ).toEqual({
      agentReview: "codex",
      preset: "strict",
    });
  });

  test("readOption rejects flag-like values after the flag name", () => {
    expect(readOption(["--preset", "--show"], "--preset")).toBeUndefined();
    expect(readOption(["--preset", "strict"], "--preset")).toBe("strict");
  });

  test("silently drops legacy safeResolver config", () => {
    expect(
      normalizeConfig({
        agentReview: "none",
        preset: "default",
        safeResolver: "suggest",
      }),
    ).toEqual(DEFAULT_CONFIG);
  });
});
