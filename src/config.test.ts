import { describe, expect, test } from "bun:test";
import {
  applyConfigEnv,
  DEFAULT_CONFIG,
  normalizeConfig,
  readOption,
} from "./core";

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
        safeResolver: "off",
      }),
    ).toEqual({
      agentReview: "codex",
      preset: "strict",
      safeResolver: "off",
    });
  });

  test("readOption rejects flag-like values after the flag name", () => {
    expect(readOption(["--preset", "--show"], "--preset")).toBeUndefined();
    expect(readOption(["--preset", "strict"], "--preset")).toBe("strict");
  });

  test("removed strict shell-session preset override maps to strict", () => {
    expect(
      applyConfigEnv(
        {
          agentReview: "none",
          preset: "strict",
          safeResolver: "off",
        },
        "enterprise",
      ),
    ).toEqual({
      agentReview: "none",
      preset: "strict",
      safeResolver: "off",
    });
  });
});
