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

  test("maps removed agent mode to none", () => {
    expect(normalizeConfig({ agentReview: "both" } as never)).toEqual({
      agentReview: "none",
      preset: "default",
      safeResolver: "off",
    });
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

  test("removed shell-session preset override maps to default", () => {
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
      preset: "default",
      safeResolver: "off",
    });
  });
});
