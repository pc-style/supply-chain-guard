import { describe, expect, test } from "bun:test";
import {
  applyConfigEnv,
  DEFAULT_CONFIG,
  normalizeConfig,
  readOption,
} from "./core";

describe("config normalization", () => {
  test("defaults are preset-aware", () => {
    expect(normalizeConfig(undefined)).toEqual(DEFAULT_CONFIG);
  });

  test("loads old agentReview-only config", () => {
    expect(normalizeConfig({ agentReview: "both" })).toEqual({
      agentReview: "both",
      preset: "default",
      safeResolver: "suggest",
    });
  });

  test("keeps explicit policy fields", () => {
    expect(
      normalizeConfig({
        agentReview: "codex",
        preset: "quiet",
        safeResolver: "off",
      }),
    ).toEqual({
      agentReview: "codex",
      preset: "quiet",
      safeResolver: "off",
    });
  });

  test("readOption rejects flag-like values after the flag name", () => {
    expect(readOption(["--preset", "--show"], "--preset")).toBeUndefined();
    expect(readOption(["--preset", "quiet"], "--preset")).toBe("quiet");
  });

  test("applies shell-session preset override", () => {
    expect(
      applyConfigEnv(
        {
          agentReview: "none",
          preset: "default",
          safeResolver: "suggest",
        },
        "enterprise",
      ),
    ).toEqual({
      agentReview: "none",
      preset: "enterprise",
      safeResolver: "suggest",
    });
  });
});
