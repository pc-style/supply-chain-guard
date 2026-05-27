import { describe, expect, test } from "bun:test";
import { readOption } from "./core";
import {
  buildSkillsInstallCommand,
  DEFAULT_SKILL_NAME,
  DEFAULT_SKILL_SOURCE,
} from "./skill-install";

describe("skill install", () => {
  test("buildSkillsInstallCommand uses npx skills add", () => {
    expect(buildSkillsInstallCommand()).toEqual([
      "npx",
      "skills",
      "add",
      DEFAULT_SKILL_SOURCE,
      "-y",
      "--skill",
      DEFAULT_SKILL_NAME,
    ]);
  });

  test("readOption ignores a following flag as the value", () => {
    expect(readOption(["--project", "--dry-run"], "--project")).toBeUndefined();
    expect(
      readOption(["--skill-source", "--dry-run"], "--skill-source"),
    ).toBeUndefined();
    expect(readOption(["--project", "/tmp/proj"], "--project")).toBe(
      "/tmp/proj",
    );
  });

  test("buildSkillsInstallCommand accepts a custom source", () => {
    expect(buildSkillsInstallCommand("./skills/scguard")).toEqual([
      "npx",
      "skills",
      "add",
      "./skills/scguard",
      "-y",
      "--skill",
      DEFAULT_SKILL_NAME,
    ]);
  });
});
