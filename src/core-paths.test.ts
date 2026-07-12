import { describe, expect, test } from "bun:test";
import { configBaseDir } from "./core";

describe("configBaseDir", () => {
  test("falls back to the home config directory for empty XDG values", () => {
    expect(configBaseDir("", "/home/user")).toBe("/home/user/.config");
    expect(configBaseDir("   ", "/home/user")).toBe("/home/user/.config");
  });

  test("uses a non-empty XDG config directory", () => {
    expect(configBaseDir("/tmp/config", "/home/user")).toBe("/tmp/config");
  });
});
