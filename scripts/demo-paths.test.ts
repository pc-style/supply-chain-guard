import { describe, expect, test } from "bun:test";
import { normalizeDemoWorkspacePath } from "./demo-paths";

describe("normalizeDemoWorkspacePath", () => {
  test("normalizes both macOS temporary path aliases from a /var workspace", () => {
    const workspace = "/var/folders/xy/scguard-demo-123";
    const output = [workspace, `/private${workspace}`].join("\n");

    expect(normalizeDemoWorkspacePath(output, workspace)).toBe(
      "./demo\n./demo",
    );
  });

  test("normalizes both macOS temporary path aliases from a /private/var workspace", () => {
    const workspace = "/private/var/folders/xy/scguard-demo-123";
    const output = [workspace, workspace.slice("/private".length)].join("\n");

    expect(normalizeDemoWorkspacePath(output, workspace)).toBe(
      "./demo\n./demo",
    );
  });
});
