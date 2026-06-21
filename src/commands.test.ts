import { describe, expect, test } from "bun:test";
import { classifyPackageCommand } from "./commands";

describe("classifyPackageCommand", () => {
  test("detects npm install when global option with value appears first", () => {
    const result = classifyPackageCommand("npm", ["--prefix", "./app", "install", "left-pad"]);
    expect(result.packageOperation).toBe(true);
    expect(result.action).toBe("install");
    expect(result.specs).toEqual(["left-pad"]);
  });

  test("detects pnpm add when short global option with value appears first", () => {
    const result = classifyPackageCommand("pnpm", ["-C", "./app", "add", "lodash"]);
    expect(result.packageOperation).toBe(true);
    expect(result.action).toBe("add");
    expect(result.specs).toEqual(["lodash"]);
  });

  test("detects yarn add when long global option with value appears first", () => {
    const result = classifyPackageCommand("yarn", ["--cwd", "./app", "add", "react"]);
    expect(result.packageOperation).toBe(true);
    expect(result.action).toBe("add");
    expect(result.specs).toEqual(["react"]);
  });
});
