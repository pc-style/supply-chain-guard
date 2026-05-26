import { describe, expect, test } from "bun:test";
import { ansiToHtml, applySgrSequence } from "./ansi-html";

describe("applySgrSequence", () => {
  test("bold + truecolor foreground", () => {
    const s = applySgrSequence(["1", "38", "2", "74", "222", "128"]);
    expect(s.bold).toBe(true);
    expect(s.fg).toBe("rgb(74,222,128)");
  });

  test("rejects invalid RGB injection", () => {
    const s = applySgrSequence(["38", "2", "74", "222", "128;color:red"]);
    expect(s.fg).toBeUndefined();
  });
});

describe("ansiToHtml", () => {
  test("preserves amber header with bold", () => {
    const html = ansiToHtml("\x1b[1;38;2;251;191;36mReport\x1b[0m");
    expect(html).toContain("font-weight:600");
    expect(html).toContain("rgb(251,191,36)");
  });

  test("escapes HTML in text", () => {
    const html = ansiToHtml("<script>");
    expect(html).toBe("&lt;script&gt;");
  });

  test("0;31 resets bold before applying red", () => {
    const html = ansiToHtml("\x1b[1mkeep\x1b[0;31mred\x1b[0m");
    expect(html).toContain("font-weight:600");
    expect(html).toContain("rgb(248,113,113)");
    expect(html).not.toMatch(/font-weight:600[^<]*rgb\(248,113,113\)/);
  });

  test("truecolor with zero channel does not reset prior styles", () => {
    const html = ansiToHtml("\x1b[1m\x1b[38;2;0;255;0mgreen\x1b[0m");
    expect(html).toContain("font-weight:600");
    expect(html).toContain("rgb(0,255,0)");
  });

  test("bold + truecolor with zero channel in one sequence", () => {
    const html = ansiToHtml("\x1b[1;38;2;0;255;0mgreen\x1b[0m");
    expect(html).toContain("font-weight:600");
    expect(html).toContain("rgb(0,255,0)");
  });

  test("truecolor background with zero channel does not reset styles", () => {
    const html = ansiToHtml("\x1b[1m\x1b[48;2;0;40;0mcell\x1b[0m");
    expect(html).toContain("font-weight:600");
    expect(html).toContain("background:rgb(0,40,0)");
  });

  test("48;2 background zero channel in combined sequence keeps prior bold", () => {
    const html = ansiToHtml("\x1b[1;48;2;0;40;0mcell\x1b[0m");
    expect(html).toContain("font-weight:600");
    expect(html).toContain("background:rgb(0,40,0)");
  });
});
