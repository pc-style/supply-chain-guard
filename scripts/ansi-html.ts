/** Convert ANSI SGR sequences to HTML spans for terminal demo rendering. */

const ESC = "\x1b[";

const RGB: Record<string, [number, number, number]> = {
  amber: [251, 191, 36],
  green: [74, 222, 128],
  red: [248, 113, 113],
  gray: [161, 161, 170],
  dim: [113, 113, 122],
  blue: [147, 197, 253],
  white: [228, 228, 231],
};

const FALLBACK: Record<string, number> = {
  amber: 33,
  green: 32,
  red: 31,
  gray: 90,
  dim: 90,
  blue: 94,
  white: 37,
};

function rgbFromCode(code: number): [number, number, number] | null {
  for (const [name, rgb] of Object.entries(RGB)) {
    if (FALLBACK[name] === code) return rgb;
  }
  return null;
}

type Style = { fg?: string; bg?: string; bold?: boolean };

function styleToCss(s: Style): string {
  const parts: string[] = [];
  if (s.bold) parts.push("font-weight:600");
  if (s.fg) parts.push(`color:${s.fg}`);
  if (s.bg) parts.push(`background:${s.bg}`);
  return parts.join(";");
}

function parseTrueColor(params: string[]): { fg?: string; bg?: string } | null {
  if (params[0] === "38" && params[1] === "2" && params.length >= 5) {
    const [, , r, g, b] = params;
    return { fg: `rgb(${r},${g},${b})` };
  }
  if (params[0] === "48" && params[1] === "2" && params.length >= 5) {
    const [, , r, g, b] = params;
    return { bg: `rgb(${r},${g},${b})` };
  }
  return null;
}

function applySgr(style: Style, code: number): Style {
  const next = { ...style };
  if (code === 0) return {};
  if (code === 1) {
    next.bold = true;
    return next;
  }
  const rgb = rgbFromCode(code);
  if (rgb) {
    next.fg = `rgb(${rgb.join(",")})`;
    return next;
  }
  if (code >= 30 && code <= 37) {
    const rgb2 = rgbFromCode(code);
    if (rgb2) next.fg = `rgb(${rgb2.join(",")})`;
    return next;
  }
  if (code >= 90 && code <= 97) {
    const rgb2 = rgbFromCode(code - 60);
    if (rgb2) next.fg = `rgb(${rgb2.join(",")})`;
    return next;
  }
  return next;
}

export function ansiToHtml(text: string): string {
  const parts: string[] = [];
  let style: Style = {};
  let i = 0;
  let buffer = "";

  const flush = () => {
    if (!buffer) return;
    const css = styleToCss(style);
    const escaped = buffer
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
    if (css) parts.push(`<span style="${css}">${escaped}</span>`);
    else parts.push(escaped);
    buffer = "";
  };

  while (i < text.length) {
    if (text[i] === "\x1b" && text[i + 1] === "[") {
      flush();
      const end = text.indexOf("m", i);
      if (end === -1) {
        buffer += text.slice(i);
        break;
      }
      const body = text.slice(i + 2, end);
      const codes = body.split(";").filter((c) => c.length > 0);
      if (codes.length === 0) {
        style = {};
      } else {
        const tc = parseTrueColor(codes);
        if (tc) {
          style = { ...style, ...tc };
        } else {
          for (const c of codes) {
            const n = Number(c);
            if (!Number.isNaN(n)) style = applySgr(style, n);
          }
        }
      }
      i = end + 1;
      continue;
    }
    buffer += text[i];
    i++;
  }
  flush();
  return parts.join("");
}

export function ansiLinesToHtml(text: string): string[] {
  return text
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .split("\n")
    .map((line) => ansiToHtml(line));
}
