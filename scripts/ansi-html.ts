/** Convert ANSI SGR sequences to HTML spans for terminal demo rendering. */

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

function parseRgbChannel(value: string | undefined): number | null {
  if (value === undefined || !/^\d+$/.test(value)) return null;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0 || n > 255) return null;
  return n;
}

function rgbCss(r: number, g: number, b: number): string {
  return `rgb(${r},${g},${b})`;
}

function styleToCss(s: Style): string {
  const parts: string[] = [];
  if (s.bold) parts.push("font-weight:600");
  if (s.fg) parts.push(`color:${s.fg}`);
  if (s.bg) parts.push(`background:${s.bg}`);
  return parts.join(";");
}

function applySgrCode(style: Style, code: number): Style {
  if (code === 0) return {};
  const next = { ...style };
  if (code === 1) {
    next.bold = true;
    return next;
  }
  const rgb = rgbFromCode(code);
  if (rgb) {
    next.fg = rgbCss(...rgb);
    return next;
  }
  if (code >= 30 && code <= 37) {
    const rgb2 = rgbFromCode(code);
    if (rgb2) next.fg = rgbCss(...rgb2);
    return next;
  }
  if (code >= 90 && code <= 97) {
    const rgb2 = rgbFromCode(code - 60);
    if (rgb2) next.fg = rgbCss(...rgb2);
    return next;
  }
  return next;
}

/** Apply all SGR codes in one CSI sequence (e.g. 1;38;2;251;191;36). */
export function applySgrSequence(codes: string[]): Style {
  if (codes.length === 0) return {};
  let style: Style = {};
  for (let i = 0; i < codes.length; ) {
    if (codes[i] === "38" && codes[i + 1] === "2") {
      const r = parseRgbChannel(codes[i + 2]);
      const g = parseRgbChannel(codes[i + 3]);
      const b = parseRgbChannel(codes[i + 4]);
      if (r !== null && g !== null && b !== null) {
        style = { ...style, fg: rgbCss(r, g, b) };
      }
      i += 5;
      continue;
    }
    if (codes[i] === "48" && codes[i + 1] === "2") {
      const r = parseRgbChannel(codes[i + 2]);
      const g = parseRgbChannel(codes[i + 3]);
      const b = parseRgbChannel(codes[i + 4]);
      if (r !== null && g !== null && b !== null) {
        style = { ...style, bg: rgbCss(r, g, b) };
      }
      i += 5;
      continue;
    }
    const n = Number(codes[i]);
    if (!Number.isNaN(n)) style = applySgrCode(style, n);
    i += 1;
  }
  return style;
}

/** True when the CSI sequence includes SGR reset (0), not a truecolor channel value. */
function sgrSequenceHasReset(codes: string[]): boolean {
  for (let i = 0; i < codes.length; ) {
    if (codes[i] === "38" && codes[i + 1] === "2") {
      i += 5;
      continue;
    }
    if (codes[i] === "48" && codes[i + 1] === "2") {
      i += 5;
      continue;
    }
    if (codes[i] === "0") return true;
    i += 1;
  }
  return false;
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
      const delta = applySgrSequence(codes);
      // Reset (0) in a sequence clears prior styles before later codes in the same sequence.
      if (codes.length === 0 || sgrSequenceHasReset(codes)) {
        style = delta;
      } else {
        style = { ...style, ...delta };
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
