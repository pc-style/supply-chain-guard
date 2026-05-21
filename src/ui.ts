// Terminal UI helpers matching the website demo palette.
//
// Palette (from site/styles.css):
//   prompt / accent  amber  #fbbf24  -> 251,191,36
//   ok / low risk    green  #4ade80  -> 74,222,128
//   medium risk      amber  #fbbf24
//   high / blocked   red    #f87171  -> 248,113,113
//   step / info      gray   #a1a1aa  -> 161,161,170
//   dim / paths      gray   #71717a  -> 113,113,122
//   tag / link       blue   #93c5fd  -> 147,197,253

import type { Risk } from "./core";

const ESC = "\x1b[";

function supportsColor(stream: NodeJS.WriteStream = process.stdout): boolean {
  // FORCE_COLOR explicitly opts in even when NO_COLOR is set,
  // matching the convention used by chalk/supports-color.
  if (Bun.env.FORCE_COLOR) return true;
  if (Bun.env.NO_COLOR) return false;
  if (Bun.env.SCGUARD_NO_COLOR) return false;
  return !!stream.isTTY;
}

const COLOR = supportsColor();
const TRUECOLOR =
  COLOR &&
  (Bun.env.COLORTERM === "truecolor" ||
    Bun.env.COLORTERM === "24bit" ||
    Bun.env.FORCE_COLOR === "3" ||
    Bun.env.TERM_PROGRAM === "iTerm.app" ||
    Bun.env.TERM_PROGRAM === "Apple_Terminal" ||
    Bun.env.TERM_PROGRAM === "vscode" ||
    Bun.env.TERM_PROGRAM === "ghostty" ||
    Bun.env.TERM_PROGRAM === "WezTerm" ||
    Bun.env.TERM === "xterm-ghostty" ||
    Bun.env.TERM === "xterm-kitty");

type RGB = [number, number, number];

const RGB_FALLBACK: Record<string, number> = {
  amber: 33,
  green: 32,
  red: 31,
  gray: 90,
  dim: 90,
  blue: 94,
  white: 37,
};

const RGB_TRUE: Record<string, RGB> = {
  amber: [251, 191, 36],
  green: [74, 222, 128],
  red: [248, 113, 113],
  gray: [161, 161, 170],
  dim: [113, 113, 122],
  blue: [147, 197, 253],
  white: [228, 228, 231],
};

function paint(text: string, name: keyof typeof RGB_TRUE, bold = false): string {
  if (!COLOR) return text;
  const open = TRUECOLOR
    ? `${ESC}${bold ? "1;" : ""}38;2;${RGB_TRUE[name].join(";")}m`
    : `${ESC}${bold ? "1;" : ""}${RGB_FALLBACK[name]}m`;
  const close = `${ESC}0m`;
  return `${open}${text}${close}`;
}

function bgPaint(text: string, name: keyof typeof RGB_TRUE, bold = true): string {
  if (!COLOR) return ` ${text} `;
  const fg = TRUECOLOR ? `${ESC}38;2;15;15;15m` : `${ESC}30m`;
  const bg = TRUECOLOR
    ? `${ESC}48;2;${RGB_TRUE[name].join(";")}m`
    : `${ESC}${RGB_FALLBACK[name] + 10}m`;
  const close = `${ESC}0m`;
  return `${bold ? `${ESC}1m` : ""}${fg}${bg} ${text} ${close}`;
}

export const c = {
  amber: (s: string, bold = false) => paint(s, "amber", bold),
  green: (s: string, bold = false) => paint(s, "green", bold),
  red: (s: string, bold = false) => paint(s, "red", bold),
  gray: (s: string, bold = false) => paint(s, "gray", bold),
  dim: (s: string, bold = false) => paint(s, "dim", bold),
  blue: (s: string, bold = false) => paint(s, "blue", bold),
  white: (s: string, bold = false) => paint(s, "white", bold),
};

export const style = {
  prompt: (s = "$") => c.amber(s, true),
  step: (s: string) => c.gray(s),
  dim: (s: string) => c.dim(s),
  title: (s: string) => c.amber(s, true),
  ok: () => c.green("ok", true),
  blocked: (s = "install blocked.") => c.red(s, true),
  tag: (s: string) => c.blue(s),
  arrow: () => c.blue("\u21b3"),
  bullet: () => c.amber("\u2022"),
  check: () => c.green("\u2713", true),
  cross: () => c.red("\u2717", true),
};

export function riskBadge(level: Risk | "info"): string {
  const text = level.toUpperCase().padEnd(4);
  if (level === "high") return bgPaint(text, "red");
  if (level === "medium") return bgPaint(text, "amber");
  if (level === "low") return bgPaint(text, "green");
  return bgPaint(text, "blue");
}

export function riskRow(level: Risk, where: string, what: string, why: string) {
  return `${riskBadge(level)} ${c.gray(where.padEnd(12))} ${c.white(what.padEnd(28))} ${c.dim(why)}`;
}

export function banner(version: string) {
  const sg = c.amber("sg", true);
  const title = c.amber("Supply Chain Guard", true);
  const tag = c.dim(`v${version}`);
  const tagline = c.gray("local install gate for npm and VS Code");
  const bar = c.dim("\u2500".repeat(58));
  return [bar, `${sg}  ${title}  ${tag}`, `    ${tagline}`, bar].join("\n");
}

export function header(title: string) {
  const rule = c.dim("\u2500".repeat(Math.max(0, 58 - title.length - 2)));
  return `\n${c.amber(title, true)} ${rule}`;
}

export function step(message: string) {
  console.log(`${c.amber("\u00bb", true)} ${c.gray(message)}`);
}

export function okLine(message: string) {
  console.log(`${style.ok()}  ${c.gray(message)}`);
}

export function warnLine(message: string) {
  console.log(`${c.amber("warn", true)} ${c.gray(message)}`);
}

export function failLine(message: string) {
  console.log(`${style.cross()}  ${c.gray(message)}`);
}

export function blockedLine(headline: string, detail: string) {
  console.log(`${style.blocked(headline)} ${c.gray(detail)}`);
}

export function meta(label: string, value: string) {
  console.log(`  ${c.dim(label.padEnd(10))} ${c.white(value)}`);
}

export function commandHint(label: string, cmd: string) {
  console.log(`  ${c.gray(label)}`);
  console.log(`    ${c.amber("$", true)} ${c.white(cmd)}`);
}

export class Spinner {
  private timer?: ReturnType<typeof setInterval>;
  private frame = 0;
  private readonly frames = ["\u280B", "\u2819", "\u2839", "\u2838", "\u283C", "\u2834", "\u2826", "\u2827", "\u2807", "\u280F"];
  private readonly stream: NodeJS.WriteStream;
  private readonly isTTY: boolean;

  constructor(private text: string, stream: NodeJS.WriteStream = process.stdout) {
    this.stream = stream;
    this.isTTY = !!stream.isTTY && COLOR;
  }

  start() {
    if (!this.isTTY) {
      this.stream.write(`${c.gray(this.text)}\n`);
      return this;
    }
    this.stream.write("\x1b[?25l");
    this.render();
    this.timer = setInterval(() => this.render(), 90);
    return this;
  }

  update(text: string) {
    this.text = text;
    if (this.isTTY) this.render();
  }

  succeed(text?: string) {
    this.stop();
    console.log(`${style.ok()}  ${c.gray(text ?? this.text)}`);
  }

  fail(text?: string) {
    this.stop();
    console.log(`${style.cross()}  ${c.gray(text ?? this.text)}`);
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    if (this.isTTY) {
      this.stream.write("\r\x1b[2K");
      this.stream.write("\x1b[?25h");
    }
  }

  private render() {
    const f = this.frames[this.frame = (this.frame + 1) % this.frames.length];
    this.stream.write(`\r\x1b[2K${c.amber(f, true)} ${c.gray(this.text)}`);
  }
}

export function withSpinner<T>(text: string, work: (spin: Spinner) => Promise<T>): Promise<T> {
  const spin = new Spinner(text).start();
  return work(spin)
    .then((value) => {
      spin.stop();
      return value;
    })
    .catch((error) => {
      spin.fail();
      throw error;
    });
}

export function riskWord(level: Risk): string {
  if (level === "high") return c.red(level, true);
  if (level === "medium") return c.amber(level, true);
  return c.green(level, true);
}

export function box(lines: string[]): string {
  const stripped = lines.map((l) => l.replace(/\x1b\[[0-9;]*m/g, ""));
  const width = Math.max(...stripped.map((s) => s.length));
  const top = c.dim(`\u256d${"\u2500".repeat(width + 2)}\u256e`);
  const bot = c.dim(`\u2570${"\u2500".repeat(width + 2)}\u256f`);
  const side = c.dim("\u2502");
  const body = lines.map((line, i) => {
    const pad = " ".repeat(width - stripped[i].length);
    return `${side} ${line}${pad} ${side}`;
  });
  return [top, ...body, bot].join("\n");
}
