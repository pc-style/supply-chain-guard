#!/usr/bin/env bun
/**
 * Capture real scguard CLI output for site demos and README screenshots.
 */
import { mkdir, rm, writeFile, copyFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { ansiLinesToHtml } from "./ansi-html";

const ROOT = join(import.meta.dir, "..");
const CLI = join(ROOT, "src", "cli.ts");
const SITE_DATA = join(ROOT, "site", "demo-data");
const DEMO_VSIX = join(ROOT, "scripts", "assets", "demo-theme.vsix");
const DEMO_EXT = join(ROOT, "scripts", "assets", "demo-extension");

const baseEnv: Record<string, string> = {
  ...process.env,
  FORCE_COLOR: "3",
  SCGUARD_OFFLINE: "1",
  SCGUARD_SHELL_HOOK_ACTIVE: "1",
  SCGUARD_SUPPRESS_HOOK_WARN: "1",
  TERM: "xterm-256color",
  COLORTERM: "truecolor",
};
delete baseEnv.NO_COLOR;

type DemoSpec = {
  slug: string;
  title: string;
  command: string;
  reportLabel: string;
  run: (ws: string) => Promise<string>;
};

function stripAnsi(line: string): string {
  return line.replace(/\x1b\[[0-9;]*m/g, "");
}

/** Drop noise that should never appear in marketing demos. */
function sanitizeForDemo(text: string): string {
  const lines = text.split("\n").filter((line) => {
    const plain = stripAnsi(line).trim();
    if (!plain) return true;
    if (/shell hook not active/i.test(plain)) return false;
    if (/^\(node:\d+\) Warning:/i.test(plain)) return false;
    if (/trace-warnings/i.test(plain)) return false;
    if (/VERY VERY EARLY STAGE/i.test(plain)) return false;
    if (/^WARNING:/i.test(plain) && /EARLY STAGE/i.test(plain)) return false;
    if (/scguard:\s*using npm/i.test(plain)) return false;
    if (/Treat it as a warning layer/i.test(plain)) return false;
    if (/It can miss malicious packages/i.test(plain)) return false;
    return true;
  });
  return lines.join("\n").replace(/\n{3,}/g, "\n\n").trim();
}

function normalizeOutput(text: string, ws: string, reportLabel: string): string {
  const displayWs = "./demo";
  return sanitizeForDemo(
    text
      .replaceAll(ws, displayWs)
      .replace(/\/tmp\/scguard-demo-[a-z0-9-]+/g, displayWs)
      .replace(
        /\.scguard\/reports\/[^\s]+?-\d+\.(json|md|txt)/g,
        `.scguard/reports/${reportLabel}.$1`,
      )
      .replace(
        /\.scguard\/reports\/[^\s]+?-\d+-codex-prompt\.md/g,
        `.scguard/reports/${reportLabel}-codex-prompt.md`,
      )
      .replace(
        /\.scguard\/reports\/[^\s]+?-\d+-pi-prompt\.md/g,
        `.scguard/reports/${reportLabel}-pi-prompt.md`,
      ),
  );
}

function runCmd(
  cmd: string,
  args: string[],
  opts: { cwd?: string; env?: Record<string, string> } = {},
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: { ...baseEnv, ...opts.env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ stdout, stderr, code: code ?? 1 }));
  });
}

async function scguard(args: string[], cwd: string, extraEnv?: Record<string, string>): Promise<string> {
  const { stdout, stderr } = await runCmd("bun", ["run", CLI, ...args], { cwd, env: extraEnv });
  return stdout + (stderr ? (stdout ? "\n" : "") + stderr : "");
}

async function ensureDemoVsix(): Promise<void> {
  const { code } = await runCmd("test", ["-f", DEMO_VSIX]);
  if (code === 0) return;
  await runCmd("bash", [
    "-c",
    `cd "${DEMO_EXT}" && zip -qr "${DEMO_VSIX}" extension extension.vsixmanifest`,
  ]);
}

async function makeWorkspace(): Promise<string> {
  const ws = join(tmpdir(), `scguard-demo-${Date.now()}`);
  await rm(ws, { recursive: true, force: true });
  await mkdir(ws, { recursive: true });
  await writeFile(
    join(ws, "package.json"),
    JSON.stringify({ name: "scguard-demo", private: true, version: "0.0.0" }, null, 2),
  );
  return ws;
}

const demos: DemoSpec[] = [
  {
    slug: "scan-npm",
    title: "scanning an npm package",
    command: "scguard review chalk@5.4.1",
    reportLabel: "chalk@5.4.1-report",
    run: async (ws) => scguard(["review", "chalk@5.4.1"], ws),
  },
  {
    slug: "add-withheld",
    title: "staged without installing",
    command: "scguard review chalk@5.4.1",
    reportLabel: "chalk@5.4.1-report",
    run: async (ws) => {
      const out = await scguard(["review", "chalk@5.4.1"], ws);
      const lines = out.split("\n");
      const start = lines.findIndex((l) => stripAnsi(l).includes("Next steps"));
      return start >= 0 ? lines.slice(Math.max(0, start - 8)).join("\n") : out;
    },
  },
  {
    slug: "add-approved",
    title: "install after approval",
    command: "scguard install is-number@7.0.0",
    reportLabel: "is-number@7.0.0-report",
    run: async (ws) => {
      const out = await scguard(["install", "is-number@7.0.0", "--pm", "npm"], ws, {
        NODE_NO_WARNINGS: "1",
      });
      const lines = out.split("\n");
      const end = lines.findIndex((l) => stripAnsi(l).includes("found 0 vulnerabilities"));
      if (end >= 0) return lines.slice(0, end + 1).join("\n");
      return out;
    },
  },
  {
    slug: "block-broad-update",
    title: "blocking a broad update",
    command: "bun update",
    reportLabel: "unused",
    run: async (ws) => scguard(["guard", "bun", "update"], ws),
  },
  {
    slug: "scan-vsix",
    title: "scanning a vsix extension",
    command: "scguard scan-vsix ./demo-theme.vsix",
    reportLabel: "demo-theme-report",
    run: async (ws) => {
      await copyFile(DEMO_VSIX, join(ws, "demo-theme.vsix"));
      return scguard(["scan-vsix", "demo-theme.vsix"], ws);
    },
  },
  {
    slug: "generated-reports",
    title: "generated reports",
    command: "ls .scguard/reports/",
    reportLabel: "chalk@5.4.1-report",
    run: async (ws) => {
      await scguard(["review", "chalk@5.4.1"], ws);
      const reports = join(ws, ".scguard", "reports");
      const files = (await readdir(reports)).sort();
      const listing = files
        .map((f) =>
          f
            .replace(/chalk@5\.4\.1-\d+/, "chalk@5.4.1-report")
            .replace(/-codex-prompt\.md$/, "-codex-prompt.md")
            .replace(/-pi-prompt\.md$/, "-pi-prompt.md"),
        )
        .map((f) => `  ${f}`)
        .join("\n");
      const sample = files.find((f) => f.endsWith(".md") && !f.includes("prompt"));
      let preview = "";
      if (sample) {
        const { stdout } = await runCmd("head", ["-n", "12", join(reports, sample)], { cwd: ws });
        preview = `\n$ head -12 .scguard/reports/chalk@5.4.1-report.md\n${stdout}`;
      }
      return `${listing}${preview}`;
    },
  },
];

async function main() {
  await ensureDemoVsix();
  await mkdir(SITE_DATA, { recursive: true });

  console.log("Capturing demo output from live scguard runs…");

  for (const demo of demos) {
    const ws = await makeWorkspace();
    try {
      let raw = await demo.run(ws);
      raw = normalizeOutput(raw, ws, demo.reportLabel);
      const full = `$ ${demo.command}\n${raw.trim()}`;
      const payload = {
        slug: demo.slug,
        title: demo.title,
        command: demo.command,
        cwd: "./demo",
        capturedAt: new Date().toISOString(),
        lines: ansiLinesToHtml(full),
        plain: full,
      };
      await writeFile(join(SITE_DATA, `${demo.slug}.json`), JSON.stringify(payload, null, 2));
      console.log(`  ✓ ${demo.slug}`);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  }

  const manifest = demos.map((d) => ({ slug: d.slug, title: d.title, command: d.command }));
  await writeFile(join(SITE_DATA, "manifest.json"), JSON.stringify(manifest, null, 2));
  console.log("\nDone. Run: node scripts/generate-demo-screenshots.mjs");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
