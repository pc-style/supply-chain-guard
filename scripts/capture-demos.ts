#!/usr/bin/env bun
/**
 * Capture real scguard CLI output for site demos and README screenshots.
 * Writes JSON (live terminal) and optional PNG via generate-demo-screenshots.mjs.
 */
import { mkdir, rm, writeFile, copyFile, readdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { ansiLinesToHtml } from "./ansi-html";

const ROOT = join(import.meta.dir, "..");
const CLI = join(ROOT, "src", "cli.ts");
const SITE_DATA = join(ROOT, "site", "demo-data");
const SITE_SHOTS = join(ROOT, "site", "screenshots");
const DOCS_SHOTS = join(ROOT, "docs", "screenshots");
const DEMO_VSIX = join(ROOT, "scripts", "assets", "demo-theme.vsix");
const DEMO_EXT = join(ROOT, "scripts", "assets", "demo-extension");

const env = {
  ...process.env,
  FORCE_COLOR: "3",
  NO_COLOR: "",
  SCGUARD_OFFLINE: "1",
  SCGUARD_SHELL_HOOK_ACTIVE: "1",
  TERM: "xterm-256color",
  COLORTERM: "truecolor",
};

type DemoSpec = {
  slug: string;
  title: string;
  command: string;
  run: (ws: string, scguard: string) => Promise<string>;
};

function runCmd(
  cmd: string,
  args: string[],
  opts: { cwd?: string; env?: Record<string, string> } = {},
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: { ...env, ...opts.env },
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

async function scguard(args: string[], cwd: string): Promise<string> {
  const { stdout, stderr, code } = await runCmd("bun", ["run", CLI, ...args], { cwd });
  const out = stdout + (stderr ? (stdout ? "\n" : "") + stderr : "");
  if (code !== 0 && !args.includes("update")) {
    // block-broad-update expects non-zero
    const allowFail = args[0] === "guard" || args.includes("update");
    if (!allowFail) console.warn(`[capture] exit ${code} for: scguard ${args.join(" ")}`);
  }
  return out;
}

function normalizeOutput(text: string, ws: string): string {
  const displayWs = "./demo";
  return text
    .replaceAll(ws, displayWs)
    .replaceAll(ws.replace(/^\.\//, ""), displayWs)
    .replace(/\/tmp\/scguard-demo-[a-z0-9-]+/g, displayWs)
    .replace(/\.scguard\/reports\/[^\s]+\.(json|md|txt)/g, (m) =>
      m.replace(/[^/]+\.(json|md)$/, "chalk@5.4.1-report.$1"),
    )
    .replace(/chalk@5\.4\.1-\d+\.(json|md)/g, "chalk@5.4.1-report.$1")
    .replace(/is-number@7\.0\.0-\d+\.(json|md)/g, "is-number@7.0.0-report.$1")
    .replace(/demo-theme-0\.0\.1\.vsix-\d+\.(json|md)/g, "demo-theme-report.$1");
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
    run: async (ws, _sg) => scguard(["review", "chalk@5.4.1"], ws),
  },
  {
    slug: "add-withheld",
    title: "staged without installing",
    command: "scguard review chalk@5.4.1",
    run: async (ws) => {
      const out = await scguard(["review", "chalk@5.4.1"], ws);
      const lines = out.split("\n");
      const start = lines.findIndex((l) => l.includes("Next steps"));
      return start >= 0 ? lines.slice(Math.max(0, start - 8)).join("\n") : out;
    },
  },
  {
    slug: "add-approved",
    title: "install after approval",
    command: "scguard install is-number@7.0.0",
    run: async (ws) => scguard(["install", "is-number@7.0.0", "--pm", "npm"], ws),
  },
  {
    slug: "block-broad-update",
    title: "blocking a broad update",
    command: "bun update",
    run: async (ws) => scguard(["guard", "bun", "update"], ws),
  },
  {
    slug: "scan-vsix",
    title: "scanning a vsix extension",
    command: "scguard scan-vsix ./demo-theme.vsix",
    run: async (ws) => {
      await copyFile(DEMO_VSIX, join(ws, "demo-theme.vsix"));
      return scguard(["scan-vsix", join(ws, "demo-theme.vsix")], ws);
    },
  },
  {
    slug: "generated-reports",
    title: "generated reports",
    command: "ls -la .scguard/reports/",
    run: async (ws) => {
      await scguard(["review", "chalk@5.4.1"], ws);
      const reports = join(ws, ".scguard", "reports");
      const files = (await readdir(reports)).sort();
      const header =
        "Every run writes JSON, Markdown, and agent prompts under .scguard/reports:\n\n";
      const listing = files
        .map((f) => f.replace(/chalk@5\.4\.1-\d+/, "chalk@5.4.1-report"))
        .map((f) => `  ${f}`)
        .join("\n");
      const sample = files.find((f) => f.endsWith(".md"));
      let preview = "";
      if (sample) {
        const { stdout } = await runCmd("head", ["-n", "12", join(reports, sample)], { cwd: ws });
        preview = `\n$ head -12 .scguard/reports/${sample.replace(/chalk@5\.4\.1-\d+/, "chalk@5.4.1-report")}\n${stdout}`;
      }
      return header + listing + preview;
    },
  },
];

async function captureHelp(): Promise<void> {
  const out = await runCmd("bun", ["run", CLI, "--help"]);
  const text = normalizeOutput(out.stdout, "");
  const payload = {
    slug: "help",
    title: "command reference",
    command: "scguard --help",
    cwd: "~",
    capturedAt: new Date().toISOString(),
    lines: ansiLinesToHtml(text),
    plain: text,
  };
  await writeFile(join(SITE_DATA, "help.json"), JSON.stringify(payload, null, 2));
}

async function main() {
  await ensureDemoVsix();
  await mkdir(SITE_DATA, { recursive: true });
  await mkdir(SITE_SHOTS, { recursive: true });
  await mkdir(DOCS_SHOTS, { recursive: true });

  console.log("Capturing demo output from live scguard runs…");

  await captureHelp();

  for (const demo of demos) {
    const ws = await makeWorkspace();
    try {
      let raw = await demo.run(ws, CLI);
      raw = normalizeOutput(raw, ws);
      const displayCmd = demo.command;
      const body = raw.trim();
      const full = `$ ${displayCmd}\n${body}`;
      const payload = {
        slug: demo.slug,
        title: demo.title,
        command: displayCmd,
        cwd: "./demo",
        capturedAt: new Date().toISOString(),
        lines: ansiLinesToHtml(full),
        plain: full,
      };
      const outPath = join(SITE_DATA, `${demo.slug}.json`);
      await writeFile(outPath, JSON.stringify(payload, null, 2));
      console.log(`  ✓ ${demo.slug} → ${outPath}`);
    } finally {
      await rm(ws, { recursive: true, force: true });
    }
  }

  const manifest = demos.map((d) => ({ slug: d.slug, title: d.title, command: d.command }));
  await writeFile(join(SITE_DATA, "manifest.json"), JSON.stringify(manifest, null, 2));
  console.log("\nDone. Run: bun run scripts/generate-demo-screenshots.mjs");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
