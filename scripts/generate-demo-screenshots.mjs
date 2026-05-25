#!/usr/bin/env node
/**
 * Render captured demo JSON into polished PNG screenshots (Playwright).
 * Syncs site/screenshots and docs/screenshots.
 */
import { chromium } from "playwright";
import { readFile, writeFile, mkdir, copyFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const SITE = join(ROOT, "site");
const DATA = join(SITE, "demo-data");
const SITE_SHOTS = join(SITE, "screenshots");
const DOCS_SHOTS = join(ROOT, "docs", "screenshots");

const CSS = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: "Geist Mono", ui-monospace, Menlo, Monaco, Consolas, monospace;
    background: #0f0d0d;
    padding: 24px;
  }
  .terminal {
    border: 1px solid #302626;
    border-radius: 12px;
    overflow: hidden;
    background: #120f0f;
    max-width: 1100px;
  }
  .terminal-titlebar {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 10px 14px;
    background: #1a1515;
    border-bottom: 1px solid #251e1e;
  }
  .dot { width: 10px; height: 10px; border-radius: 50%; }
  .dot-r { background: #f87171; }
  .dot-y { background: #fbbf24; }
  .dot-g { background: #4ade80; }
  .cmd { margin-left: 6px; font-size: 11px; color: #6a5050; flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .terminal-body {
    padding: 16px 18px 20px;
    font-size: 12px;
    line-height: 1.55;
    color: #e4e4e7;
    white-space: pre;
  }
  .term-line { min-height: 1.55em; }
`;

function shellPage(demo) {
  const lines = demo.lines.map((l) => `<div class="term-line">${l || "&nbsp;"}</div>`).join("");
  const cwd = demo.cwd || "./demo";
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>${CSS}</style></head><body>
  <div class="terminal">
    <div class="terminal-titlebar">
      <span class="dot dot-r"></span><span class="dot dot-y"></span><span class="dot dot-g"></span>
      <span class="cmd">${cwd} $ ${demo.command}</span>
    </div>
    <div class="terminal-body">${lines}</div>
  </div></body></html>`;
}

async function shot(browser, slug) {
  const raw = await readFile(join(DATA, `${slug}.json`), "utf8");
  const demo = JSON.parse(raw);
  const page = await browser.newPage({ viewport: { width: 1120, height: 720 } });
  await page.setContent(shellPage(demo), { waitUntil: "domcontentloaded" });
  const el = page.locator(".terminal");
  await el.screenshot({ path: join(SITE_SHOTS, `${slug}.png`), type: "png" });
  await page.close();
  console.log(`  ✓ ${slug}.png`);
}

async function main() {
  const manifest = JSON.parse(await readFile(join(DATA, "manifest.json"), "utf8"));
  await mkdir(SITE_SHOTS, { recursive: true });
  await mkdir(DOCS_SHOTS, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  try {
    for (const { slug } of manifest) await shot(browser, slug);
    await shot(browser, "help");
  } finally {
    await browser.close();
  }

  for (const file of ["help", ...manifest.map((m) => m.slug)]) {
    await copyFile(join(SITE_SHOTS, `${file}.png`), join(DOCS_SHOTS, `${file}.png`));
  }

  const complete = {
    slug: "demo-complete",
    title: "demo workspace cleaned up",
    command: "scguard demo cleanup",
    cwd: "./demo",
    lines: [
      '<span style="color:rgb(161,161,170)">Demo workspace removed. Re-run </span><span style="color:rgb(147,197,253)">bun run scripts/capture-demos.ts</span><span style="color:rgb(161,161,170)"> to refresh captures.</span>',
    ],
  };
  const pageHtml = shellPage(complete);
  const browser2 = await chromium.launch({ headless: true });
  const page = await browser2.newPage({ viewport: { width: 1120, height: 200 } });
  await page.setContent(pageHtml);
  await page.locator(".terminal").screenshot({ path: join(SITE_SHOTS, "demo-complete.png") });
  await browser2.close();
  await copyFile(join(SITE_SHOTS, "demo-complete.png"), join(DOCS_SHOTS, "demo-complete.png"));

  console.log("\nSynced PNGs to site/screenshots and docs/screenshots");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
