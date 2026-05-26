import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { chromium } from "playwright";

const SITE_ROOT = join(import.meta.dir, "..", "site");
const AXE_SOURCE = readFileSync(
  join(import.meta.dir, "..", "node_modules", "axe-core", "axe.min.js"),
  "utf8",
);
const PORT = 4173;

test("marketing site has no serious or critical axe violations", async () => {
  const server = Bun.serve({
    port: PORT,
    fetch(req) {
      const url = new URL(req.url);
      let path = decodeURIComponent(url.pathname);
      if (path.endsWith("/")) path += "index.html";
      if (path === "/") path = "/index.html";
      const file = Bun.file(join(SITE_ROOT, path.replace(/^\//, "")));
      return new Response(file);
    },
  });

  const browser = await chromium.launch();
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: "networkidle" });
    await page.addScriptTag({ content: AXE_SOURCE });
    const results = await page.evaluate(async () => {
      const axe = (
        window as unknown as {
          axe: {
            run: (
              ctx?: unknown,
              opts?: unknown,
            ) => Promise<{
              violations: {
                id: string;
                impact?: string;
                help: string;
                nodes: { target: string[] }[];
              }[];
            }>;
          };
        }
      ).axe;
      return axe.run(document, {
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"],
        },
      });
    });
    const blocking = results.violations.filter(
      (v) => v.impact === "serious" || v.impact === "critical",
    );
    expect(blocking).toEqual([]);
  } finally {
    await context.close();
    await browser.close();
    server.stop();
  }
}, 60_000);
