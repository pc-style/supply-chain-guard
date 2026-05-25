# Demo rendering comparison

Pick which approach you want on **scguard.pcstyle.dev**. Both use the **same captured CLI output** from `bun run scripts/capture-demos.ts`.

---

## A — Live terminal (recommended)

**How it works:** Real `scguard` runs write JSON under `site/demo-data/`. The site renders ANSI-colored HTML in a terminal chrome widget. Tabs swap JSON payloads — no stale PNGs.

**Pros**
- Always matches current CLI colors and copy
- Crisp at any viewport (text, not raster)
- Small payload (~few KB JSON per tab)
- Refresh = re-run one script

**Cons**
- Requires JS (noscript falls back to PNG)
- Slightly more moving parts (ansi-html + demo-terminal.js)

**Preview:** Open the site `#demo` section after `bun run scripts/capture-demos.ts` and click tabs.

**Files:** `site/demo-terminal.js`, `site/demo-data/*.json`, `scripts/capture-demos.ts`, `scripts/ansi-html.ts`

---

## B — Generated PNG screenshots

**How it works:** Playwright screenshots the same terminal HTML used for captures. PNGs land in `site/screenshots/` and `docs/screenshots/` (README embeds).

**Pros**
- Works everywhere (README on GitHub, noscript, social previews)
- Pixel-perfect “terminal app” look
- No runtime fetch for demo section if you switch back to `<img>`

**Cons**
- Must regenerate when CLI output changes
- Heavier assets, can look soft when scaled
- Extra devDependency step (`playwright` + chromium)

**Preview:** See `site/screenshots/scan-npm.png` (and siblings) after `bun run demo-screenshots`.

**Files:** `scripts/generate-demo-screenshots.mjs`, `site/screenshots/*.png` (six demo tabs only — no help, no demo-complete)

---

## Side-by-side (scan npm)

| Live terminal (A) | PNG screenshot (B) |
|-------------------|-------------------|
| `site/demo-data/scan-npm.json` → rendered in browser | `site/screenshots/scan-npm.png` |

Open both in the IDE or deploy preview to compare sharpness, scroll behavior, and tab switching.

---

## Regenerate everything

```sh
bun run demo-screenshots
```

Or capture JSON only:

```sh
bun run capture-demos
```

---

## Current production choice

**`index.html` uses approach A** (live terminal). Approach B remains for README/GitHub and `<noscript>` fallback.

To revert the site player to PNG-only, restore the `<img id="player-img">` block and tab handler in `script.js` (see git history on this branch).
