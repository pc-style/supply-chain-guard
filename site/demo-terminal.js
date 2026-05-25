/** Live terminal player — renders captured scguard CLI output. */

const DEMO_DATA_BASE = "./demo-data";
const manifestPromise = fetch(`${DEMO_DATA_BASE}/manifest.json`).then((r) => {
  if (!r.ok) throw new Error("demo manifest missing — run: bun run scripts/capture-demos.ts");
  return r.json();
});

const cache = new Map();

async function loadDemo(slug) {
  if (cache.has(slug)) return cache.get(slug);
  const res = await fetch(`${DEMO_DATA_BASE}/${slug}.json`);
  if (!res.ok) throw new Error(`demo data missing: ${slug}`);
  const data = await res.json();
  cache.set(slug, data);
  return data;
}

function renderTerminal(demo, bodyEl, titleEl, cmdEl) {
  if (titleEl) titleEl.textContent = demo.title;
  if (cmdEl) {
    const cwd = demo.cwd ? ` ${demo.cwd}` : "";
    cmdEl.textContent = `${cwd} $ ${demo.command}`;
  }
  if (!bodyEl) return;
  bodyEl.innerHTML = demo.lines
    .map((line) => `<div class="term-line">${line || "&nbsp;"}</div>`)
    .join("");
  bodyEl.scrollTop = 0;
}

export async function initDemoTerminal(root = document) {
  const tabs = root.querySelectorAll(".ptab[data-shot]");
  const body = root.getElementById("terminal-body");
  const title = root.getElementById("player-title");
  const cmd = root.getElementById("terminal-cmd");
  const frame = root.getElementById("player-frame");
  if (!tabs.length || !body) return;

  await manifestPromise;
  const first = tabs[0]?.getAttribute("data-shot");
  if (first) {
    const demo = await loadDemo(first);
    renderTerminal(demo, body, title, cmd);
  }

  tabs.forEach((tab) => {
    tab.addEventListener("click", async () => {
      tabs.forEach((t) => {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");
      const shot = tab.getAttribute("data-shot");
      if (!shot) return;
      frame?.classList.add("loading");
      try {
        const demo = await loadDemo(shot);
        renderTerminal(demo, body, title, cmd);
      } finally {
        frame?.classList.remove("loading");
      }
    });
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => initDemoTerminal());
} else {
  initDemoTerminal();
}
