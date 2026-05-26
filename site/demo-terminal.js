/** Live terminal player — renders captured scguard CLI output. */

const DEMO_DATA_BASE = "./demo-data";

async function loadManifest() {
  const res = await fetch(`${DEMO_DATA_BASE}/manifest.json`);
  if (!res.ok) throw new Error("demo manifest missing — run: bun run scripts/capture-demos.ts");
  return res.json();
}

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

function showDemoError(body, message) {
  if (!body) return;
  body.innerHTML = `<div class="term-line term-dim">${message}</div>`;
}

export async function initDemoTerminal(root = document) {
  const tabs = root.querySelectorAll(".ptab[data-shot]");
  const body = root.getElementById("terminal-body");
  const title = root.getElementById("player-title");
  const cmd = root.getElementById("terminal-cmd");
  const frame = root.getElementById("player-frame");
  if (!tabs.length || !body) return;

  try {
    await loadManifest();
  } catch (err) {
    showDemoError(body, "Demo unavailable — use README screenshots or run capture-demos.");
    console.warn(err);
    return;
  }

  let loadSeq = 0;

  async function showShot(shot) {
    const seq = ++loadSeq;
    frame?.classList.add("loading");
    try {
      const demo = await loadDemo(shot);
      if (seq !== loadSeq) return;
      renderTerminal(demo, body, title, cmd);
    } catch (err) {
      if (seq !== loadSeq) return;
      showDemoError(body, `Failed to load demo: ${shot}`);
      console.warn(err);
    } finally {
      if (seq === loadSeq) frame?.classList.remove("loading");
    }
  }

  const first = tabs[0]?.getAttribute("data-shot");
  if (first) await showShot(first);

  function activateTab(tab) {
    tabs.forEach((t) => {
      const on = t === tab;
      t.classList.toggle("active", on);
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
    });
    if (frame && tab.id) frame.setAttribute("aria-labelledby", tab.id);
    const shot = tab.getAttribute("data-shot");
    if (shot) showShot(shot);
  }

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => activateTab(tab));
  });

  tablist?.addEventListener("keydown", (event) => {
    const list = [...tabs];
    const i = list.indexOf(document.activeElement);
    if (i < 0) return;
    let next = i;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (i + 1) % list.length;
    else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (i - 1 + list.length) % list.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = list.length - 1;
    else return;
    event.preventDefault();
    const target = list[next];
    target.focus();
    activateTab(target);
  });

}

function boot() {
  initDemoTerminal().catch((err) => {
    const body = document.getElementById("terminal-body");
    showDemoError(body, "Demo unavailable.");
    console.warn(err);
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}
