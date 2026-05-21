// ── copy-to-clipboard ───────────────────────────────────────────
document.querySelectorAll("[data-copy]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const text = btn.getAttribute("data-copy") || "";
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const span = document.createElement("span");
      span.textContent = text;
      document.body.appendChild(span);
      const r = document.createRange();
      r.selectNodeContents(span);
      const sel = window.getSelection();
      sel?.removeAllRanges();
      sel?.addRange(r);
      try { document.execCommand("copy"); } catch {}
      sel?.removeAllRanges();
      span.remove();
    }
    btn.classList.add("copied");
    const label = btn.querySelector(".copy-label");
    if (label) label.textContent = "Copied";
    setTimeout(() => {
      btn.classList.remove("copied");
      if (label) label.textContent = "Copy";
    }, 1600);
  });
});

// ── demo player tabs ────────────────────────────────────────────
const tabs = document.querySelectorAll(".ptab");
const img = document.getElementById("player-img");
const playerTitle = document.getElementById("player-title");
const titles = {
  "scan-npm": "scguard, scan an npm package",
  "add-withheld": "scguard, stage without installing",
  "add-approved": "scguard, install after approval",
  "block-broad-update": "scguard, blocking a broad update",
  "scan-vsix": "scguard, scan a .vsix",
  "generated-reports": "scguard, generated reports",
};

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => {
      t.classList.remove("active");
      t.setAttribute("aria-selected", "false");
    });
    tab.classList.add("active");
    tab.setAttribute("aria-selected", "true");
    const shot = tab.getAttribute("data-shot");
    if (!shot || !img) return;
    img.style.animation = "none";
    void img.offsetWidth;
    img.style.animation = "";
    img.src = `./screenshots/${shot}.png`;
    img.alt = titles[shot] || shot;
    if (playerTitle) playerTitle.textContent = titles[shot] || `scguard, ${shot}`;
  });
});

// ── hero terminal typing animation ──────────────────────────────
const termOut = document.getElementById("hero-term-out");
const termCaret = document.getElementById("hero-term-caret");

function riskRow(level, where, what, why) {
  return `<span class="risk-row"><span class="risk-label risk-${level.toLowerCase()}">${level}</span><span class="ln-step">${where}</span><span class="ln-dim">${what}<span class="ln-step">  ${why}</span></span></span>`;
}

const lines = [
  { html: `<span class="ln-prompt">$</span> scguard review left-pad`, type: true, delay: 500 },
  { html: ``, type: false, delay: 300 },
  { html: `<span class="ln-step">Resolving graph and simulating install...</span>`, type: false, delay: 700 },
  { html: ``, type: false, delay: 400 },
  { html: `<span class="ln-title">Supply Chain Guard Report</span>`, type: false, delay: 500 },
  { html: ``, type: false, delay: 250 },
  { html: riskRow("HIGH", "postinstall", "node-crypto-exfil", "network exfiltration to api.evil.dev"), type: false, delay: 450 },
  { html: riskRow("MED",  "preinstall",  "bin/sh -c curl...", "remote script download"), type: false, delay: 450 },
  { html: riskRow("LOW",  "prepare",     "scripts/build.js",  "build script with fs access"), type: false, delay: 450 },
  { html: ``, type: false, delay: 350 },
  { html: `<span class="ln-ok">ok</span>  <span class="ln-step">license check</span>`, type: false, delay: 350 },
  { html: `<span class="ln-ok">ok</span>  <span class="ln-step">all licenses allowed</span>`, type: false, delay: 350 },
  { html: `<span class="ln-ok">ok</span>  <span class="ln-step">no critical CVEs detected</span>`, type: false, delay: 350 },
  { html: ``, type: false, delay: 300 },
  { html: `<span class="ln-blocked">install blocked.</span> <span class="ln-step">2 high-risk issue(s) found.</span>`, type: false, delay: 700 },
];

async function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function typeLine(html, into) {
  const tmp = document.createElement("div");
  tmp.innerHTML = html;
  const plain = tmp.textContent || "";
  const span = document.createElement("span");
  into.appendChild(span);
  for (let i = 0; i < plain.length; i++) {
    span.textContent += plain[i];
    await sleep(14 + Math.random() * 26);
  }
  span.innerHTML = html;
}

async function appendLine(html, into) {
  const span = document.createElement("span");
  span.innerHTML = html;
  into.appendChild(span);
}

async function newline(into) {
  into.appendChild(document.createTextNode("\n"));
}

async function runTerminal() {
  if (!termOut) return;
  while (true) {
    termOut.innerHTML = "";
    for (const line of lines) {
      await sleep(line.delay);
      if (line.type) {
        await typeLine(line.html, termOut);
      } else {
        await appendLine(line.html, termOut);
      }
      await newline(termOut);
    }
    await sleep(5000);
  }
}

if (termOut && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
  runTerminal();
} else if (termOut) {
  termOut.innerHTML = lines.map((l) => l.html).join("\n");
  if (termCaret) termCaret.style.display = "none";
}
