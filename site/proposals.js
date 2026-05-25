// Lightweight interactions for design proposals (no terminal animation).
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
      try {
        document.execCommand("copy");
      } catch {}
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

const tabs = document.querySelectorAll(".ptab");
const img = document.getElementById("player-img");
const playerTitle = document.getElementById("player-title");
const titles = {
  "scan-npm": "Scanning an npm package",
  "add-withheld": "Staged without installing",
  "add-approved": "Install after approval",
  "block-broad-update": "Blocking a broad update",
  "scan-vsix": "Scanning a VSIX extension",
  "generated-reports": "Generated reports",
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
    img.src = `/screenshots/${shot}.png`;
    img.alt = titles[shot] || shot;
    if (playerTitle) playerTitle.textContent = titles[shot] || shot;
  });
});
