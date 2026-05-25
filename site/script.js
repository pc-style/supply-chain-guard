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
    if (label) label.textContent = "copied";
    setTimeout(() => {
      btn.classList.remove("copied");
      if (label) label.textContent = "copy install";
    }, 1600);
  });
});

const tabs = document.querySelectorAll(".ptab");
const img = document.getElementById("player-img");
const playerTitle = document.getElementById("player-title");
const titles = {
  "scan-npm": "scanning an npm package",
  "add-withheld": "staged without installing",
  "add-approved": "install after approval",
  "block-broad-update": "blocking a broad update",
  "scan-vsix": "scanning a vsix extension",
  "generated-reports": "generated reports",
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
    img.src = `./screenshots/${shot}.png`;
    img.alt = titles[shot] || shot;
    if (playerTitle) playerTitle.textContent = titles[shot] || shot;
  });
});
