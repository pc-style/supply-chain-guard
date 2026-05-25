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

// Demo tab switching is handled by demo-terminal.js (live captured CLI output).
