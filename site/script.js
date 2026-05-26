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
    copyFeedback(btn, "copied");
  });
});

// Demo tab switching is handled by demo-terminal.js (live captured CLI output).
