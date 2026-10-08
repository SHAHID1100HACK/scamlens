"use strict";
(async () => {
  try {
    const r = await fetch("/api/extension/version"); const d = await r.json();
    if (!r.ok) throw new Error();
    const a = document.getElementById("dl"); a.href = "/downloads/" + d.file; a.setAttribute("download", d.file);
    document.getElementById("ver").textContent = `v${d.version} · ${(d.size / 1024).toFixed(1)} KB · built ${d.built}`;
    document.getElementById("sha").textContent = d.sha256;
  } catch { document.getElementById("sha").textContent = "package not available yet"; }
})();
