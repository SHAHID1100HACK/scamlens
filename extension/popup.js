const out = document.getElementById("out");
const LABELS = { low_signals: "No strong red flags", suspicious: "Suspicious", high_risk: "High risk", uncertain: "Not sure" };
function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
const send = (m) => new Promise((res) => chrome.runtime.sendMessage(m, (r) => res(r || { error: "No response." })));

function copyBtn(label, value) {
  const b = el("button", label); b.type = "button";
  b.addEventListener("click", async () => { try { await navigator.clipboard.writeText(value); b.textContent = "Copied ✓"; } catch { b.textContent = "Copy failed"; } });
  return b;
}

function render(p) {
  out.replaceChildren();
  if (!p) return;
  if (p.error) { out.append(el("p", p.error)); return; }
  const d = p.result;
  const top = el("div"); top.append(el("span", String(d.score), "score"), el("span", LABELS[d.label] || d.label, "pill " + d.label));
  out.append(top);
  if (d.limited_mode) out.append(el("div", "AI reasoning unavailable: showing rule-based checks only.", "banner"));
  if (d._redacted) out.append(el("div", d._redacted + " sensitive item(s) were hidden before analysis.", "banner"));
  out.append(el("p", d.summary));
  if (d.red_flags.length) {
    out.append(el("h3", "Warning signs"));
    const ul = document.createElement("ul");
    for (const f of d.red_flags) { const li = el("li"); li.append(el("q", String(f.quote)), el("span", String(f.category), "tag"), document.createTextNode(" — " + String(f.why))); ul.append(li); }
    out.append(ul);
    const row = el("div", undefined, "row");
    const hb = el("button", "Highlight on page"); hb.type = "button";
    hb.addEventListener("click", async () => { const r = await send({ type: "highlight", quotes: d.red_flags.map((f) => f.quote) }); hb.textContent = r.error ? r.error : "Highlighted " + r.hits; });
    const cb = el("button", "Clear"); cb.type = "button"; cb.addEventListener("click", () => send({ type: "clear" }));
    row.append(hb, cb); out.append(row);
  }
  if (d.matched_playbooks.length) {
    out.append(el("h3", "Known scam patterns"));
    for (const m of d.matched_playbooks) { const b = el("div", undefined, "pb"); b.append(el("strong", String(m.name))); if (m.source === "auto") b.append(el("span", "Learned " + m.learned_on, "badge")); out.append(b); }
  }
  out.append(el("h3", "What to do next"));
  const ul = document.createElement("ul"); for (const a of d.safe_actions) ul.append(el("li", String(a))); out.append(ul);
  const row = el("div", undefined, "row"); row.append(copyBtn("Copy safe reply", String(d.safe_reply)), copyBtn("Copy family warning", String(d.forward_warning))); out.append(row);
  out.append(el("p", String(d.disclaimer || ""), "muted"));
}

async function run(source) {
  out.replaceChildren(el("p", "Analyzing…"));
  render(await send({ type: "analyze", source, mode: "auto" }));
}
document.getElementById("sel").addEventListener("click", () => run("selection"));
document.getElementById("page").addEventListener("click", () => run("page"));
send({ type: "last" }).then((p) => { if (p && p.at && Date.now() - p.at < 600000) render(p); });
