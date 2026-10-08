"use strict";
// All rendering uses textContent / DOM nodes only (no innerHTML) so server or model text cannot inject markup.
const $ = (id) => document.getElementById(id);
const EXAMPLES = {
  "Fake internship fee": "Congratulations! You are shortlisted for a remote internship at a top firm. Pay Rs 1,500 refundable registration fee via UPI today to confirm your slot. Do not share this with anyone. Contact HR on Telegram.",
  "UPI refund trick": "Scan this QR code to receive your refund of Rs 1,500. Enter your UPI PIN to confirm. The offer expires in 30 minutes.",
  "Fake KYC": "Dear customer, your bank KYC expires today. Update now at http://sbi-kyc-update.xyz/login or your account will be blocked within 2 hours. Enter your OTP to confirm.",
  "Courier parcel": "Your parcel is held at customs. Pay a clearance fee of Rs 2,200 through the link to release your package, or it will be returned today.",
  "Marketplace overpayment": "Hi, I am interested in your laptop listing. I will pay extra if you ship via my courier. I sent a Rs 500 collect request, please accept it to receive the advance.",
  "Family emergency": "Mom I lost my phone and I am in trouble, this is my new number. Please send Rs 20,000 urgently and do not tell dad. I cannot talk right now.",
  "AI trading bot": "Our new AI trading bot gives guaranteed 40 percent weekly returns. Deposit now, limited slots left. Join our Telegram group to start earning today.",
  "Genuine: interview": "Your interview is scheduled for Tuesday 11:00 AM on Google Meet. The link is in your calendar invite. Please reply to confirm your attendance.",
  "Genuine: bank alert": "Rs 2,400 debited from your account ending 1234 at a grocery store on 05-Oct. If this was not you, call the number printed on the back of your card."
};
const LABELS = { low_signals: "No strong red flags", suspicious: "Suspicious", high_risk: "High risk", uncertain: "Not sure" };

function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }

function highlight(text, quotes) {
  const ranges = [];
  const lower = text.toLowerCase();
  for (const q of quotes) {
    if (!q || q.length < 4) continue;
    let i = text.indexOf(q);
    if (i < 0) i = lower.indexOf(q.toLowerCase());
    if (i >= 0) ranges.push([i, i + q.length]);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of ranges) { const last = merged[merged.length - 1]; if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]); else merged.push([...r]); }
  const box = el("div", undefined, "textview");
  let pos = 0;
  for (const [a, b] of merged) { box.append(document.createTextNode(text.slice(pos, a))); box.append(el("mark", text.slice(a, b))); pos = b; }
  box.append(document.createTextNode(text.slice(pos)));
  return box;
}

function list(items) { const ul = document.createElement("ul"); for (const t of items) ul.append(el("li", t)); return ul; }

function copyBtn(label, value) {
  const b = el("button", label, "btn small"); b.type = "button";
  b.addEventListener("click", async () => { try { await navigator.clipboard.writeText(value); b.textContent = "Copied ✓"; setTimeout(() => (b.textContent = label), 1500); } catch { b.textContent = "Copy failed"; } });
  return b;
}

function render(d, original) {
  const root = $("result"); root.replaceChildren(); root.classList.remove("hidden");
  const v = el("div", undefined, "verdict");
  v.append(el("div", String(d.score), "score"), el("span", LABELS[d.label] || d.label, "pill " + d.label), el("span", "confidence: " + d.confidence, "muted"));
  root.append(el("h2", "Result"), v);
  const bar = el("div", undefined, "bar " + d.label); const fill = document.createElement("span"); fill.style.width = Math.max(2, d.score) + "%"; bar.append(fill); root.append(bar);
  if (d.limited_mode) root.append(el("div", "AI reasoning is unavailable right now. Showing rule-based checks and the classifier only.", "banner"));
  root.append(el("p", d.summary));
  root.append(el("h3", "Warning signs in your text"));
  if (d.red_flags.length) {
    root.append(highlight(original, d.red_flags.map((f) => f.quote)));
    const ul = document.createElement("ul");
    for (const f of d.red_flags) { const li = el("li", undefined, "flag"); li.append(el("q", f.quote), el("span", f.category, "tag"), document.createTextNode(" — " + f.why)); ul.append(li); }
    root.append(ul);
  } else root.append(el("p", "No specific warning phrases were found. That does not mean the message is safe.", "muted"));
  if (d.matched_playbooks.length) {
    root.append(el("h3", "Matches known scam patterns"));
    for (const p of d.matched_playbooks) {
      const box = el("div", undefined, "pb"); box.append(el("strong", p.name));
      if (p.source === "auto") box.append(el("span", "Learned " + p.learned_on, "badge"));
      if (p.new_this_week) box.append(el("span", "New this week", "badge"));
      box.append(el("div", "similarity " + p.similarity, "muted small")); root.append(box);
    }
  }
  root.append(el("h3", "What to do next"), list(d.safe_actions));
  const row = el("div", undefined, "row"); row.append(copyBtn("Copy a safe reply", d.safe_reply), copyBtn("Copy warning for family", d.forward_warning)); root.append(row);
  const det = document.createElement("details"); det.append(el("summary", "Evidence details"));
  const tb = document.createElement("table"); const hr = tb.insertRow();
  for (const h of ["Signal", "Points", "Detail"]) hr.append(el("th", h));
  for (const e of d.evidence) { const r = tb.insertRow(); r.insertCell().textContent = e.signal; r.insertCell().textContent = String(e.points); r.insertCell().textContent = e.detail; }
  const bd = d.score_breakdown; det.append(tb, el("p", `Score parts — evidence ${bd.evidence}, classifier ${bd.classifier}, AI ${bd.llm === null ? "n/a" : bd.llm}` + (bd.floor_applied ? `, minimum applied: ${bd.floor_applied}` : ""), "muted small"));
  root.append(det, el("p", d.disclaimer, "note"));
  root.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function analyze() {
  const text = $("text").value.trim(); const btn = $("go");
  if (text.length < 20) { alert("Please paste at least 20 characters."); return; }
  btn.disabled = true; btn.textContent = "Analyzing…";
  try {
    const r = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text, mode: $("mode").value }) });
    const d = await r.json();
    if (!r.ok) { const root = $("result"); root.replaceChildren(el("p", d.error || "Something went wrong.")); root.classList.remove("hidden"); return; }
    render(d, text);
  } catch { const root = $("result"); root.replaceChildren(el("p", "Network error. Please try again.")); root.classList.remove("hidden"); }
  finally { btn.disabled = false; btn.textContent = "Analyze"; }
}

async function status() {
  try { const s = await (await fetch("/api/knowledge/status")).json();
    $("kstatus").textContent = `${s.seed_count} built-in scam playbooks · ${s.auto_count} auto-learned · newest card ${s.newest_card_date || "n/a"}` + (s.last_refresh ? ` · refreshed ${s.last_refresh}` : "");
  } catch { $("kstatus").textContent = "Status unavailable."; }
}

document.addEventListener("DOMContentLoaded", () => {
  const ex = $("examples");
  for (const [name, txt] of Object.entries(EXAMPLES)) { const b = el("button", name, "chip"); b.type = "button"; b.addEventListener("click", () => { $("text").value = txt; $("counter").textContent = txt.length + " / 6000"; }); ex.append(b); }
  $("text").addEventListener("input", () => ($("counter").textContent = $("text").value.length + " / 6000"));
  $("go").addEventListener("click", analyze);
  status();
});
