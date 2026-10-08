import { BACKEND, DEV_BACKEND } from "./config.js";
import { redact } from "./redact.js";

const MAX = 6000;
const COLORS = { low_signals: "#1f8a4c", suspicious: "#b86e00", high_risk: "#c62828", uncertain: "#5b6475" };

async function backend() {
  const { dev } = await chrome.storage.local.get("dev");
  return dev ? DEV_BACKEND : BACKEND;
}

function validShape(d) {
  return d && typeof d.score === "number" && typeof d.label === "string" && Array.isArray(d.red_flags) &&
    Array.isArray(d.matched_playbooks) && Array.isArray(d.safe_actions) && typeof d.summary === "string";
}

async function callApi(rawText, mode, pageUrl) {
  const { text, count } = redact(rawText.trim().slice(0, MAX));
  if (text.length < 20) return { error: "Please select at least 20 characters of text." };
  try {
    const body = { text, mode: mode || "auto" };
    if (pageUrl && /^https?:\/\//.test(pageUrl)) body.page_url = pageUrl.slice(0, 2048);
    const r = await fetch((await backend()) + "/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) return { error: typeof d.error === "string" ? d.error : "Could not analyze." };
    if (!validShape(d)) return { error: "Unexpected response from server." };
    d._redacted = count;
    return { result: d, analyzed: text };
  } catch { return { error: "Network error. Is the ScamLens server awake?" }; }
}

async function remember(tabId, payload) {
  await chrome.storage.session.set({ last: { ...payload, tabId, at: Date.now() } });
  if (payload.result) {
    chrome.action.setBadgeText({ text: String(payload.result.score), tabId });
    chrome.action.setBadgeBackgroundColor({ color: COLORS[payload.result.label] || "#5b6475", tabId });
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "scamlens-check", title: "Check with ScamLens", contexts: ["selection"] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "scamlens-check" || !tab || !info.selectionText) return;
  const payload = await callApi(info.selectionText, "auto", tab.url);
  await remember(tab.id, payload);
  try { await chrome.action.openPopup(); } catch { /* user can click the toolbar icon */ }
});

function collectSelection() { return (window.getSelection() || "").toString(); }
function collectPage() {
  const t = document.body ? document.body.innerText : "";
  return t.replace(/\s+\n/g, "\n").slice(0, 6000);
}
function markQuotes(quotes) {
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(n) { const p = n.parentElement; if (!p || /^(SCRIPT|STYLE|NOSCRIPT|TEXTAREA|INPUT|MARK)$/.test(p.tagName)) return NodeFilter.FILTER_REJECT; return NodeFilter.FILTER_ACCEPT; }
  });
  const nodes = []; while (walker.nextNode()) nodes.push(walker.currentNode);
  let hits = 0;
  for (const q of quotes) {
    if (!q || q.length < 4) continue;
    for (const n of nodes) {
      const i = n.nodeValue.indexOf(q);
      if (i < 0 || !n.parentNode) continue;
      const mid = n.splitText(i); mid.splitText(q.length);
      const m = document.createElement("mark"); m.className = "scamlens-mark";
      m.style.setProperty("background", "#ffe58a"); m.style.setProperty("color", "#000");
      mid.parentNode.replaceChild(m, mid); m.appendChild(mid); hits++;
      break;
    }
  }
  return hits;
}
function clearMarks() {
  document.querySelectorAll("mark.scamlens-mark").forEach((m) => { const p = m.parentNode; while (m.firstChild) p.insertBefore(m.firstChild, m); p.removeChild(m); p.normalize(); });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;          // only our own extension pages
  (async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) return sendResponse({ error: "No active tab." });
    if (msg.type === "analyze") {
      const fn = msg.source === "page" ? collectPage : collectSelection;
      let raw = "";
      try { const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: fn }); raw = (res && res.result) || ""; }
      catch { return sendResponse({ error: "This page cannot be read (browser pages are blocked)." }); }
      const payload = await callApi(raw, msg.mode, tab.url);
      await remember(tab.id, payload);
      return sendResponse(payload);
    }
    if (msg.type === "highlight") {
      const quotes = Array.isArray(msg.quotes) ? msg.quotes.filter((q) => typeof q === "string").slice(0, 8) : [];
      try { const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: markQuotes, args: [quotes] }); return sendResponse({ hits: res.result }); }
      catch { return sendResponse({ error: "Could not highlight on this page." }); }
    }
    if (msg.type === "clear") {
      try { await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: clearMarks }); } catch {}
      return sendResponse({ ok: true });
    }
    if (msg.type === "last") { const { last } = await chrome.storage.session.get("last"); return sendResponse(last || null); }
    sendResponse({ error: "Unknown request." });
  })();
  return true;
});
