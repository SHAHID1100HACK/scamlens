// Client-side redaction: runs BEFORE any text leaves the browser.
function luhn(d) { let s = 0, alt = false; for (let i = d.length - 1; i >= 0; i--) { let n = +d[i]; if (alt) { n *= 2; if (n > 9) n -= 9; } s += n; alt = !alt; } return s % 10 === 0; }
export function redact(text) {
  let count = 0;
  text = text.replace(/(?<!\d)(?:\d[ -]?){13,19}(?!\d)/g, (m) => { const d = m.replace(/\D/g, ""); if (d.length >= 13 && d.length <= 19 && luhn(d)) { count++; return "[CARD HIDDEN]" + m.slice(m.trimEnd().length); } return m; });
  text = text.replace(/(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)/g, () => { count++; return "[ID HIDDEN]"; });
  text = text.replace(/\b(otp|pin|cvv|cvc|password|passcode)\b\s*(?:is|:|=|-)?\s*([A-Za-z0-9@#$!]{3,12})/gi, (_, k) => { count++; return k + " [HIDDEN]"; });
  return { text, count };
}
