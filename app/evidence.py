"""Deterministic evidence engine. No LLM involved; works in limited mode."""
from __future__ import annotations
import asyncio
import json
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
import tldextract
from rapidfuzz.distance import Levenshtein

from . import config
from .schemas import EvidenceItem
from .security import normalize, valid_domain

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # offline snapshot
_B = json.loads((config.DATA_DIR / "brands.json").read_text(encoding="utf-8"))
BRANDS: dict[str, list[str]] = _B["brands"]
OFFICIAL = {d for v in BRANDS.values() for d in v}
SHORTENERS = set(_B["shorteners"])
FREE_EMAIL = set(_B["free_email"])
RISKY_TLDS = set(_B["risky_tlds"])

I = re.I
# Each pattern is linear-time (no nested quantifiers) and is run on capped input only.
PATTERNS = {
    "advance_fee": (25, True,
        re.compile(r"(?:(?:registration|processing|clearance|joining|training|security|refundable|verification|delivery|activation|insurance|gst|kit|token)\b[^.\n]{0,25}\b(?:fee|charge|charges|deposit|amount|payment)|"
                   r"(?:fee|deposit|charges?)\b[^.\n]{0,30}\b(?:refundable|upi|to (?:confirm|receive|claim|release|unlock))|"
                   r"(?:rs\.?|inr|₹)\s?[\d,]+\b[^.\n]{0,30}\b(?:advance|fee|deposit)|advance (?:payment|of)|\badvance\b[^.\n]{0,20}\b(?:rs\.?|₹)\s?\d)", I),
        "Asks for money up front (fee, deposit or advance) before anything is delivered"),
    "payment_request": (12, False,
        re.compile(r"(?:(?:pay|send|transfer|deposit|remit)\b[^.\n]{0,40}\b(?:rs\.?|inr|₹)\s?\d[\d,]*|urgent(?:ly)?\b[^.\n]{0,15}(?:rs\.?|₹)\s?\d[\d,]*|(?:rs\.?|₹)\s?\d[\d,]*\b[^.\n]{0,20}(?:urgent|chahiye|immediately))", I),
        "Asks you to send money"),
    "credential_request": (30, True,
        re.compile(r"(?:(?:enter|share|send|tell|give|provide|submit|confirm|verify)\b[^.\n]{0,30}\b(?:otp|upi pin|pin|cvv|cvc|password|passcode|card number|aadhaar|net ?banking)|"
                   r"(?:otp|cvv|upi pin|password)\b[^.\n]{0,20}\b(?:to confirm|to verify|to receive|to claim)|"
                   r"\b(?:anydesk|teamviewer|quicksupport|rustdesk)\b|share (?:the )?(?:\d+[- ]digit )?code)", I),
        "Asks for a secret (OTP, PIN, CVV, password) or remote access to your device"),
    "risky_payment": (20, False,
        re.compile(r"(?:gift ?cards?|itunes card|google play card|bitcoin|\bbtc\b|crypto(?:currency)?|usdt|western union|moneygram|wire transfer|"
                   r"scan (?:this |the )?qr|collect request|accept the (?:collect )?request|upi (?:id|collect)|to receive (?:money|your refund|the advance))", I),
        "Unusual or hard-to-reverse payment method"),
    "off_platform_contact": (10, False,
        re.compile(r"(?:\b(?:whatsapp|telegram|signal)\b|text me on|mail (?:me|us) at)", I),
        "Moves the conversation to a private channel"),
    "urgency_pressure": (10, False,
        re.compile(r"(?:within \d+ ?(?:hours?|hrs?|minutes?|mins?)|in \d+ ?(?:hours?|minutes?)|\bimmediately\b|\burgent(?:ly)?\b|last chance|act now|today only|"
                   r"(?:will|shall) be (?:blocked|suspended|disconnected|cut|closed|deactivated)|limited slots|expires? (?:today|tonight)|final notice|hurry)", I),
        "Creates time pressure so you act before thinking"),
    "authority_claim": (10, False,
        re.compile(r"(?:cyber ?crime|\bcbi\b|\bnarcotics\b|customs (?:department|officer)|\bpolice\b|income tax (?:department|officer)|\btrai\b|\brbi\b|"
                   r"army officer|\bofficer\b[^.\n]{0,20}\btransfer|fraud (?:prevention )?department|your (?:ceo|boss|manager)|this is (?:from )?(?:the )?(?:bank|hr|support))", I),
        "Claims to be an authority you cannot verify"),
    "secrecy_request": (15, False,
        re.compile(r"(?:do not|don't|dont|never) (?:tell|share|inform|discuss|call|disclose)\b[^.\n]{0,30}|keep (?:this|it) (?:secret|confidential|private|between us)|mat (?:bata|batana|batao)|kisi ko (?:mat|na)|stay on the (?:video )?call|"
                   r"(?:don't|do not) (?:hang up|disconnect)", I),
        "Asks you to keep it secret or stay on the line"),
    "too_good_to_be_true": (10, False,
        re.compile(r"(?:guaranteed (?:\d+|returns?|profit|income|job)|\d+ ?(?:%|percent)\s*(?:weekly|daily|monthly|returns?)|earn (?:rs\.?|₹|inr)?\s?[\d,]+\s*(?:/|per|a)\s*(?:day|hour|task)|"
                   r"no (?:experience|interview|skills?) (?:needed|required)|work from home[^.\n]{0,40}earn|you (?:have )?won|lucky draw|free (?:laptop|iphone|gift)|like and (?:rate|share)|per task)", I),
        "Pay or returns that are unrealistically good"),
    "tech_support_pitch": (20, False,
        re.compile(r"(?:(?:computer|device|pc|phone|laptop) (?:is|has been|may be) (?:infected|hacked|compromised)|allow remote access|call (?:microsoft|apple|windows|google) support|virus detected)", I),
        "Tech-support pitch that pushes you toward remote access or a helpline"),
    "payment_proof_pressure": (15, False,
        re.compile(r"(?:(?:check|see|attached|sent)\b[^.\n]{0,20}\bscreenshot|bank will (?:credit|reflect)|will (?:credit|reflect) (?:by|in) (?:evening|tomorrow|few)|ship (?:the item |it )?(?:today|first|now)|courier will collect)", I),
        "Pushes you to act on unverified payment proof or to ship first"),
    "tech_ai_hint": (3, False,
        re.compile(r"(?:\bai (?:trading )?bot\b|\bai[- ]powered (?:trading|investment)\b|voice (?:message|note)|new number|naya number|lost (?:my )?phone|phone toot)", I),
        "Pattern linked to AI-enabled or impersonation scams"),
}

URL_RE = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\"')\]]{3,300}|(?<![@\w.])(?:[a-z0-9\-]{1,63}\.)+(?:com|in|org|net|co|io|app|xyz|top|click|info|biz|me|link|site|online|icu|buzz|sbs|cyou|shop|store|live|vip)(?:/[^\s<>\"')\]]{0,200})?)")
URL_DEFANG = re.compile(r"(?i)hxxp", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@([A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+)")
COMPANY_CLAIM = re.compile(r"(?i)\b(hr|recruit(?:er|ment)|hiring|offer letter|company|careers?|joining)\b")

_rdap_cache: dict[str, tuple[float, int | None]] = {}


def extract_urls(text: str) -> list[str]:
    t = URL_DEFANG.sub("http", text).replace("[.]", ".")
    out, seen = [], set()
    for m in URL_RE.finditer(t):
        u = m.group(1).rstrip(".,;:!?")
        if u.lower() not in seen:
            seen.add(u.lower()); out.append(u)
    return out[:8]


def _host(u: str) -> str:
    if "://" not in u:
        u = "http://" + u
    try:
        p = urlsplit(u)
        return (p.hostname or "").lower()
    except ValueError:
        return ""


def _registrable(host: str) -> str:
    e = _EXTRACT(host)
    return f"{e.domain}.{e.suffix}" if e.suffix else host


def lookalike(reg: str) -> tuple[bool, str]:
    """True if the registrable domain imitates a known brand without being official."""
    if reg in OFFICIAL:
        return False, ""
    label = reg.split(".")[0]
    tokens = set(re.split(r"[-_\d]+", label))
    for brand in BRANDS:
        if brand in tokens and label != brand:   # e.g. sbi-kyc-update.xyz
            return True, brand
    for brand, doms in BRANDS.items():
        # brand name embedded in a different domain (e.g. sbi-kyc-update.xyz)
        if len(brand) >= 4 and brand in label.replace("-", "") and label != brand:
            return True, brand
        for d in doms:
            dl = d.split(".")[0]
            if len(dl) >= 5 and label != dl and Levenshtein.distance(label, dl) <= 2:
                return True, brand
    # confusables (amaz0n, paypa1, netfIix): compare visual skeletons
    sk = _skeleton(label)
    for brand in BRANDS:
        bs = _skeleton(brand)
        if len(brand) >= 4 and label != brand and bs in sk:
            return True, brand
    return False, ""


def _skeleton(x: str) -> str:
    x = x.lower().replace("rn", "m").replace("vv", "w")
    return x.translate(str.maketrans("01$5i1|3", "olssllle"))


async def domain_age_days(reg: str, client: httpx.AsyncClient | None = None) -> int | None:
    """Domain age via RDAP. Fixed host (rdap.org); user input is only a validated domain label."""
    d = valid_domain(reg)
    if not d:
        return None
    hit = _rdap_cache.get(d)
    if hit and time.time() - hit[0] < 86400:
        return hit[1]
    age = None
    try:
        own = client is None
        client = client or httpx.AsyncClient(timeout=config.RDAP_TIMEOUT_S, follow_redirects=True)
        try:
            r = await client.get(f"https://rdap.org/domain/{d}", headers={"Accept": "application/rdap+json"})
            if r.status_code == 200:
                for ev in r.json().get("events", []):
                    if ev.get("eventAction") == "registration":
                        dt = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                        age = max(0, (datetime.now(timezone.utc) - dt).days)
                        break
        finally:
            if own:
                await client.aclose()
    except Exception:
        age = None
    if len(_rdap_cache) > 1000:
        _rdap_cache.clear()
    _rdap_cache[d] = (time.time(), age)
    return age


NEG = re.compile(r"(?:never|not|n't|dont|without)\s*(?:ever\s*)?$", I)
LEGIT_FEE = re.compile(r"(?:tuition|semester|exam(?:ination)? fee|college portal|university portal|hostel fee|library fine)", I)


def _ok(name: str, text: str, m) -> bool:
    """Context checks that cut false alarms on genuine messages."""
    if name == "credential_request":
        before = text[max(0, m.start() - 25):m.start()]
        after = text[m.end():m.end() + 40]
        if NEG.search(before) or re.search(r"(?i)\bonly with the (?:driver|rider|agent)\b", after):
            return False
    if name == "advance_fee":
        ctx = text[max(0, m.start() - 60):m.end() + 60]
        if LEGIT_FEE.search(ctx):
            return False
    return True


def pattern_signals(text: str) -> list[tuple[EvidenceItem, list[tuple[int, int]]]]:
    out = []
    for name, (pts, hard, rx, detail) in PATTERNS.items():
        spans = [(m.start(), m.end()) for m in rx.finditer(text) if _ok(name, text, m)][:3]
        if spans:
            out.append((EvidenceItem(signal=name, value=text[spans[0][0]:spans[0][1]][:80], points=pts, detail=detail, hard=hard), spans))
    return out


async def analyze_evidence(text: str, use_rdap: bool = True) -> tuple[list[EvidenceItem], list[dict]]:
    """Returns (evidence items, highlightable spans [{start,end,signal}])."""
    t = normalize(text)
    items: list[EvidenceItem] = []
    spans: list[dict] = []
    for item, sp in pattern_signals(t):
        items.append(item)
        for a, b in sp:
            spans.append({"start": a, "end": b, "signal": item.signal})

    urls = extract_urls(t)
    ages = []
    for u in urls:
        host = _host(u)
        if not host:
            continue
        reg = _registrable(host)
        # url-specific signals
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            items.append(EvidenceItem(signal="url_ip_literal", value=host, points=15, detail="Link points to a raw IP address"))
            continue
        if "@" in u.split("//")[-1].split("/")[0]:
            items.append(EvidenceItem(signal="url_userinfo_trick", value=host, points=15, detail="Link hides its real destination after an @ sign"))
        if host.startswith("xn--") or ".xn--" in host:
            items.append(EvidenceItem(signal="url_homoglyph_punycode", value=host, points=20, detail="Look-alike (punycode) domain"))
        if reg in SHORTENERS or host in SHORTENERS:
            items.append(EvidenceItem(signal="url_shortener", value=host, points=8, detail="Shortened link hides the real destination"))
        la, brand = lookalike(reg)
        if la:
            items.append(EvidenceItem(signal="url_lookalike", value=reg, points=25, detail=f"Domain imitates '{brand}' but is not its official site"))
        tld = reg.rsplit(".", 1)[-1]
        if tld in RISKY_TLDS:
            items.append(EvidenceItem(signal="url_suspicious_tld", value=reg, points=5, detail=f".{tld} domains are frequently abused"))
        if u.lower().startswith("http://") and re.search(r"(?i)login|verify|kyc|pay|update|secure", u):
            items.append(EvidenceItem(signal="url_no_tls", value=host, points=5, detail="Login/payment link without HTTPS"))
        if reg not in OFFICIAL:
            ages.append(reg)
        sp = t.lower().find(u.lower())
        if sp >= 0:
            spans.append({"start": sp, "end": sp + len(u), "signal": "url"})

    if use_rdap and ages:
        res = await asyncio.gather(*(domain_age_days(r) for r in set(ages[:3])))
        for reg, age in zip(set(ages[:3]), res):
            if age is None:
                continue
            if age < 30:
                items.append(EvidenceItem(signal="url_new_domain", value=age, points=20, detail=f"{reg} was registered only {age} day(s) ago"))
            elif age < 90:
                items.append(EvidenceItem(signal="url_new_domain", value=age, points=10, detail=f"{reg} is only {age} days old"))

    # free-email recruiter / company claims
    for m in EMAIL_RE.finditer(t):
        dom = m.group(1).lower()
        if dom in FREE_EMAIL and COMPANY_CLAIM.search(t):
            items.append(EvidenceItem(signal="free_email_for_company", value=dom, points=10, detail="Company or recruiter contacts you from a free email address"))
            spans.append({"start": m.start(), "end": m.end(), "signal": "free_email_for_company"})
            break
    return items, spans


def evidence_score(items: list[EvidenceItem]) -> int:
    # one tally per signal type so repeated URLs cannot stack unboundedly
    best: dict[str, int] = {}
    for it in items:
        best[it.signal] = max(best.get(it.signal, 0), it.points)
    return min(100, sum(best.values()))
