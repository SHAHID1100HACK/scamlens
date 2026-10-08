"""Security helpers: redaction, sanitising, injection screening, SSRF guard, rate limiting, cache."""
from __future__ import annotations
import ipaddress
import re
import secrets
import socket
import time
import unicodedata
from collections import OrderedDict, defaultdict, deque
from urllib.parse import urlsplit

from . import config

# ---------------------------------------------------------------- headers
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'self' https://huggingface.co"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

# ---------------------------------------------------------------- text hygiene
_ZW = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")


def normalize(text: str) -> str:
    """NFKC + strip invisible/bidi characters (used for matching)."""
    return _ZW.sub("", unicodedata.normalize("NFKC", text))


def strip_markup(s: str, limit: int = 600) -> str:
    """Remove HTML-ish and markdown-link characters from model/server strings."""
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)
    s = s.replace("<", "").replace(">", "")
    s = _ZW.sub("", s)
    return s.strip()[:limit]


# ---------------------------------------------------------------- redaction
def _luhn(num: str) -> bool:
    ds = [int(c) for c in num][::-1]
    tot = sum(ds[0::2]) + sum(sum(divmod(d * 2, 10)) for d in ds[1::2])
    return tot % 10 == 0


_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_AADHAAR = re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)")
_SECRET_CTX = re.compile(r"(?i)\b(otp|pin|cvv|cvc|password|passcode)\b\s*(?:is|:|=|-)?\s*([A-Za-z0-9@#$!]{3,12})")


def redact(text: str) -> tuple[str, int]:
    """Mask card numbers, 12-digit IDs and secrets next to OTP/PIN/CVV words."""
    count = 0

    def card(m):
        nonlocal count
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            count += 1
            tail = m.group(0)[len(m.group(0).rstrip(" -")):]
            return "[CARD HIDDEN]" + tail
        return m.group(0)

    def aad(m):
        nonlocal count
        count += 1
        return "[ID HIDDEN]"

    def sec(m):
        nonlocal count
        count += 1
        return f"{m.group(1)} [HIDDEN]"

    text = _CARD.sub(card, text)
    text = _AADHAAR.sub(aad, text)
    text = _SECRET_CTX.sub(sec, text)
    return text, count


# ---------------------------------------------------------------- injection screening
_INJECTION = re.compile(
    r"(?i)(ignore (all |any )?(the )?(previous|prior|above) (instructions|prompts?)|"
    r"disregard (all |the )?(previous|prior|above)|system prompt|developer message|"
    r"you are now|act as (an? )?(ai|assistant|system)|new instructions|"
    r"(mark|rate|label|classify|output|set) (this|it|the (message|text)) (as )?(safe|legit|genuine|risk ?0)|"
    r"risk\s*[:=]\s*0\b|<<<\s*(end|data)|\bassistant\s*:|\bsystem\s*:)"
)


def injection_suspected(text: str) -> bool:
    return bool(_INJECTION.search(normalize(text)))


def new_nonce() -> str:
    return secrets.token_hex(8)


def strip_delimiters(text: str) -> str:
    return text.replace("<<<", "< < <").replace(">>>", "> > >")


# ---------------------------------------------------------------- SSRF guard
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def valid_domain(domain: str) -> str | None:
    """Return an ASCII (IDNA) lowercase domain if it is a plausible public hostname."""
    d = domain.strip().strip(".").lower()
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return d if _DOMAIN_RE.match(d) else None


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_global


def check_url_target(url: str, resolver=socket.getaddrinfo) -> tuple[bool, str]:
    """SSRF pre-check. True only if scheme/port/host are safe and every resolved IP is public."""
    try:
        p = urlsplit(url)
    except ValueError:
        return False, "unparseable"
    if p.scheme not in ("http", "https"):
        return False, "scheme"
    if p.username or p.password or "@" in (p.netloc or ""):
        return False, "credentials"
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        return False, "port"
    if port not in (80, 443):
        return False, "port"
    host = p.hostname
    if not host:
        return False, "nohost"
    # integer / hex / octal IP forms
    if re.fullmatch(r"(0x[0-9a-f]+|\d+)", host, re.I):
        return False, "numeric-host"
    try:
        ipaddress.ip_address(host)
        return (is_public_ip(host), "ip-literal" if not is_public_ip(host) else "ok")
    except ValueError:
        pass
    if host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
        return False, "local-name"
    try:
        infos = resolver(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return False, "unresolvable"
    ips = {i[4][0] for i in infos}
    if not ips or not all(is_public_ip(ip) for ip in ips):
        return False, "non-public-ip"
    return True, "ok"


# ---------------------------------------------------------------- rate limit + cache
class RateLimiter:
    def __init__(self):
        self.minute: dict[str, deque] = defaultdict(deque)
        self.day: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str, per_min: int, per_day: int, now: float | None = None) -> bool:
        now = now or time.time()
        m, d = self.minute[key], self.day[key]
        while m and now - m[0] > 60:
            m.popleft()
        while d and now - d[0] > 86400:
            d.popleft()
        if len(m) >= per_min or len(d) >= per_day:
            return False
        m.append(now)
        d.append(now)
        if len(self.minute) > 5000:  # crude memory bound
            self.minute.clear(); self.day.clear()
        return True


class TTLCache:
    def __init__(self, ttl=config.CACHE_TTL_S, maxsize=config.CACHE_MAX):
        self.ttl, self.maxsize = ttl, maxsize
        self.d: OrderedDict = OrderedDict()

    def get(self, k):
        v = self.d.get(k)
        if not v:
            return None
        if time.time() - v[0] > self.ttl:
            self.d.pop(k, None)
            return None
        return v[1]

    def set(self, k, val):
        self.d[k] = (time.time(), val)
        self.d.move_to_end(k)
        while len(self.d) > self.maxsize:
            self.d.popitem(last=False)

    def clear(self):
        self.d.clear()


def client_ip(headers, peer: str | None) -> str:
    """Right-most X-Forwarded-For entry (added by the platform proxy), else the socket peer."""
    xff = headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[-1].strip()[:64]
    return (peer or "unknown")[:64]
