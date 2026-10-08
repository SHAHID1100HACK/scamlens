"""FastAPI app. Security: strict validation, size caps, rate limits, headers on every response."""
from __future__ import annotations
import asyncio
import hashlib
import json
import logging
import re
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from . import config
from .pipeline import run
from .rag import store
from .schemas import AnalyzeRequest, ID_RE
from .security import SECURITY_HEADERS, RateLimiter, TTLCache, client_ip

log = logging.getLogger("scamlens")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

async def _auto_refresh():
    """Pull the reviewed knowledge file from the one fixed KNOWLEDGE_URL, now and every few hours."""
    while True:
        try:
            await store.refresh()
            cache.clear()
        except Exception as e:
            log.warning("knowledge refresh failed class=%s", type(e).__name__)
        await asyncio.sleep(config.REFRESH_INTERVAL_S)


@asynccontextmanager
async def lifespan(_):
    task = asyncio.create_task(_auto_refresh()) if config.KNOWLEDGE_URL else None
    yield
    if task:
        task.cancel()


api = FastAPI(title="ScamLens", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
limiter, refresh_limiter, cache = RateLimiter(), RateLimiter(), TTLCache()
api.add_middleware(CORSMiddleware, allow_origins=config.ALLOWED_ORIGINS, allow_origin_regex=r"^moz-extension://[0-9a-f-]{36}$",
                   allow_methods=["GET", "POST", "OPTIONS"],
                   allow_headers=["Content-Type"], allow_credentials=False, max_age=600)


def err(status: int, msg: str, **extra):
    return JSONResponse({"error": msg, **extra}, status_code=status)


@api.exception_handler(RequestValidationError)
async def _validation(_: Request, __):
    return err(422, "Invalid request.")


@api.exception_handler(Exception)
async def _unhandled(_: Request, exc: Exception):
    log.warning("unhandled error class=%s", type(exc).__name__)   # class only: never log content
    return err(500, "Something went wrong.")


async def read_limited_json(request: Request) -> dict | None:
    if int(request.headers.get("content-length", "0") or 0) > config.MAX_BODY_BYTES:
        return None
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > config.MAX_BODY_BYTES:
            return None
    try:
        data = json.loads(bytes(buf) or b"null")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


@api.get("/health")
async def health():
    return {"status": "ok"}


@api.post("/api/analyze")
async def analyze(request: Request):
    ip = client_ip(request.headers, request.client.host if request.client else None)
    if not limiter.allow(ip, config.RATE_PER_MINUTE, config.RATE_PER_DAY):
        r = err(429, "Too many requests. Please slow down.")
        r.headers["Retry-After"] = "30"
        return r
    if "application/json" not in request.headers.get("content-type", ""):
        return err(415, "Send JSON.")
    data = await read_limited_json(request)
    if data is None:
        return err(413, "Request too large.")
    try:
        req = AnalyzeRequest(**data)
    except (ValidationError, TypeError):
        return err(422, "Invalid request. Text must be 20 to 6000 characters.")
    key = hashlib.sha256(f"{req.mode}\n{req.text}".encode()).hexdigest()
    hit = cache.get(key)
    if hit:
        return JSONResponse(hit)
    t0 = time.time()
    resp = await run(req)
    payload = resp.model_dump()
    cache.set(key, payload)
    log.info("analyze id=%s mode=%s len=%d label=%s limited=%s signals=%s ms=%d", resp.request_id, req.mode,
             len(req.text), resp.label, resp.limited_mode, [e.signal for e in resp.evidence], (time.time() - t0) * 1000)
    return JSONResponse(payload)


@api.get("/api/knowledge/status")
async def kstatus():
    return store.status()


@api.get("/api/playbooks/{pid}")
async def playbook(pid: str):
    if not ID_RE.match(pid):
        return err(404, "Not found.")
    for c in store.cards:
        if c.id == pid:
            return c.model_dump(exclude={"confidence"})
    return err(404, "Not found.")


@api.get("/")
async def index():
    return FileResponse(config.STATIC_DIR / "index.html")


DL_DIR = config.STATIC_DIR / "downloads"
DL_RE = re.compile(r"^scamlens-extension-v[0-9]{1,3}(?:\.[0-9]{1,3}){1,2}\.zip$")


@api.get("/api/extension/version")
async def ext_version():
    try:
        return json.loads((DL_DIR / "version.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return err(404, "Extension package not built.")


@api.get("/downloads/{name}")
async def download(name: str):
    """Fixed-directory download; name must match a strict pattern (no path traversal)."""
    if not DL_RE.match(name) or not (DL_DIR / name).is_file():
        return err(404, "Not found.")
    return FileResponse(DL_DIR / name, media_type="application/zip", filename=name)


@api.get("/install")
async def install():
    return FileResponse(config.STATIC_DIR / "install.html")


class SafeStatic(StaticFiles):
    async def get_response(self, path, scope):
        if path.startswith("downloads"):      # downloads are served only through the strict /downloads route
            from starlette.exceptions import HTTPException
            raise HTTPException(status_code=404)
        return await super().get_response(path, scope)


api.mount("/static", SafeStatic(directory=str(config.STATIC_DIR)), name="static")


class SecurityHeaders:
    """Outermost ASGI wrapper so even 500s and 404s carry the headers."""
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.inner(scope, receive, send)
        path = scope.get("path", "")

        async def send2(msg):
            if msg["type"] == "http.response.start":
                headers = [(k, v) for k, v in msg.get("headers", []) if k.lower() not in
                           {h.lower().encode() for h in SECURITY_HEADERS}]
                for k, v in SECURITY_HEADERS.items():
                    headers.append((k.encode(), v.encode()))
                if path.startswith("/api/"):
                    headers.append((b"cache-control", b"no-store"))
                msg = {**msg, "headers": headers}
            await send(msg)
        await self.inner(scope, receive, send2)


app = SecurityHeaders(api)
