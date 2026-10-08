"""Playbook store + retrieval (TF-IDF cosine with recency bonus) + safe knowledge refresh."""
from __future__ import annotations
import asyncio
import json
import time
from datetime import date, datetime
from typing import Iterable

import httpx
from pydantic import ValidationError
from sklearn.feature_extraction.text import TfidfVectorizer

from . import config
from .schemas import PlaybookCard


def _card_text(c: PlaybookCard) -> str:
    return " ".join([c.name, c.hook, " ".join(c.red_flags), " ".join(c.pressure_tactics),
                     " ".join(c.channels), " ".join(c.payment_methods)])


def _load(path) -> list[PlaybookCard]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for r in raw if isinstance(raw, list) else []:
        try:
            out.append(PlaybookCard(**r))
        except ValidationError:
            continue
    return out


class Store:
    def __init__(self):
        self.seed: list[PlaybookCard] = _load(config.DATA_DIR / "seed_cards.json")
        self.auto: list[PlaybookCard] = [c for c in _load(config.DATA_DIR / "auto_cards.json") if c.confidence >= 0.7]
        self.quarantined = len(_load(config.DATA_DIR / "quarantine.json"))
        self.last_refresh: str | None = None
        self._lock = asyncio.Lock()
        self._last_call = 0.0
        self._build()

    def _build(self):
        cards = self.seed + [c for c in self.auto if c.id not in {s.id for s in self.seed}]
        vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english", min_df=1)
        mat = vec.fit_transform([_card_text(c) for c in cards])
        self.cards, self.vec, self.mat = cards, vec, mat  # atomic swap of the three together

    def retrieve(self, text: str, k: int = config.TOP_K) -> list[tuple[PlaybookCard, float]]:
        if not self.cards:
            return []
        q = self.vec.transform([text])
        sims = (self.mat @ q.T).toarray().ravel()
        today = date.today()
        scored = []
        for c, s in zip(self.cards, sims):
            if s < config.MIN_SIMILARITY:
                continue
            try:
                age = (today - datetime.strptime(c.date, "%Y-%m-%d").date()).days
            except ValueError:
                age = 9999
            bonus = 0.05 if age <= 14 else 0.02 if age <= 60 else 0.0
            scored.append((c, float(s), float(s) + bonus))
        scored.sort(key=lambda t: t[2], reverse=True)
        return [(c, s) for c, s, _ in scored[:k]]

    def status(self) -> dict:
        newest = max((c.date for c in self.cards), default="")
        return {"seed_count": len(self.seed), "auto_count": len(self.auto),
                "quarantined_count": self.quarantined, "last_refresh": self.last_refresh,
                "newest_card_date": newest}

    async def refresh(self, client: httpx.AsyncClient | None = None) -> dict:
        """Pull validated cards from the fixed KNOWLEDGE_URL. Never runs ingestion or an LLM."""
        if not config.KNOWLEDGE_URL.startswith("https://"):
            return {"error": "knowledge source not configured"}
        if time.time() - self._last_call < config.REFRESH_COOLDOWN_S:
            return {"error": "cooldown", "retry_after": int(config.REFRESH_COOLDOWN_S - (time.time() - self._last_call))}
        if self._lock.locked():
            return {"error": "refresh already running"}
        async with self._lock:
            self._last_call = time.time()
            own = client is None
            client = client or httpx.AsyncClient(timeout=5.0, follow_redirects=False)
            try:
                r = await client.get(config.KNOWLEDGE_URL)
                if r.status_code != 200 or len(r.content) > 2_000_000:
                    return {"error": "bad response"}
                raw = r.json()
                cards = [PlaybookCard(**x) for x in raw]       # one bad card rejects the whole file
            except (httpx.HTTPError, ValueError, ValidationError, TypeError):
                return {"error": "invalid knowledge file"}
            finally:
                if own:
                    await client.aclose()
            cards = [c.model_copy(update={"origin": "auto"}) for c in cards if c.confidence >= 0.7][:200]
            before = len(self.auto)
            self.auto = cards
            self._build()
            self.last_refresh = datetime.utcnow().isoformat(timespec="seconds") + "Z"
            return {"added": max(0, len(cards) - before), "total_auto": len(cards),
                    "newest_card_date": self.status()["newest_card_date"]}


store = Store()
