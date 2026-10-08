"""Strict Pydantic models for every input and output."""
from __future__ import annotations
import re
from typing import List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import config

Mode = Literal["auto", "job_listing", "chat", "link"]
Label = Literal["low_signals", "suspicious", "high_risk", "uncertain"]
Conf = Literal["low", "medium", "high"]
ID_RE = re.compile(r"^[a-z0-9\-]{3,64}$")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AnalyzeRequest(Strict):
    text: str
    mode: Mode = "auto"
    page_url: Optional[str] = Field(default=None, max_length=2048)
    language_hint: Optional[str] = Field(default=None, max_length=10)

    @field_validator("text")
    @classmethod
    def _text(cls, v: str) -> str:
        v = "".join(ch for ch in v if ch in "\n\t" or ord(ch) >= 32).strip()
        if len(v) < config.MIN_TEXT:
            raise ValueError("text too short")
        if len(v) > config.MAX_TEXT:
            raise ValueError("text too long")
        return v

    @field_validator("page_url")
    @classmethod
    def _url(cls, v):
        if v and not re.match(r"^https?://", v, re.I):
            raise ValueError("bad url")
        return v


class RedFlag(Strict):
    quote: str = Field(max_length=300)
    why: str = Field(max_length=200)
    category: str = Field(default="other", max_length=40)


class EvidenceItem(Strict):
    signal: str
    value: str | int | float | bool | None = None
    points: int = 0
    detail: str = ""
    hard: bool = False


class PlaybookCard(Strict):
    id: str
    name: str = Field(max_length=120)
    origin: Literal["seed", "auto"] = "seed"
    channels: List[str] = Field(default_factory=list, max_length=8)
    targets: List[str] = Field(default_factory=list, max_length=8)
    hook: str = Field(max_length=500)
    red_flags: List[str] = Field(default_factory=list, max_length=8)
    pressure_tactics: List[str] = Field(default_factory=list, max_length=8)
    payment_methods: List[str] = Field(default_factory=list, max_length=8)
    safe_response: List[str] = Field(default_factory=list, max_length=6)
    ai_enabled: bool = False
    date: str = "2026-10-01"
    source_url: str = ""
    source_name: str = ""
    confidence: float = 1.0

    @field_validator("id")
    @classmethod
    def _id(cls, v):
        if not ID_RE.match(v):
            raise ValueError("bad id")
        return v


class MatchedPlaybook(Strict):
    id: str
    name: str
    source: str
    learned_on: str
    source_url: str = ""
    similarity: float
    new_this_week: bool = False


class LLMOutput(Strict):
    risk: int = Field(ge=0, le=100)
    mode: str = "other"
    tactics: List[str] = Field(default_factory=list, max_length=12)
    red_flags: List[RedFlag] = Field(default_factory=list, max_length=12)
    matched_playbook_ids: List[str] = Field(default_factory=list, max_length=8)
    summary: str = Field(max_length=1200)
    safe_actions: List[str] = Field(default_factory=list, max_length=8)
    safe_reply: str = Field(default="", max_length=600)
    forward_warning: str = Field(default="", max_length=600)
    confidence: Conf = "medium"
    injection_attempt_detected: bool = False


class Breakdown(Strict):
    evidence: int
    classifier: int
    llm: Optional[int]
    floor_applied: Optional[str] = None


class AnalyzeResponse(Strict):
    request_id: str
    score: int
    label: Label
    confidence: Conf
    limited_mode: bool
    summary: str
    red_flags: List[RedFlag]
    evidence: List[EvidenceItem]
    matched_playbooks: List[MatchedPlaybook]
    safe_actions: List[str]
    safe_reply: str
    forward_warning: str
    score_breakdown: Breakdown
    disclaimer: str = ("ScamLens can be wrong. 'No strong red flags' does not mean safe. "
                       "Verify through official channels.")
