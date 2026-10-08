"""Orchestrates one analysis: redact -> evidence -> classifier -> RAG -> LLM -> fusion -> response."""
from __future__ import annotations
import re
import uuid
from datetime import date, datetime

from . import classifier, config
from .evidence import analyze_evidence, evidence_score
from .llm import analyze_with_llm
from .rag import store
from .schemas import (AnalyzeRequest, AnalyzeResponse, EvidenceItem, MatchedPlaybook, RedFlag)
from .scoring import fuse
from .security import injection_suspected, normalize, redact, _INJECTION

JOB = re.compile(r"(?i)\b(salary|stipend|job|intern(?:ship)?|vacancy|hiring|recruit|apply|offer letter|joining|work from home|per month|ctc)\b")
MARKET = re.compile(r"(?i)\b(seller|buyer|listing|olx|price|negotiable|delivery|courier|advance|sofa|bike|laptop|used|sell(?:ing)?|buy(?:ing)?)\b")


def detect_mode(text: str, hint: str) -> str:
    if hint != "auto":
        return hint
    stripped = re.sub(r"https?://\S+", "", text).strip()
    if len(stripped) < 25 and "http" in text.lower():
        return "link"
    if JOB.search(text):
        return "job_listing"
    return "chat"


DEFAULT_ACTIONS = {
    "high_risk": ["Do not pay, reply with details, or click any link", "Verify through the organisation's official website or app",
                  "Block and report the sender", "Tell a friend or family member before acting"],
    "suspicious": ["Pause before acting on this", "Verify the sender through an official channel you find yourself",
                   "Never share OTPs, PINs or card details", "Ask someone you trust"],
    "uncertain": ["Treat it with caution until verified", "Check the sender through an official channel", "Never share OTPs or PINs"],
    "low_signals": ["Still verify unexpected requests through official channels", "Never share OTPs or PINs"],
}


def _fallback_text(label: str, items: list[EvidenceItem]) -> tuple[str, str, str]:
    reasons = [i.detail for i in items if i.points > 0][:4]
    if label == "high_risk":
        head = "This message shows several strong warning signs."
    elif label == "suspicious":
        head = "This message has some warning signs."
    elif label == "uncertain":
        head = "ScamLens is not sure about this message."
    else:
        head = "No strong red flags were found by the automatic checks."
    summary = head + (" " + "; ".join(reasons) + "." if reasons else "") + " Always verify through official channels."
    reply = "Thanks, I will verify this directly with the official organisation before doing anything."
    warn = "Careful: I got a message that looks like a scam. Do not pay or share codes, and check through official channels."
    return summary[:700], reply, warn


def _rule_flags(text: str, spans: list[dict], items: list[EvidenceItem]) -> list[RedFlag]:
    why = {i.signal: i.detail for i in items}
    out, seen = [], set()
    for sp in sorted(spans, key=lambda s: s["start"]):
        q = text[sp["start"]:sp["end"]].strip()
        sig = sp["signal"]
        if sig == "url":
            continue
        if len(q) < 4 or q.lower() in seen:
            continue
        seen.add(q.lower())
        out.append(RedFlag(quote=q[:200], why=why.get(sig, "Warning sign")[:200], category=sig))
    return out


async def run(req: AnalyzeRequest) -> AnalyzeResponse:
    original = req.text
    norm = normalize(original)
    red_text, n_red = redact(norm)
    mode = detect_mode(norm, req.mode)

    items, spans = await analyze_evidence(norm)
    # prompt-injection attempts inside the submitted text are themselves a strong warning sign
    inj = _INJECTION.search(norm)
    if inj:
        items.append(EvidenceItem(signal="prompt_injection_attempt", value=inj.group(0)[:60], points=15,
                                  detail="The text tries to give instructions to an AI system"))
        spans.append({"start": inj.start(), "end": inj.end(), "signal": "prompt_injection_attempt"})

    ev_score = evidence_score(items)
    cls_prob = classifier.predict_prob(red_text)
    retrieved = store.retrieve(red_text)
    cards = [c for c, _ in retrieved]

    llm_out = await analyze_with_llm(red_text, mode, items, cards)
    if llm_out and llm_out.injection_attempt_detected and not inj:
        items.append(EvidenceItem(signal="prompt_injection_attempt", value=True, points=15,
                                  detail="The text tries to give instructions to an AI system"))
        ev_score = evidence_score(items)

    score, label, conf, limited, bd = fuse(ev_score, cls_prob, llm_out.risk if llm_out else None,
                                           llm_out.confidence if llm_out else None, items, len(norm))

    flags = list(llm_out.red_flags) if llm_out else []
    have = {f.quote.lower() for f in flags}
    for f in _rule_flags(norm, spans, items):
        if f.quote.lower() not in have and len(flags) < 8:
            flags.append(f); have.add(f.quote.lower())

    sim = {c.id: s for c, s in retrieved}
    order = ([i for i in llm_out.matched_playbook_ids if i in sim] if llm_out else [])
    order += [c.id for c in cards if c.id not in order]
    by_id = {c.id: c for c in cards}
    today = date.today()
    matched = []
    for i in order[:3]:
        c = by_id[i]
        try:
            fresh = (today - datetime.strptime(c.date, "%Y-%m-%d").date()).days <= 7
        except ValueError:
            fresh = False
        matched.append(MatchedPlaybook(id=c.id, name=c.name, source=c.origin, learned_on=c.date,
                                       source_url=c.source_url, similarity=round(sim[i], 2),
                                       new_this_week=fresh and c.origin == "auto"))

    f_sum, f_reply, f_warn = _fallback_text(label, items)
    summary = (llm_out.summary if llm_out and llm_out.summary else f_sum)
    if label == "uncertain":
        summary = "ScamLens is not sure about this one. " + summary
    if n_red:
        summary += f" ({n_red} sensitive item(s) were hidden before analysis.)"
    actions = (llm_out.safe_actions if llm_out and llm_out.safe_actions else DEFAULT_ACTIONS[label])
    return AnalyzeResponse(
        request_id=str(uuid.uuid4()), score=score, label=label, confidence=conf, limited_mode=limited,
        summary=summary[:900], red_flags=flags[:8], evidence=items[:14], matched_playbooks=matched,
        safe_actions=actions[:5], safe_reply=(llm_out.safe_reply if llm_out and llm_out.safe_reply else f_reply),
        forward_warning=(llm_out.forward_warning if llm_out and llm_out.forward_warning else f_warn),
        score_breakdown=bd)
