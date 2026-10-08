"""Fusion scoring, floors, labels, abstention."""
from __future__ import annotations
from .schemas import Breakdown, EvidenceItem


def fuse(evidence_score: int, classifier_prob: float | None, llm_risk: int | None,
         llm_conf: str | None, items: list[EvidenceItem], text_len: int):
    """Returns (score, label, confidence, limited_mode, breakdown)."""
    cls = round((classifier_prob or 0.0) * 100)
    limited = llm_risk is None
    if limited:
        w_e, w_c = (0.75, 0.25) if classifier_prob is not None else (1.0, 0.0)
        final = w_e * evidence_score + w_c * cls
    else:
        if classifier_prob is None:
            final = 0.5 * evidence_score + 0.5 * llm_risk
        else:
            final = 0.40 * evidence_score + 0.40 * llm_risk + 0.20 * cls
    fired = {i.signal for i in items}
    floor = None
    if "credential_request" in fired and final < 80:
        final, floor = 80, "credential_request"
    elif "advance_fee" in fired and final < 70:
        final, floor = 70, "advance_fee"
    score = int(round(max(0, min(100, final))))
    lo, hi = (20, 55) if limited else (30, 60)     # without the AI opinion, scores run lower: be more cautious
    label = "low_signals" if score < lo else "suspicious" if score < hi else "high_risk"
    conf = llm_conf or ("medium" if evidence_score >= 30 or fired else "low")

    uncertain = False
    if text_len < 20:
        uncertain = True
    elif not limited and abs(evidence_score - llm_risk) > 45 and floor is None:
        uncertain = True
    elif not limited and llm_conf == "low" and 30 <= score <= 70 and floor is None:
        uncertain = True
    elif limited and not fired and cls < 50:
        # nothing fired and no AI opinion: be honest rather than reassuring
        uncertain = False if score < 30 else True
    if uncertain:
        label = "uncertain"
    return score, label, conf, limited, Breakdown(evidence=evidence_score, classifier=cls, llm=llm_risk, floor_applied=floor)
