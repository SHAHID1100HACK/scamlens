from app.scoring import fuse
from app.schemas import EvidenceItem

def E(*names): return [EvidenceItem(signal=n, points=10) for n in names]

def test_floor_advance_fee_beats_low_llm():
    score, label, *_ = fuse(25, 0.1, 5, "high", E("advance_fee"), 100)
    assert score >= 70 and label == "high_risk"

def test_floor_credential_request():
    score, label, *_ = fuse(30, 0.0, 0, "high", E("credential_request"), 100)
    assert score >= 80

def test_limited_mode_flag_and_weights():
    score, label, conf, limited, bd = fuse(60, 0.5, None, None, E("urgency_pressure"), 100)
    assert limited and bd.llm is None and 50 <= score <= 60

def test_uncertain_on_disagreement():
    _, label, *_ = fuse(0, 0.0, 80, "high", [], 100)
    assert label == "uncertain"

def test_uncertain_low_conf_midrange():
    _, label, *_ = fuse(40, 0.4, 45, "low", E("urgency_pressure"), 100)
    assert label == "uncertain"

def test_low_signals():
    score, label, *_ = fuse(0, 0.02, 5, "high", [], 100)
    assert label == "low_signals" and score < 30
