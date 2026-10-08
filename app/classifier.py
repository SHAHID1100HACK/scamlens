"""Secondary opinion: TF-IDF + logistic regression trained at build time on UCI SMS Spam.
Loaded only from our own build artifact (never from user-supplied paths)."""
import joblib
from . import config

_model = None
_tried = False


def _load():
    global _model, _tried
    if _tried:
        return _model
    _tried = True
    p = config.MODEL_DIR / "classifier.joblib"
    if p.exists():
        try:
            _model = joblib.load(p)
        except Exception:
            _model = None
    return _model


def predict_prob(text: str) -> float | None:
    m = _load()
    if m is None:
        return None
    try:
        return float(m.predict_proba([text])[0][1])
    except Exception:
        return None
