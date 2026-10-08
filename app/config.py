"""Central configuration. Secrets come only from environment variables."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
STATIC_DIR = BASE_DIR / "app" / "static"


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "")
FALLBACK_API_KEY = os.getenv("FALLBACK_API_KEY", "")
FALLBACK_BASE_URL = os.getenv("FALLBACK_BASE_URL", "").rstrip("/")
FALLBACK_MODEL = os.getenv("FALLBACK_MODEL", "")
KNOWLEDGE_URL = os.getenv("KNOWLEDGE_URL", "")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
ENABLE_URL_EXPANSION = os.getenv("ENABLE_URL_EXPANSION", "false").lower() == "true"

MIN_TEXT = 20
MAX_TEXT = 6000
MAX_BODY_BYTES = 20 * 1024
DAILY_LLM_BUDGET = _int("DAILY_LLM_BUDGET", 800)
RATE_PER_MINUTE = _int("RATE_PER_MINUTE", 8)
RATE_PER_DAY = _int("RATE_PER_DAY", 60)
REFRESH_PER_HOUR = 3
REFRESH_COOLDOWN_S = 60
REFRESH_INTERVAL_S = 6 * 3600
CACHE_TTL_S = 3600
CACHE_MAX = 500
LLM_TIMEOUT_S = 25.0
LLM_MAX_TOKENS = 3000
THINKING_LEVEL = os.getenv("THINKING_LEVEL", "minimal")
RDAP_TIMEOUT_S = 3.0
TOP_K = 4
MIN_SIMILARITY = 0.15   # TF-IDF cosine scale; tuned against genuine messages
