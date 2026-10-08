import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    from app import main, llm
    main.limiter.minute.clear(); main.limiter.day.clear(); main.refresh_limiter.minute.clear(); main.refresh_limiter.day.clear()
    main.cache.clear(); llm._budget.update(day="", n=0)
    return TestClient(main.app)
