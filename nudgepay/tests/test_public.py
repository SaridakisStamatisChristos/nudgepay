from app.main import app
from fastapi.testclient import TestClient

def test_landing_public():
    c = TestClient(app, base_url="https://testserver")
    r = c.get("/")
    assert r.status_code == 200
    assert b"NudgePay" in r.content
