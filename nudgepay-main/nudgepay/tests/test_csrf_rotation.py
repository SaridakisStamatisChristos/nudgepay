from types import SimpleNamespace

from starlette.requests import Request

from app import csrf


async def _empty_receive() -> dict:
    return {"type": "http.request", "body": b"", "more_body": False}


def _request_with_session() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "session": {},
        "app": {},
    }
    return Request(scope, _empty_receive)


def test_issue_csrf_token_rotates(monkeypatch):
    settings = SimpleNamespace(
        csrf_secret="secret",
        csrf_token_ttl_seconds=3600,
        csrf_rotation_interval_seconds=1,
    )
    monkeypatch.setattr(csrf, "get_settings", lambda: settings)

    request = _request_with_session()
    first = csrf.issue_csrf_token(request)
    request.scope["session"]["_csrf_rotated_at"] = 0
    second = csrf.issue_csrf_token(request)
    assert first != second


def test_force_rotate_clears_session(monkeypatch):
    settings = SimpleNamespace(
        csrf_secret="secret",
        csrf_token_ttl_seconds=3600,
        csrf_rotation_interval_seconds=300,
    )
    monkeypatch.setattr(csrf, "get_settings", lambda: settings)

    request = _request_with_session()
    token = csrf.issue_csrf_token(request)
    assert "_csrf_token" in request.scope["session"]
    rotated = csrf.force_rotate_csrf_token(request)
    assert rotated != token
    assert request.scope["session"].get("_csrf_rotated_at", 0) >= 0
