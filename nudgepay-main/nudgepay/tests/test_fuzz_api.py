import json
from urllib.error import HTTPError

import pytest

from nudgepay.scripts import fuzz_api


def test_random_string_generates_alphanumeric_characters():
    value = fuzz_api._random_string(12)
    assert len(value) == 12
    allowed = set(fuzz_api.string.ascii_letters + fuzz_api.string.digits)
    assert set(value) <= allowed


def test_payloads_shape(monkeypatch):
    monkeypatch.setattr(fuzz_api, '_random_string', lambda length=16: 'x' * length)
    payloads = list(fuzz_api._payloads())
    assert payloads[0]['amount'] >= -10_000
    assert payloads[1]['nested'] == {'unexpected': True}
    assert payloads[2]['list'] == ['xxxx' for _ in range(3)]


class DummyResponse:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_fuzz_once_success(monkeypatch):
    def fake_urlopen(request, timeout):
        assert request.full_url.endswith('/probe')
        assert json.loads(request.data) == {'payload': True}
        return DummyResponse(204)

    monkeypatch.setattr(fuzz_api.urllib.request, 'urlopen', fake_urlopen)
    result = fuzz_api.fuzz_once('/probe', {'payload': True})
    assert result.status == 204
    assert result.error is None


def test_fuzz_once_http_error(monkeypatch):
    error = HTTPError('http://test/probe', 503, 'boom', hdrs=None, fp=None)

    def fake_urlopen(request, timeout):
        raise error

    monkeypatch.setattr(fuzz_api.urllib.request, 'urlopen', fake_urlopen)
    result = fuzz_api.fuzz_once('/probe', {'payload': False})
    assert result.status == 503
    assert 'boom' in result.error


def test_main_reports_failures(monkeypatch, capsys):
    outputs = [
        fuzz_api.FuzzResult('/ok', {'id': 1}, 200),
        fuzz_api.FuzzResult('/bad', {'id': 2}, 503, error='server exploded'),
    ]
    calls = []

    def fake_fuzz(endpoint, payload):
        calls.append((endpoint, payload))
        return outputs[len(calls) - 1]

    monkeypatch.setattr(fuzz_api, 'fuzz_once', fake_fuzz)
    monkeypatch.setattr(fuzz_api.random, 'choice', lambda seq: seq[0])
    monkeypatch.setattr(fuzz_api, '_payloads', lambda: [{'id': 1}])

    exit_code = fuzz_api.main(rounds=2)
    captured = capsys.readouterr()

    assert exit_code == 1
    assert '[FAIL] /bad status=503 error=server exploded' in captured.out
    assert calls == [('/api/payments', {'id': 1}), ('/api/payments', {'id': 1})]
