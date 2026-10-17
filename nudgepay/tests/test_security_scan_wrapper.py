from __future__ import annotations

import subprocess
from typing import Any, Dict

import pytest

from nudgepay.scripts import security_scan


class _FakeCompletedProcess:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _install_fake_run(monkeypatch: pytest.MonkeyPatch, result: _FakeCompletedProcess) -> Dict[str, Any]:
    captured_args: Dict[str, Any] = {}

    def _fake_run(*args: Any, **kwargs: Any) -> _FakeCompletedProcess:
        captured_args["args"] = args
        captured_args["kwargs"] = kwargs
        return result

    monkeypatch.setattr(subprocess, "run", _fake_run)
    return captured_args


def test_run_pip_audit_success(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    result = _FakeCompletedProcess(returncode=0, stdout="ok", stderr="")
    captured = _install_fake_run(monkeypatch, result)

    exit_code = security_scan.run_pip_audit()

    assert exit_code == 0
    assert "pip-audit" in captured["args"][0][0]
    output = capsys.readouterr()
    assert output.out == "ok"
    assert output.err == ""


@pytest.mark.parametrize(
    "stderr",
    [
        "requests.exceptions.ProxyError: Tunnel connection failed: 403",  # proxy issue
        "Failed to establish a new connection: [Errno -3] Temporary failure in name resolution",
    ],
)
def test_run_pip_audit_network_issue(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stderr: str,
) -> None:
    result = _FakeCompletedProcess(returncode=1, stdout="", stderr=stderr)
    _install_fake_run(monkeypatch, result)

    exit_code = security_scan.run_pip_audit()

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "pip-audit skipped" in captured.err


def test_run_pip_audit_real_failure(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    result = _FakeCompletedProcess(returncode=2, stdout="warning", stderr="boom")
    _install_fake_run(monkeypatch, result)

    exit_code = security_scan.run_pip_audit()

    assert exit_code == 2
    captured = capsys.readouterr()
    assert captured.out == "warning"
    assert captured.err.endswith("boom")
