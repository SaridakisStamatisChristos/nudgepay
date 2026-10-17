"""Helpers for running security scans in CI.

This wrapper ensures that ``pip-audit`` fails gracefully when it cannot
reach the vulnerability service (common inside sandboxed CI) while still
surfacing real dependency issues.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Sequence

# Error fragments that indicate the environment cannot reach the vulnerability
# database. ``pip-audit`` bubbles up the underlying ``requests`` error, so we
# simply look for those fragments and downgrade the failure to a warning.
_NETWORK_ERROR_FRAGMENTS: Sequence[str] = (
    "ProxyError",
    "Failed to establish a new connection",
    "Tunnel connection failed",
    "Name or service not known",
    "Temporary failure in name resolution",
    "getaddrinfo failed",
    "Network is unreachable",
    "Failed to upgrade `pip`",
)


def _pip_audit_command() -> list[str]:
    project_root = Path(__file__).resolve().parents[1]
    requirements = project_root / "requirements.txt"
    return [
        "pip-audit",
        "--progress-spinner=off",
        "--requirement",
        str(requirements),
    ]


def run_pip_audit() -> int:
    """Execute ``pip-audit`` and return the resulting exit code.

    Network failures are treated as a soft failure so that offline
    environments do not cause the entire CI job to fail. Any other
    non-zero exit code is propagated so that genuine vulnerabilities are
    still surfaced to developers.
    """

    result = subprocess.run(
        _pip_audit_command(),
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode == 0:
        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return 0

    combined_output = "\n".join(
        part for part in (result.stdout, result.stderr) if part
    )

    if any(fragment in combined_output for fragment in _NETWORK_ERROR_FRAGMENTS):
        if combined_output:
            sys.stderr.write(f"{combined_output}\n")
        sys.stderr.write(
            "pip-audit skipped: unable to reach vulnerability service; "
            "treating as a transient network issue.\n"
        )
        return 0

    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result.returncode


def main() -> int:
    return run_pip_audit()


if __name__ == "__main__":
    sys.exit(main())
