#!/usr/bin/env python3
"""Synthetic monitoring script for key user journeys."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

BASE_URL = os.getenv("NUDGPAY_BASE_URL", "http://localhost:8000")


def _request(path: str, method: str = "GET", data: bytes | None = None) -> int:
    url = f"{BASE_URL.rstrip('/')}{path}"
    request = urllib.request.Request(url, data=data, method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:  # pragma: no cover - external dependency
        return exc.code
    except Exception:  # pragma: no cover - external dependency
        return 0


def run_once() -> dict[str, int]:
    status: dict[str, int] = {}
    status["health"] = _request("/healthz")
    status["marketing"] = _request("/")
    payload = json.dumps({"invoice_id": 1, "stage": "manual"}).encode("utf-8")
    status["webhook"] = _request("/webhooks/stripe", method="POST", data=payload)
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="Synthetic monitor runner")
    parser.add_argument("--iterations", type=int, default=1, help="Number of iterations to execute")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable output")
    args = parser.parse_args()

    failures = 0
    history: list[dict[str, int]] = []
    for _ in range(args.iterations):
        results = run_once()
        history.append(results)
        for check, status in results.items():
            if not args.json:
                print(f"{check}: {status}")
            if status >= 500 or status == 0:
                failures += 1
    if args.json:
        summary = {"iterations": args.iterations, "failures": failures, "history": history}
        print(json.dumps(summary))
    return 1 if failures else 0


if __name__ == "__main__":  # pragma: no cover - script entrypoint
    sys.exit(main())
