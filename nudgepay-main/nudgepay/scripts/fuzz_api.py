#!/usr/bin/env python3
"""Lightweight fuzzing harness for the public API surface."""

from __future__ import annotations

import json
import os
import random
import string
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterable

BASE_URL = os.getenv("NUDGPAY_BASE_URL", "http://localhost:8000")
ENDPOINTS = ["/api/payments", "/api/invoices", "/api/webhooks/test"]


@dataclass(slots=True)
class FuzzResult:
    endpoint: str
    payload: dict[str, object]
    status: int
    error: str | None = None


def _random_string(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _payloads() -> Iterable[dict[str, object]]:
    yield {"value": _random_string(), "amount": random.randint(-10_000, 10_000)}
    yield {"value": None, "nested": {"unexpected": True}}
    yield {"list": [_random_string(4) for _ in range(3)]}


def fuzz_once(endpoint: str, payload: dict[str, object]) -> FuzzResult:
    url = f"{BASE_URL.rstrip('/')}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return FuzzResult(endpoint, payload, response.status)
    except urllib.error.HTTPError as exc:  # pragma: no cover - depends on service responses
        return FuzzResult(endpoint, payload, exc.code, error=str(exc))
    except Exception as exc:  # pragma: no cover - network dependent
        return FuzzResult(endpoint, payload, -1, error=str(exc))


def main(rounds: int = 10) -> int:
    results: list[FuzzResult] = []
    for _ in range(rounds):
        endpoint = random.choice(ENDPOINTS)
        payload = random.choice(list(_payloads()))
        results.append(fuzz_once(endpoint, payload))

    failures = [result for result in results if result.status >= 500 or result.status < 0]
    for result in failures:
        print(f"[FAIL] {result.endpoint} status={result.status} error={result.error}")
    return 1 if failures else 0


if __name__ == "__main__":  # pragma: no cover - script entrypoint
    sys.exit(main())
