"""Minimal subset of itsdangerous used in tests."""
from __future__ import annotations

import base64
import hmac
import time
from hashlib import sha256
from typing import Union

from .exc import BadSignature


class TimestampSigner:
    """Tiny reimplementation compatible with Starlette's expectations."""

    def __init__(self, secret_key: Union[str, bytes], sep: bytes = b".") -> None:
        if isinstance(secret_key, str):
            secret_key = secret_key.encode("utf-8")
        self._secret = secret_key
        self.sep = sep

    def _signature(self, value: bytes, timestamp: bytes) -> bytes:
        digest = hmac.new(self._secret, value + self.sep + timestamp, sha256).digest()
        return base64.b64encode(digest)

    def sign(self, value: Union[str, bytes]) -> bytes:
        if isinstance(value, str):
            value = value.encode("utf-8")
        timestamp = str(int(time.time())).encode("ascii")
        sig = self._signature(value, timestamp)
        return self.sep.join((value, timestamp, sig))

    def unsign(self, signed_value: Union[str, bytes], max_age: int | None = None) -> bytes:
        if isinstance(signed_value, str):
            signed_value = signed_value.encode("utf-8")
        try:
            value, timestamp, signature = signed_value.split(self.sep, 2)
        except ValueError as exc:  # pragma: no cover - defensive
            raise BadSignature("Malformed signed value") from exc

        expected = self._signature(value, timestamp)
        if not hmac.compare_digest(signature, expected):
            raise BadSignature("Signature does not match")

        if max_age is not None:
            try:
                ts_int = int(timestamp.decode("ascii"))
            except ValueError as exc:  # pragma: no cover - defensive
                raise BadSignature("Bad timestamp") from exc
            if time.time() - ts_int > max_age:
                raise BadSignature("Signature expired")

        return value


__all__ = ["BadSignature", "TimestampSigner"]
