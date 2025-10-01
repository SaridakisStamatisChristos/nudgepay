"""Simple circuit breaker utilities with Redis-backed persistence."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from .redis_utils import get_redis

logger = logging.getLogger(__name__)


@dataclass
class _MemoryState:
    failures: int = 0
    opened_until: float = 0.0


class CircuitBreaker:
    """Track failures and short-circuit processing when a threshold is exceeded."""

    def __init__(
        self,
        name: str,
        *,
        failure_threshold: int,
        reset_after_seconds: int,
        redis_client: Any | None = None,
        use_redis: bool = True,
    ) -> None:
        if failure_threshold <= 0:
            raise ValueError("failure_threshold must be positive")
        if reset_after_seconds <= 0:
            raise ValueError("reset_after_seconds must be positive")
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_after_seconds = reset_after_seconds
        if not use_redis:
            self._redis = None
        elif redis_client is not None:
            self._redis = redis_client
        else:
            self._redis = get_redis()
        self._memory = _MemoryState()

    # Redis key helpers -------------------------------------------------
    @property
    def _failures_key(self) -> str:
        return f"nudgepay:cb:{self.name}:failures"

    @property
    def _open_key(self) -> str:
        return f"nudgepay:cb:{self.name}:open"

    # Lifecycle ---------------------------------------------------------
    def is_open(self) -> bool:
        """Return ``True`` when the circuit breaker is currently open."""

        if self._redis:
            try:
                return bool(self._redis.get(self._open_key))
            except Exception:  # pragma: no cover - redis connectivity issues
                logger.warning("Circuit breaker %s fell back to in-memory state", self.name, exc_info=True)
        now = time.time()
        if self._memory.opened_until and self._memory.opened_until <= now:
            self._memory.opened_until = 0.0
            self._memory.failures = 0
        return self._memory.opened_until > now

    def record_failure(self) -> None:
        """Register a failure and open the circuit when the threshold is reached."""

        if self._redis:
            try:
                failures = int(self._redis.incr(self._failures_key))
                if failures == 1:
                    self._redis.expire(self._failures_key, self.reset_after_seconds)
                if failures >= self.failure_threshold:
                    self._redis.setex(self._open_key, self.reset_after_seconds, 1)
                return
            except Exception:  # pragma: no cover - redis connectivity issues
                logger.warning("Circuit breaker %s failed to update redis state", self.name, exc_info=True)

        now = time.time()
        if self._memory.opened_until and now >= self._memory.opened_until:
            self._memory.failures = 0
            self._memory.opened_until = 0.0
        self._memory.failures += 1
        if self._memory.failures >= self.failure_threshold:
            self._memory.opened_until = now + self.reset_after_seconds

    def record_success(self) -> None:
        """Reset the breaker after a successful execution."""

        if self._redis:
            try:
                self._redis.delete(self._failures_key)
                self._redis.delete(self._open_key)
            except Exception:  # pragma: no cover - redis connectivity issues
                logger.warning("Circuit breaker %s failed to clear redis state", self.name, exc_info=True)
        self._memory.failures = 0
        self._memory.opened_until = 0.0

    def reset(self) -> None:
        """Alias for :meth:`record_success` to aid testability."""

        self.record_success()


__all__ = ["CircuitBreaker"]
