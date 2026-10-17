"""Security utilities for protecting administrative access."""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Deque, Dict

try:  # pragma: no cover - optional dependency
    from redis.exceptions import RedisError
except ImportError:  # pragma: no cover - optional dependency
    class RedisError(Exception):
        pass

from .redis_utils import get_redis

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class _AttemptWindow:
    """Track recent login attempts for a specific identity."""

    attempts: Deque[float]
    blocked_until: float | None = None


class LoginThrottle:
    """Enforce rate limits on login attempts to reduce brute-force risk."""

    def __init__(self, *, limit: int, window_seconds: int, block_seconds: int) -> None:
        self._limit = limit
        self._window = window_seconds
        self._block = block_seconds
        self._lock = Lock()
        self._state: Dict[str, _AttemptWindow] = {}
        self._redis = get_redis()
        if self._redis is None:
            logger.warning("Redis client not available; login throttling will use in-memory fallback")

    def _attempt_key(self, key: str) -> str:
        return f"login_attempts:{key}"

    def _block_key(self, key: str) -> str:
        return f"login_block:{key}"

    def _register_failure_redis(self, key: str, now: float) -> bool:
        if self._redis is None:
            return False
        attempt_key = self._attempt_key(key)
        block_key = self._block_key(key)
        try:
            pipe = self._redis.pipeline()
            pipe.zremrangebyscore(attempt_key, 0, now - self._window)
            pipe.zadd(attempt_key, {str(now): now})
            pipe.expire(attempt_key, self._window + self._block)
            pipe.zcard(attempt_key)
            _, _, _, count = pipe.execute()
            if int(count) >= self._limit:
                self._redis.setex(block_key, self._block, 1)
            return True
        except RedisError:
            logger.warning("Falling back to in-memory throttle due to Redis error", exc_info=True)
            self._redis = None
            return False

    def register_failure(self, key: str) -> bool:
        """Record a failed login attempt for ``key``.

        Returns ``True`` when the failure triggered a throttle block.
        """

        now = time.time()
        if self._register_failure_redis(key, now):
            redis_block = self._check_block_redis(key)
            return bool(redis_block)

        window = self._get_state(key)
        with self._lock:
            self._prune_attempts(window, now)
            window.attempts.append(now)
            if len(window.attempts) >= self._limit:
                window.blocked_until = now + self._block
                return True
        return False

    def reset(self, key: str) -> None:
        """Clear rate limit counters for ``key`` after successful authentication."""

        if self._redis is not None:
            try:
                self._redis.delete(self._attempt_key(key), self._block_key(key))
            except RedisError:
                logger.debug("Failed to clear Redis throttle state for %s", key, exc_info=True)
        with self._lock:
            if key in self._state:
                self._state.pop(key, None)

    def _check_block_redis(self, key: str) -> bool | None:
        if self._redis is None:
            return None
        try:
            if self._redis.exists(self._block_key(key)):
                return True
            # prune old attempts to keep window accurate
            self._redis.zremrangebyscore(self._attempt_key(key), 0, time.time() - self._window)
            return False
        except RedisError:
            logger.warning("Redis unavailable when checking throttle; using memory", exc_info=True)
            self._redis = None
            return None

    def is_blocked(self, key: str) -> bool:
        """Return ``True`` if ``key`` is currently blocked."""

        redis_block = self._check_block_redis(key)
        if redis_block is not None:
            return redis_block

        now = time.time()
        window = self._get_state(key)
        with self._lock:
            self._prune_attempts(window, now)
            blocked_until = window.blocked_until
            if blocked_until is None:
                return False
            if blocked_until <= now:
                window.blocked_until = None
                window.attempts.clear()
                return False
            return True

    def retry_after(self, key: str) -> int:
        """Return the remaining seconds before ``key`` can retry."""

        if self._redis is not None:
            try:
                ttl = self._redis.ttl(self._block_key(key))
                if ttl and ttl > 0:
                    return ttl
            except RedisError:
                logger.debug("Failed retrieving Redis TTL for %s", key, exc_info=True)
                self._redis = None

        now = time.time()
        window = self._get_state(key)
        blocked_until = window.blocked_until or 0.0
        retry_after = max(int(round(blocked_until - now)), 0)
        return retry_after

    def _get_state(self, key: str) -> _AttemptWindow:
        with self._lock:
            window = self._state.get(key)
            if window is None:
                window = _AttemptWindow(deque())
                self._state[key] = window
            return window

    def _prune_attempts(self, window: _AttemptWindow, now: float) -> None:
        """Remove attempts outside the sliding window."""

        threshold = now - self._window
        while window.attempts and window.attempts[0] < threshold:
            window.attempts.popleft()


__all__ = ["LoginThrottle"]
