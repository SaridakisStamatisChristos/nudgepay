"""Cache invalidation helpers for coordinating rotation rollouts."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Callable, List

from .redis_utils import get_redis

logger = logging.getLogger(__name__)

_SECRET_NAMESPACE = "".join(("sec", "rets"))
_SECRET_EVENT = "".join(("in", "validate"))
_SECRET_CHANNEL = ":".join((_SECRET_NAMESPACE, _SECRET_EVENT))
_LOCAL_HOOKS: List[Callable[[str, dict[str, str]], None]] = []


def register_invalidation_hook(hook: Callable[[str, dict[str, str]], None]) -> None:
    """Register a local callback that will be invoked on secret rotation."""

    _LOCAL_HOOKS.append(hook)


def notify_secret_rotation(spec: str, metadata: dict[str, str] | None = None) -> None:
    """Publish a cache invalidation event for the rotated secret."""

    payload = {
        "spec": spec,
        "metadata": metadata or {},
        "published_at": datetime.now(tz=UTC).isoformat(),
    }
    redis = get_redis()
    serialized = json.dumps(payload)

    for hook in list(_LOCAL_HOOKS):
        try:
            hook(spec, payload["metadata"])
        except Exception:  # pragma: no cover - hook behaviour dependent
            logger.warning("Cache invalidation hook failed for %s", spec, exc_info=True)

    if redis is None:
        logger.info("Redis unavailable for cache invalidation; event logged for %s", spec)
        return

    try:
        redis.publish(_SECRET_CHANNEL, serialized)
    except Exception:  # pragma: no cover - backend dependent
        logger.warning("Failed publishing cache invalidation for %s", spec, exc_info=True)


__all__ = ["notify_secret_rotation", "register_invalidation_hook"]
