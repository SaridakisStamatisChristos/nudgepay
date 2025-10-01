"""Redis connection helpers with graceful fallbacks."""

from __future__ import annotations

from functools import lru_cache
from importlib import import_module
from typing import Any

from .config import get_settings


@lru_cache(maxsize=1)
def get_redis() -> Any | None:
    try:
        redis_module = import_module("redis")
    except ImportError:
        return None
    settings = get_settings()
    return redis_module.Redis.from_url(settings.redis_url)


__all__ = ["get_redis"]
