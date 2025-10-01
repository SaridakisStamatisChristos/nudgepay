"""Logging utilities for structured, contextual logs."""

from __future__ import annotations

import json
import logging
from contextvars import ContextVar
from datetime import datetime, timezone
from logging.config import dictConfig
from typing import Any, Dict

_RESERVED_RECORD_KEYS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "message",
    "request_id",
}


request_id_ctx_var: ContextVar[str] = ContextVar("request_id", default="-")


class RequestContextFilter(logging.Filter):
    """Inject the active request id into log records."""

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - trivial
        record.request_id = request_id_ctx_var.get("-")
        return True


class JsonFormatter(logging.Formatter):
    """Format log records as JSON for structured ingestion."""

    def format(self, record: logging.LogRecord) -> str:  # pragma: no cover - exercised indirectly
        log_payload: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }

        if record.exc_info:
            log_payload["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            log_payload["stack_info"] = self.formatStack(record.stack_info)

        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_KEYS:
                continue
            log_payload.setdefault(key, value)

        return json.dumps(log_payload, default=_json_default)


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):  # pragma: no cover - safeguard
        return value.isoformat()
    return str(value)


def setup_logging(level: str = "INFO") -> None:
    """Configure application-wide structured logging."""

    logging.captureWarnings(True)
    dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {"json": {"()": "app.logging_utils.JsonFormatter"}},
            "filters": {"context": {"()": "app.logging_utils.RequestContextFilter"}},
            "handlers": {
                "default": {
                    "class": "logging.StreamHandler",
                    "filters": ["context"],
                    "formatter": "json",
                    "stream": "ext://sys.stdout",
                }
            },
            "root": {"handlers": ["default"], "level": level.upper()},
        }
    )


def get_request_id(default: str = "-") -> str:
    """Return the current request id from context."""

    return request_id_ctx_var.get(default)


__all__ = [
    "JsonFormatter",
    "RequestContextFilter",
    "get_request_id",
    "request_id_ctx_var",
    "setup_logging",
]

