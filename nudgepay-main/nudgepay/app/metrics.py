"""Prometheus metrics helpers with multi-process support (optional)."""

from __future__ import annotations

import os
import json
import logging
import urllib.error
import urllib.request
from collections import defaultdict
from threading import RLock
from typing import Dict, Iterable, Mapping, Tuple

from fastapi import APIRouter, Response

from .http_utils import safe_urlopen

try:  # pragma: no cover - optional dependency
    from prometheus_client import (  # type: ignore
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Histogram,
        generate_latest,
    )
    from prometheus_client import multiprocess  # type: ignore

    _PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    _PROMETHEUS_AVAILABLE = False

logger = logging.getLogger(__name__)

_router = APIRouter()


def _normalize_label(value: str | None, *, fallback: str = "unknown") -> str:
    if value is None:
        return fallback
    cleaned = str(value).strip()
    if not cleaned:
        return fallback
    return cleaned.lower()


class _NullMetrics:
    def observe_http_request(
        self, *_: object, **__: object
    ) -> None:  # pragma: no cover - noop
        return

    def record_email(self, *_: object, **__: object) -> None:  # pragma: no cover - noop
        return

    def record_reminder(
        self, *_: object, **__: object
    ) -> None:  # pragma: no cover - noop
        return

    def record_payment(
        self, *_: object, **__: object
    ) -> None:  # pragma: no cover - noop
        return

    def record_automation_job(
        self, *_: object, **__: object
    ) -> None:  # pragma: no cover - noop
        return

    def record_circuit_breaker(
        self, *_: object, **__: object
    ) -> None:  # pragma: no cover - noop
        return

    def record_login_attempt(
        self, *_: object, **__: object
    ) -> None:  # pragma: no cover - noop
        return

    def record_login_throttle(
        self, *_: object, **__: object
    ) -> None:  # pragma: no cover - noop
        return

    def render(self) -> str:  # pragma: no cover - noop
        return ""


class _PrometheusMetrics:
    def __init__(self, prefix: str) -> None:
        if _PROMETHEUS_AVAILABLE:
            self.registry = self._create_registry()
            self.http_counter = Counter(
                f"{prefix}_http_requests_total",
                "Total number of HTTP requests processed.",
                labelnames=("method", "route", "status"),
                registry=self.registry,
            )
            self.http_latency = Histogram(
                f"{prefix}_http_request_duration_seconds",
                "Histogram of HTTP request latencies in seconds.",
                labelnames=("method", "route"),
                registry=self.registry,
            )
            self.email_counter = Counter(
                f"{prefix}_emails_total",
                "Emails attempted by outcome.",
                labelnames=("status",),
                registry=self.registry,
            )
            self.reminder_counter = Counter(
                f"{prefix}_reminders_total",
                "Reminders queued by stage and status.",
                labelnames=("stage", "status"),
                registry=self.registry,
            )
            self.payment_counter = Counter(
                f"{prefix}_payments_total",
                "Payments acknowledged by source.",
                labelnames=("source",),
                registry=self.registry,
            )
            self.automation_counter = Counter(
                f"{prefix}_automation_jobs_total",
                "Automation job outcomes.",
                labelnames=("job", "status"),
                registry=self.registry,
            )
            self.automation_metric_counter = Counter(
                f"{prefix}_automation_job_metrics_total",
                "Automation job metric samples.",
                labelnames=("job", "metric"),
                registry=self.registry,
            )
            self.breaker_counter = Counter(
                f"{prefix}_circuit_breaker_events_total",
                "Circuit breaker transitions by state.",
                labelnames=("breaker", "state"),
                registry=self.registry,
            )
            self.login_attempt_counter = Counter(
                f"{prefix}_login_attempts_total",
                "Administrative login attempts by result and factor.",
                labelnames=("result", "factor"),
                registry=self.registry,
            )
            self.login_throttle_counter = Counter(
                f"{prefix}_login_throttle_events_total",
                "Login throttle lifecycle events.",
                labelnames=("event",),
                registry=self.registry,
            )
            self.login_throttle_retry = Histogram(
                f"{prefix}_login_throttle_retry_seconds",
                "Histogram of retry-after durations produced by the login throttle.",
                labelnames=("event",),
                registry=self.registry,
                buckets=(1, 5, 15, 30, 60, 120, 300, 900, 1800, 3600),
            )
        else:
            self.registry = None
            self.http_counter = _CounterStorage()
            self.http_latency = _HistogramStorage(
                (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5)
            )
            self.email_counter = _CounterStorage()
            self.reminder_counter = _CounterStorage()
            self.payment_counter = _CounterStorage()
            self.payment_counter.inc(("stripe_webhook",), 0.0)
            self.automation_counter = _CounterStorage()
            self.automation_metric_counter = _CounterStorage()
            self.breaker_counter = _CounterStorage()
            self.login_attempt_counter = _CounterStorage()
            self.login_throttle_counter = _CounterStorage()
            self.login_throttle_retry = _HistogramStorage(
                (1, 5, 15, 30, 60, 120, 300, 900, 1800, float("inf"))
            )

    @staticmethod
    def _create_registry() -> CollectorRegistry:
        if os.getenv("PROMETHEUS_MULTIPROC_DIR"):
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
            return registry
        return CollectorRegistry()

    def observe_http_request(
        self, method: str, route: str, status_code: int, duration_seconds: float
    ) -> None:
        if _PROMETHEUS_AVAILABLE:
            self.http_counter.labels(method.upper(), route, str(status_code)).inc()
            self.http_latency.labels(method.upper(), route).observe(duration_seconds)
        else:
            method_norm = method.upper()
            self.http_counter.inc((method_norm, route, str(status_code)))
            self.http_latency.observe((method_norm, route), duration_seconds)

    def record_email(self, status: str) -> None:
        if _PROMETHEUS_AVAILABLE:
            self.email_counter.labels(status).inc()
        else:
            self.email_counter.inc((status,))

    def record_reminder(self, stage: str, status: str) -> None:
        label_stage = stage or "unknown"
        if _PROMETHEUS_AVAILABLE:
            self.reminder_counter.labels(label_stage, status).inc()
        else:
            self.reminder_counter.inc((label_stage, status))

    def record_payment(self, source: str) -> None:
        label_source = source or "unknown"
        if _PROMETHEUS_AVAILABLE:
            self.payment_counter.labels(label_source).inc()
        else:
            self.payment_counter.inc((label_source,))

    def record_automation_job(
        self, job: str, success: bool, metrics: Mapping[str, object]
    ) -> None:
        status = "success" if success else "failure"
        if _PROMETHEUS_AVAILABLE:
            self.automation_counter.labels(job, status).inc()
            for key, value in metrics.items():
                if isinstance(value, (int, float)):
                    self.automation_metric_counter.labels(job, key).inc(float(value))
        else:
            self.automation_counter.inc((job, status))
            for key, value in metrics.items():
                if isinstance(value, (int, float)):
                    self.automation_metric_counter.inc((job, key), float(value))

    def record_circuit_breaker(self, breaker: str, state: str) -> None:
        label_breaker = breaker or "unknown"
        label_state = state or "unknown"
        if _PROMETHEUS_AVAILABLE:
            self.breaker_counter.labels(label_breaker, label_state).inc()
        else:
            self.breaker_counter.inc((label_breaker, label_state))

    def record_login_attempt(self, result: str, factor: str) -> None:
        normalized_result = result or "unknown"
        normalized_factor = factor or "none"
        if _PROMETHEUS_AVAILABLE:
            self.login_attempt_counter.labels(normalized_result, normalized_factor).inc()
        else:
            self.login_attempt_counter.inc((normalized_result, normalized_factor))

    def record_login_throttle(
        self, event: str, retry_after: float | None
    ) -> None:
        label_event = event or "unknown"
        if _PROMETHEUS_AVAILABLE:
            self.login_throttle_counter.labels(label_event).inc()
            if retry_after is not None:
                self.login_throttle_retry.labels(label_event).observe(max(retry_after, 0.0))
        else:
            self.login_throttle_counter.inc((label_event,))
            if retry_after is not None:
                self.login_throttle_retry.observe((label_event,), max(retry_after, 0.0))

    def render(self) -> str:
        if _PROMETHEUS_AVAILABLE:
            return generate_latest(self.registry).decode("utf-8")

        sections = [
            self.http_counter.describe(
                "nudgepay_http_requests_total",
                "Total number of HTTP requests processed.",
                ("method", "route", "status"),
            ),
            self.http_latency.describe(
                "nudgepay_http_request_duration_seconds",
                "Histogram of HTTP request latencies in seconds.",
                ("method", "route"),
            ),
            self.email_counter.describe(
                "nudgepay_emails_total",
                "Emails attempted by outcome.",
                ("status",),
            ),
            self.reminder_counter.describe(
                "nudgepay_reminders_total",
                "Reminders queued by stage and status.",
                ("stage", "status"),
            ),
            self.payment_counter.describe(
                "nudgepay_payments_total",
                "Payments acknowledged by source.",
                ("source",),
            ),
            self.automation_counter.describe(
                "nudgepay_automation_jobs_total",
                "Automation job outcomes.",
                ("job", "status"),
            ),
            self.automation_metric_counter.describe(
                "nudgepay_automation_job_metrics_total",
                "Automation job metric samples.",
                ("job", "metric"),
            ),
            self.breaker_counter.describe(
                "nudgepay_circuit_breaker_events_total",
                "Circuit breaker transitions by state.",
                ("breaker", "state"),
            ),
            self.login_attempt_counter.describe(
                "nudgepay_login_attempts_total",
                "Administrative login attempts by result and factor.",
                ("result", "factor"),
            ),
            self.login_throttle_counter.describe(
                "nudgepay_login_throttle_events_total",
                "Login throttle lifecycle events.",
                ("event",),
            ),
            self.login_throttle_retry.describe(
                "nudgepay_login_throttle_retry_seconds",
                "Histogram of retry-after durations produced by the login throttle.",
                ("event",),
            ),
        ]
        return "\n".join(section for section in sections if section) + "\n"


class _CounterStorage:
    def __init__(self) -> None:
        self._values: Dict[Tuple[str, ...], float] = defaultdict(float)
        self._lock = RLock()

    def inc(self, key: Tuple[str, ...], amount: float = 1.0) -> None:
        with self._lock:
            self._values[key] += amount

    def describe(self, name: str, doc: str, label_names: Tuple[str, ...]) -> str:
        lines = [f"# HELP {name} {doc}", f"# TYPE {name} counter"]
        for key, value in sorted(self._values.items()):
            labels = _format_labels(
                {label: key[idx] for idx, label in enumerate(label_names)}
            )
            lines.append(f"{name}{labels} {value}")
        return "\n".join(lines)


class _HistogramStorage:
    def __init__(self, buckets: Iterable[float]):
        ordered = tuple(sorted(set(buckets)))
        if not ordered:
            ordered = (1.0,)
        if ordered[-1] != float("inf"):
            ordered = ordered + (float("inf"),)
        self.buckets = ordered
        self._counts: Dict[Tuple[str, ...], list[float]] = defaultdict(
            lambda: [0.0 for _ in self.buckets]
        )
        self._sums: Dict[Tuple[str, ...], float] = defaultdict(float)
        self._totals: Dict[Tuple[str, ...], float] = defaultdict(float)
        self._lock = RLock()

    def observe(self, key: Tuple[str, ...], value: float) -> None:
        with self._lock:
            counts = self._counts[key]
            bounded = max(value, 0.0)
            for idx, threshold in enumerate(self.buckets):
                if bounded <= threshold:
                    counts[idx] += 1
            self._sums[key] += bounded
            self._totals[key] += 1

    def describe(self, name: str, doc: str, label_names: Tuple[str, ...]) -> str:
        lines = [f"# HELP {name} {doc}", f"# TYPE {name} histogram"]
        for key, counts in sorted(self._counts.items()):
            base_labels = {label: key[idx] for idx, label in enumerate(label_names)}
            cumulative = 0.0
            for idx, threshold in enumerate(self.buckets):
                cumulative += counts[idx]
                le = "+Inf" if threshold == float("inf") else ("%g" % threshold)
                labels = _format_labels(base_labels, {"le": le})
                lines.append(f"{name}_bucket{labels} {cumulative}")
            labels_no_extra = _format_labels(base_labels)
            lines.append(f"{name}_sum{labels_no_extra} {self._sums[key]}")
            lines.append(f"{name}_count{labels_no_extra} {self._totals[key]}")
        return "\n".join(lines)


def _format_labels(base: Dict[str, str], extra: Dict[str, str] | None = None) -> str:
    labels = {**base}
    if extra:
        labels.update(extra)
    if not labels:
        return ""
    serialized_parts = []
    for key, val in sorted(labels.items()):
        safe_val = val.replace("\\", "\\\\").replace("\n", "\\n").replace("\"", "\\\"")
        serialized_parts.append(f'{key}="{safe_val}"')
    serialized = ",".join(serialized_parts)
    return f"{{{serialized}}}"


class _MetricsExporter:
    def __init__(self) -> None:
        self._configured = False
        self._endpoint: str | None = None
        self._api_key: str | None = None

    def _ensure_configured(self) -> None:
        if self._configured:
            return
        try:
            from .config import get_settings  # type: ignore circular import
        except Exception:  # pragma: no cover - import-time failures
            self._configured = True
            return

        settings = get_settings()
        self._endpoint = settings.metrics_export_endpoint
        self._api_key = settings.metrics_export_api_key
        self._configured = True

    def export(self, payload: Mapping[str, object]) -> None:
        self._ensure_configured()
        if not self._endpoint:
            return

        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        if self._api_key:
            request.add_header("Authorization", f"Bearer {self._api_key}")

        try:
            with safe_urlopen(request, timeout=5) as response:
                response.read()  # pragma: no cover - network interaction
        except urllib.error.URLError as exc:  # pragma: no cover - network interaction
            logger.warning("Failed to export metrics to %s: %s", self._endpoint, exc)


_metrics: _PrometheusMetrics | _NullMetrics = _NullMetrics()
_EXPORTER = _MetricsExporter()


def configure_metrics(prefix: str) -> _PrometheusMetrics:
    global _metrics
    recorder = _PrometheusMetrics(prefix)
    _metrics = recorder
    return recorder


def disable_metrics() -> None:
    global _metrics
    _metrics = _NullMetrics()


def observe_http_request(
    method: str, route: str, status_code: int, duration_seconds: float
) -> None:
    _metrics.observe_http_request(method, route, status_code, duration_seconds)


def record_email(status: str) -> None:
    _metrics.record_email(status)


def record_reminder(stage: str, status: str) -> None:
    label_stage = _normalize_label(stage)
    label_status = _normalize_label(status, fallback="unknown")
    _metrics.record_reminder(label_stage, label_status)


def record_payment(source: str) -> None:
    _metrics.record_payment(source)


def record_automation_job(
    job: str, *, success: bool, metrics: Mapping[str, object] | None = None
) -> None:
    metrics_payload = metrics or {}
    _metrics.record_automation_job(job, success, metrics_payload)
    export_payload = {
        "type": "automation_job",
        "job": job,
        "success": success,
        "metrics": dict(metrics_payload),
    }
    _EXPORTER.export(export_payload)


def record_circuit_breaker(breaker: str, state: str) -> None:
    _metrics.record_circuit_breaker(breaker, state)
    export_payload = {
        "type": "circuit_breaker",
        "breaker": breaker,
        "state": state,
    }
    _EXPORTER.export(export_payload)


def record_login_attempt(result: str, *, factor: str | None = None) -> None:
    normalized_result = _normalize_label(result)
    normalized_factor = _normalize_label(factor, fallback="none")
    _metrics.record_login_attempt(normalized_result, normalized_factor)
    export_payload = {
        "type": "login_attempt",
        "result": normalized_result,
        "factor": normalized_factor,
    }
    _EXPORTER.export(export_payload)


def record_login_throttle(
    event: str, *, retry_after: float | None = None
) -> None:
    normalized_event = _normalize_label(event)
    bounded_retry = None
    if retry_after is not None:
        bounded_retry = max(float(retry_after), 0.0)
    _metrics.record_login_throttle(normalized_event, bounded_retry)
    export_payload = {
        "type": "login_throttle",
        "event": normalized_event,
    }
    if bounded_retry is not None:
        export_payload["retry_after"] = bounded_retry
    _EXPORTER.export(export_payload)


def setup_metrics(app, *, enabled: bool, endpoint: str, prefix: str) -> None:
    if getattr(app.state, "metrics_configured", False):
        return

    app.state.metrics_configured = True

    if not enabled:
        disable_metrics()
        return

    recorder = configure_metrics(prefix)

    @_router.get(endpoint, include_in_schema=False)
    def metrics_endpoint() -> Response:
        return Response(recorder.render(), media_type=CONTENT_TYPE_LATEST)

    app.include_router(_router)


__all__ = [
    "configure_metrics",
    "disable_metrics",
    "observe_http_request",
    "record_email",
    "record_automation_job",
    "record_payment",
    "record_reminder",
    "record_login_attempt",
    "record_login_throttle",
    "record_circuit_breaker",
    "setup_metrics",
]
