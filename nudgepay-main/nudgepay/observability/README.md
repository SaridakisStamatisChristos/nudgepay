# Observability runbook

## Metrics

* Scrape `/metrics` from each API pod with Prometheus. Key series:
  * `nudgepay_http_request_duration_seconds` – latency SLOs.
  * `nudgepay_reminders_total` – reminder delivery success/failure counts.
  * `nudgepay_payments_total` – webhook acknowledgements.
* Configure Grafana dashboards to visualise login throttling events, reminder backlog, webhook
  retries, and the new reminder DLQ snapshot (`reminder_dashboard_snapshot`). Trend queued vs.
  retryable jobs, surface oldest failure age, and annotate chaos drills (SMTP/Stripe) so responders
  can differentiate experiments from incidents. Include histograms for p50/p95 request latency and
  queue processing delay.
* Secret rotation history is exported via the `secret_rotation_runbook` table. Surface this in Grafana
  so auditors can follow links to runbooks/dashboards for each rotation alongside hook counts and
  metadata. 【F:nudgepay/app/runbooks.py†L1-L63】【F:nudgepay/app/models.py†L1-L200】

## Logging

* Application logs use structured JSON (see `logging_utils.py`). Ship to a centralized platform
  (CloudWatch, Stackdriver, Datadog, etc.). Retain for 30 days minimum for auditing.
* Audit events are stored in the `admin_audit_log` table. Stream to your SIEM or export daily to
  immutable storage.

## Alerts

Suggested alerts with initial thresholds:

| Condition | Threshold | Action |
|-----------|-----------|--------|
| Healthcheck failures | >3 consecutive probes | Page on-call, recycle pod |
| Login throttle TTL | TTL > 0 for > 5 minutes | Investigate brute-force attack |
| Reminder job failures | `outboundjob` failed > 5 in 10m or DLQ retryable > 10 | Triage SMTP/Stripe connectivity |
| DLQ staleness | `reminder_dashboard_snapshot_oldest_failure_age_seconds` > 1800 | Trigger reprocessor job |
| Stripe webhook duplicates | `processedwebhook` delta > 0 | Investigate payment provider |

## Traces

OpenTelemetry instrumentation can be added by wrapping the ASGI app with `opentelemetry-instrument`.
Propagate request IDs via the existing `RequestContextMiddleware` header. Capture chaos experiment
annotations as span events to provide context when SMTP/Stripe outages are injected.
