# Horizontal Scaling Playbook

NudgePay supports running multiple API replicas behind a load balancer. This guide outlines the
expectations and required infrastructure when scaling horizontally to meet production traffic.

## Shared services

* **Database** – Use a managed PostgreSQL instance. Configure connection pooling (e.g. pgBouncer)
  and ensure `DATABASE_URL` reflects the pooled endpoint. Migrations are run through
  `scripts/run_migrations.sh` during deployment.
* **Redis** – Required for login throttling, reminder job queueing (RQ) and metrics fan-in. A single
  highly available Redis cluster should be provisioned and referenced via `REDIS_URL`.
* **Object storage/backups** – Ship the output of `scripts/backup.sh` to a durable bucket (S3/GCS)
  on a scheduled basis.

## Application replicas

* Each replica is stateless; sessions are cookie based. Run at least two API pods behind a load
  balancer with sticky sessions disabled.
* Configure health probes to hit `/healthz`. The container image exposes this endpoint and includes
  a Docker healthcheck to surface failures quickly.
* Mount a shared `PROMETHEUS_MULTIPROC_DIR` or scrape per-instance metrics via Prometheus. When the
  multiprocess directory is set, the app automatically enables Prometheus multiprocess collectors.

## Background workers

* Reminder delivery runs in Redis-backed RQ workers. Deploy at least one worker process alongside
  the API. Workers use the same image and can be started with `rq worker nudgepay`.
* Dead-letter tracking is persisted in the `outboundjob` table. Alert when jobs accumulate failures
  beyond expected thresholds.

## Observability and limits

* Metrics are exposed at `/metrics`. Scrape every 15s to power dashboards for request latency,
  reminder delivery status, and payment acknowledgements.
* Define alerts on login throttle saturation, reminder job failures, and webhook signature failures.
* Use the structured audit log (`admin_audit_log` table) to feed SIEM pipelines; export via
  scheduled jobs or change streams.

## Deployment expectations

* Bake the container via the multi-stage `Dockerfile` and deploy with IaC (see `ops/terraform`).
* Run database migrations before flipping traffic to new versions.
* Rotate admin credentials regularly using `python -m app.manage_admins rotate <id>` and revoke
  access for inactive admins.
