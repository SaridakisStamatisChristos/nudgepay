# High-risk operations governance

This document summarizes how NudgePay's high-risk administrative workflows are implemented and how to operate them safely. It aligns with the secrets & identity, operational automation, security validation, and reliability testing initiatives.

## Secrets & identity controls
- **Rotation runbooks & dashboards:** Every credential rotation records a `SecretRotationRunbook` entry containing timing, hook fan-out counts, and deep links to the authoritative runbook and Grafana dashboards. Rotations are written via `app.runbooks.record_rotation_run`, and history is visible through the admin reporting views.
- **Delegated approvals:** Requests for privileged actions (e.g., webhook signing rotation, payout overrides) create `DelegatedApproval` records with state transitions for request, approval, rejection, and expiry. The approval lifecycle is exposed through FastAPI endpoints (`/admin/approvals/*`) implemented in `app.approvals` and `app.main`.
- **Scoped service tokens:** Automation clients use short-lived `ServiceToken` credentials with scope restrictions (resource, verb, environment). These tokens are managed through `app.service_tokens` and validated by `app.high_risk` guards before allowing critical operations.

## Operational automation ledger
- **Deployment records:** The deployment CLI (`scripts/deployment_ledger.py`) and disaster-recovery drill script (`scripts/disaster_recovery.sh`) emit `DeploymentRecord` events that capture build SHA, migration status, synthetic monitor verdicts, and rollback outcomes. Ledger persistence lives in `app.deployments`.
- **Automation execution metadata:** Background jobs write `AutomationExecutionRecord` entries through `app.automation` using the shared `app.ledger` helpers, capturing job identifiers, runtime metadata, success/failure, and correlation IDs.
- **Auditable storage:** Ledger tables use JSON payloads for evidence retention, enabling auditors to trace who performed each action and the resulting state changes.
- **Schema rehearsal evidence:** Weekly `run_schema_rehearsal` and `run_environment_seed` jobs publish downgrade/backfill results and validation scores, providing auditors with canonical dataset proofs for each environment. 【F:nudgepay/app/automation.py†L1-L575】
- **Runbook catalog:** Multi-region storage runbooks are codified in `ops/runbooks/storage_backends.json`. The `scripts/storage_failover.py` helper and disaster recovery automation use the catalog to document every object storage and analytics warehouse failover rehearsal. 【F:nudgepay/ops/runbooks/storage_backends.json†L1-L25】【F:nudgepay/scripts/storage_failover.py†L1-L58】

## Security validation enhancements
- **Webhook incident pipeline:** Anomalous webhook activity (signature failures, replays, circuit-breaker trips) triggers `IncidentEvent` creation via `app.incidents`. Alerts fan out to PagerDuty and Slack using the dispatchers in `app.automation`.
- **Chaos drills:** The chaos module (`app.chaos`) now includes webhook replay/backoff scenarios, upstream dependency degradations, and payment link throttling that validate retry semantics and incident fan-out under failure conditions. Scheduled automation runs the full game day bundle and records outcomes in the ledger. 【F:nudgepay/app/chaos.py†L1-L168】【F:nudgepay/app/automation.py†L1-L575】

## Reliability testing program
- **Synthetic monitor gating:** Restore drills invoke `scripts/synthetic_monitors.py` before allowing rollbacks or canary promotions. Failed monitors block progression and emit ledger entries.
- **Soak tests:** Long-running reliability runs execute through `scripts/soak_test.py`, shipping latency drift metrics to the observability stack. Results feed into canary gate evaluation handled in `app.deployments`.
- **Scheduled restore exercises:** Disaster-recovery automation performs scheduled restore rehearsals, persisting execution metadata, storage failover results, synthetic monitor verdicts, and canary validation scores so release managers can audit gating decisions. 【F:nudgepay/scripts/disaster_recovery.sh†L1-L192】
- **Synthetic data canary:** `scripts/canary_score.py` enforces seeded dataset fidelity as part of canary promotions, complementing the synthetic monitor gates. 【F:nudgepay/scripts/canary_score.py†L1-L33】

## Evidence and auditing
To review historical evidence, query the ledger tables through the admin dashboard or use the CLI utilities that wrap SQLModel sessions. Each record includes timestamps, request/approval actors, payloads, and external links for dashboards or runbooks. Combined, these controls provide dual authorization, scoped automation credentials, immutable history, and continuous testing coverage for high-risk operations.
