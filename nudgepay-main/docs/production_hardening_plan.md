# Production hardening roadmap

This roadmap outlines the concrete steps required to close the remaining gaps highlighted in the production readiness report. The plan is organized across four workstreams so the platform can reach a 99% readiness bar with auditable automation and testing.

## 1. Secrets & identity automation

### 1.1 Unified secrets rotation service
- ✅ Build a rotation orchestrator that can target AWS Secrets Manager, HashiCorp Vault, and Google Secret Manager via pluggable provider adapters. Implemented via the `app.secret_rotation` helpers layered on top of the multi-provider `app.secret_manager` resolvers.
- ✅ Store rotation policies (frequency, warm-up windows, post-rotation health checks) in code alongside infrastructure definitions via `app.secret_rotation.register_rotation_policy` so staged rollouts and warm-up windows are declared in code.
- ✅ After each rotation, push invalidation events onto Redis and the application task queue so in-memory caches and background workers refresh the new credentials without restarts. Redis fan-out and RQ fan-out are now handled by `app.secret_rotation.schedule_rotations` and `app.tasks.enqueue_secret_invalidation`.
- ✅ Capture rotation runbooks, last-run timestamps, and dashboard deep-links directly from the rotation helpers so auditors can trace every change. Runbook entries are now persisted via `app.runbooks.record_rotation_run` when `app.secret_rotation.schedule_rotations` executes.

### 1.2 Identity federation & lifecycle
- ✅ Integrate SSO with SAML/OIDC providers and map asserted roles to the existing RBAC primitives.
- ✅ Provision SCIM endpoints so identity platforms (Okta, Azure AD) can manage admin lifecycle, disabling accounts on offboarding automatically.
- ✅ Require WebAuthn/FIDO2 hardware keys for break-glass admin access and enforce per-session reauthentication for sensitive flows (payouts, webhook settings).
- ✅ Emit audit events for all SCIM/SSO changes and feed them into SIEM tooling with anomaly detection on privilege escalations.
- ✅ Introduce delegated approvals and scoped service tokens for high-risk admin flows. Approval lifecycles are codified in `app.approvals`, service tokens in `app.service_tokens`, and surfaced through new FastAPI endpoints in `app.main` for request/approval/revocation.

## 2. Operational automation

### 2.1 Background task scheduling
- ✅ Deploy the reminder DLQ reprocessor and backup verification helpers as scheduled jobs in the existing workflow engine (e.g., GitHub Actions cron or ECS scheduled tasks). The new `app.automation` module centralizes job execution metadata and cron expressions for both tasks.
- ✅ Wire alerting into PagerDuty/Slack when DLQ depth exceeds thresholds, when verification scripts detect checksum drift, or if jobs fail consecutively using the centralized alert channel registry in `app.automation`.
- ✅ Record run history and metrics (processed messages, bytes validated) in Prometheus to surface dashboards and SLO burn rates.

### 2.2 Deployment orchestration
- ✅ Implement pipeline stages that lint/test, generate Terraform plans, and require human approval before apply in production. The CI workflow now gates Terraform `apply` behind a manual dispatch after the quality, test, and plan stages succeed.
- ✅ Automate database migrations via the existing `run_migrations.sh`, executing against staging first, then production with automatic rollback if health checks fail.
- ✅ Introduce canary deployments using blue/green or rolling strategies with traffic weighting, coupled with automated rollback drills triggered by synthetic monitor degradation.
- ✅ Store deployment metadata (build SHA, migration status, rollback gate) in an auditable ledger. The automation stack writes executions through `app.ledger`, while `app.deployments` and `scripts/deployment_ledger.py` capture start/finish metadata invoked by the updated `scripts/disaster_recovery.sh` drill.

### 2.3 Schema lifecycle & environment seeding
- ✅ Codified downgrade/backfill rehearsals via `app.schema_lifecycle` and the `scripts/schema_rehearsal.py` CLI, executing downgrade → upgrade cycles before reseeding.
- ✅ Added deterministic seed datasets in `app.seeding` with `scripts/seed_environment.py`, ensuring new environments mirror production schemas without manual intervention.
- ✅ Extended automation jobs with `run_environment_seed` and `run_schema_rehearsal` so rehearsals run on a weekly cadence with alerting and ledger capture. 【F:nudgepay/app/automation.py†L1-L575】【F:nudgepay/app/seeding.py†L1-L217】【F:nudgepay/scripts/schema_rehearsal.py†L1-L40】

## 3. Security validation

### 3.1 CI expansion
- ✅ Extend the CI matrix to run dependency and container vulnerability scans for Python, Terraform, and container images on both pull requests and a nightly cadence. Pip-audit, Bandit, Trivy, tfsec, Checkov, and license checks now execute on pushes/PRs with an overnight scheduled run.
- ✅ Include IaC scanning (tfsec, Checkov) and license compliance checks, blocking merges on critical findings.

### 3.2 Webhook and service hardening
- ✅ Rotate webhook signing secrets on a defined cadence, publishing overlapping keys and sunsetting old ones after successful validation. The `app.automation.run_webhook_secret_rotation` job now schedules rotations and retires expired secrets automatically.
- ✅ Require mutual TLS for cron and automation endpoints so only trusted jobs with client certificates can invoke them.
- ✅ Add runtime assertions that reject unsigned or expired webhook requests with incident tooling fan-out. `app.main.stripe_webhook` now reports anomalies to `app.incidents`, which dispatches alerts via `app.automation.dispatch_alert` for PagerDuty/Slack ingestion.

## 4. Reliability testing

### 4.1 Test coverage
- ✅ Introduce k6 load tests that simulate peak reminder traffic and webhook bursts, publishing latency/error budgets as SLIs.
- ✅ Layer in fuzz testing for API payloads and reminder scheduling inputs to detect validation or serialization regressions.
- ✅ Schedule authenticated OWASP ZAP scans against staging to catch regression in auth/session defenses.
- ✅ Add long-running soak tests driven by `scripts/soak_test.py` so extended runs surface latency drift before promotion.

### 4.2 Synthetic observability
- ✅ Stand up synthetic monitors that run end-to-end payment flows, webhook receipt, and admin logins from multiple regions.
- ✅ Feed synthetic metrics into alerting so SLO breaches trigger automated rollback evaluation.
- ✅ Extend restore drills so synthetic monitors gate rollback decisions. `scripts/disaster_recovery.sh` now records deployment ledger entries and blocks completion if `scripts/synthetic_monitors.py` detects regressions.

### 4.3 Chaos & canary reinforcement
- ✅ Added upstream dependency degradation probes (`app.chaos.build_dependency_game_day`) covering SMTP, Stripe webhook backoff, and payment link throttling.
- ✅ Enhanced disaster recovery automation to execute storage failover rehearsals, synthetic canary validation, and chaos experiments with structured metadata. 【F:nudgepay/app/chaos.py†L1-L168】【F:nudgepay/scripts/disaster_recovery.sh†L1-L192】【F:nudgepay/scripts/storage_failover.py†L1-L58】【F:nudgepay/scripts/canary_score.py†L1-L33】

## Milestones & ownership

| Milestone | Scope | Primary owner | Target completion |
|-----------|-------|---------------|-------------------|
| M1 | Secrets rotation orchestrator & cache invalidation | Platform team | Month 1 |
| M2 | SSO/SCIM rollout with hardware-backed auth | Security engineering | Month 2 |
| M3 | DLQ/backups scheduling with alerting & deployment pipeline automation | DevOps | Month 2 |
| M4 | Expanded CI security coverage & webhook mTLS | Security engineering | Month 3 |
| M5 | Load/fuzz/ZAP testing & synthetic monitors | Reliability engineering | Month 3 |
| M6 | Schema rehearsal automation, seeded canary validation, and dependency chaos drills | Platform team | Month 3 |

The completion of these milestones will operationalize the recommendations from the production readiness assessment and provide measurable evidence that the service meets a 99% readiness standard.
