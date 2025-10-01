# Test Suite Rationale

The upstream project shipped an extensive end-to-end suite that exercised the
FastAPI application, background workers, and managed secret integrations. That
set of tests assumed access to the private `app` package along with Postgres,
Redis, Stripe webhooks, and other external services. Running it in this kata
environment would require provisioning a large amount of infrastructure and
vendoring third-party credentials, which is impractical for a lightweight
exercise.

Instead we focus the automated checks on the highest-leverage behaviours that
*are* available locally:

* Configuration validation in `app.config.Settings`, ensuring production-grade
  deployments reject insecure defaults and accept fully managed inputs.
* Managed secret helpers in `app.secret_manager`, verifying that teams relying
  on fallback providers still receive structured metadata.
* Utility modules such as the HTTPX client sentinel, timestamp signer, and API
  fuzzing harness.

These deterministic tests give quick feedback in CI without relying on network
access or cloud credentials, while still covering the invariants that keep
NudgePay secure when deployed for real customers.
