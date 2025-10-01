# NudgePay – get paid faster
Micro app that politely nudges late invoices and drops a Stripe Payment Link in every reminder.

## Quick start (Docker)
```bash
cp .env.example .env
docker-compose up --build
# App: http://localhost:8000   MailHog (email): http://localhost:8025
```

## Quick start (Python)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=sqlite:///./nudgpay.db
uvicorn app.main:app --reload
```

## Login

Set `ADMIN_EMAIL` and `ADMIN_PASSWORD_HASH` in `.env`. Generate a hash:

```bash
make hash
```

## Stripe setup

* Set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`.
* Local dev webhooks:

```bash
stripe listen --forward-to http://localhost:8000/webhooks/stripe
```

## Cron (reminders)

POST daily with header `X-CRON-KEY: $CRON_SECRET`:

```bash
curl -X POST "$BASE_URL/internal/run-reminders" -H "X-CRON-KEY: $CRON_SECRET"
```

## Environment configuration

| Environment | Required variables | Managed secret guidance |
|-------------|-------------------|--------------------------|
| Local / development | `DATABASE_URL` (may be SQLite), `SESSION_SECRET`, `CRON_SECRET`, `CRON_HMAC_SECRET`, `CSRF_SECRET` | Plain environment values are acceptable for local testing. Rotate the defaults in `.env.example` before sharing screenshots or recordings. |
| Test / CI | `ENVIRONMENT=test`, managed secrets via `env://` fallbacks for `SESSION_SECRET`, `CRON_SECRET`, `CRON_HMAC_SECRET`, `SERVICE_TOKEN_PEPPER`, `ADMIN_PASSWORD_HASH`, `ADMIN_TOTP_SECRET`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | CI runs `make ci` and `scripts/validate_release.py`, which require every sensitive setting to reference a managed provider (`aws-secrets://`, `vault://`, `gcp-sm://`, or `env://`). |
| Staging / production | `ENVIRONMENT=staging|production`, Postgres `DATABASE_URL`, HTTPS `BASE_URL`, `SESSION_HTTPS_ONLY=true`, managed secret refs for all sensitive settings, alert transports (`AUTOMATION_PAGERDUTY_SERVICE`, `AUTOMATION_PAGERDUTY_ROUTING_KEY_REF`, `AUTOMATION_SLACK_CHANNEL`, `AUTOMATION_SLACK_WEBHOOK_REF`, `AUTOMATION_EMAIL_RECIPIENTS`) | Managed secrets must come from AWS Secrets Manager, HashiCorp Vault, or GCP Secret Manager. Deployment automation fails when defaults are detected. |

`Settings.ensure_valid(strict=True)` blocks short secrets, SQLite URLs, and non-HTTPS cookies in staging and production. The GitHub Actions workflow (`.github/workflows/ci.yml`) exports managed secret references and runs `scripts/validate_release.py` plus schema rehearsal gates before promotion.

## Deploy

### Fly.io

```bash
flyctl launch --no-deploy
flyctl volumes create data --size 1 --region ams
flyctl secrets set \
  SESSION_SECRET_REF=aws-secrets://prod/nudgepay/session \
  CRON_SECRET_REF=aws-secrets://prod/nudgepay/cron \
  CRON_HMAC_SECRET_REF=aws-secrets://prod/nudgepay/cron-hmac \
  SERVICE_TOKEN_PEPPER_REF=aws-secrets://prod/nudgepay/service-token-pepper \
  ADMIN_PASSWORD_HASH_REF=aws-secrets://prod/nudgepay/admin-password \
  ADMIN_TOTP_SECRET_REF=aws-secrets://prod/nudgepay/admin-totp \
  STRIPE_SECRET_KEY_REF=aws-secrets://prod/nudgepay/stripe-secret \
  STRIPE_WEBHOOK_SECRET_REF=aws-secrets://prod/nudgepay/stripe-webhook
make deploy-fly
```

### Render

Use `render.yaml` and configure managed secret references in the dashboard instead of raw values.

## Security notes

* Set `SESSION_HTTPS_ONLY=true` in production.
* Rotate all secrets before launch; never log PII or secrets.
* Payment data never touches NudgePay (Stripe-hosted).

## Testing

```bash
make test
```

> **Note**
>
> Continuous integration focuses on deterministic checks that validate
> configuration safety, managed secret integrations, and supporting utilities.
> The rationale for this lighter-weight suite lives in
> [`docs/test-suite-rationale.md`](../docs/test-suite-rationale.md).

### Test client configuration

The application sets `SESSION_HTTPS_ONLY=true` even in tests so secure cookies are issued.
When instantiating FastAPI's `TestClient`, always provide an HTTPS base URL (for example,
`TestClient(app, base_url="https://testserver")`) so authentication sessions persist across
requests.
