# Incident response and disaster recovery drills

## Automated disaster recovery rehearsal

Use the `scripts/disaster_recovery.sh` helper to rehearse full-stack recovery in staging:

1. Trigger a fresh logical backup via `make backup` or your managed database snapshot tooling.
2. Run `scripts/disaster_recovery.sh --restore-latest --storage-backends object_storage,analytics_warehouse --storage-region us-west-2` to provision a scratch database, restore the
   most recent backup, execute `alembic upgrade head`, and validate multi-region storage runbooks.
3. Execute the Terraform plan with `terraform plan -var-file=staging.tfvars` to rehearse region
   failover. The script injects a temporary override for the service discovery endpoint so traffic
   can be flipped between regions without DNS propagation delays.
4. Review the synthetic monitor and canary validation output (returned as JSON) to confirm queue drain, webhook replay, and seeded dataset integrity. The script fails fast when the canary score dips below the configured threshold.
5. Capture metrics from `observability/README.md` dashboards to confirm queue drain and webhook
   replay are successful post-failover.

## Paging and playbooks

* **On-call rotation:** Publish a PagerDuty (or Opsgenie) schedule with 24/7 coverage. Ensure the
  "Payments" escalation policy includes engineering management as the second layer.
* **Severity matrix:**
  * Sev1 – Complete API outage or data loss. Page primary on-call immediately, engage incident
    commander, and open a dedicated chat bridge.
  * Sev2 – Partial degradation (reminders delayed, webhook retries climbing). Page on-call within
    5 minutes and post updates to the status page every 30 minutes.
  * Sev3 – Minor feature regression. Create Jira incident ticket and notify affected customers via
    email within 24 hours.
* **Post-incident:** Run a blameless retrospective within 5 business days. Capture follow-up actions
  in the production readiness backlog and automate verification tests wherever possible.

## Chaos drill cadence

* Monthly chaos game days run via the `run_chaos_game_day` automation job and the `app.chaos.build_dependency_game_day` probes. SMTP outages, Stripe webhook backoff, and payment link throttling are injected alongside storage failover simulations. Surface the impact in Grafana using the DLQ, webhook, and canary dashboards.
* Quarterly region failover rehearsal: execute `scripts/disaster_recovery.sh --region-failover` to
  simulate control-plane loss. Validate Terraform `apply` remains gated behind review before
  proceeding to production.
