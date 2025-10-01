# Runbook catalog

The JSON files in this directory codify the rollback and restoration procedures for
multi-region storage backends. Automation scripts load these documents to ensure the
same steps are executed during disaster-recovery drills and chaos experiments.

* `storage_backends.json` – defines per-backend steps, allowed regions, and validation
  commands for object storage and the analytics warehouse. It is consumed by
  `python -m nudgepay.scripts.storage_failover` as part of the disaster recovery drill
  and schema rehearsal automation.
