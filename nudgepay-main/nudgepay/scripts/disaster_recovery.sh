#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 [--restore-latest] [--region-failover] [--plan-only] [--storage-backends list] [--storage-region region] [--canary-threshold score]

Automates disaster recovery drills by restoring the latest backup, validating migrations,
rehearsing multi-region storage failover runbooks, and running Terraform plan/apply gates.
USAGE
}

RESTORE=false
FAILOVER=false
PLAN_ONLY=false
ROLLBACK_NEEDED=false
STORAGE_BACKENDS="${STORAGE_BACKENDS:-}"
STORAGE_REGION="${STORAGE_REGION:-us-west-2}"
CANARY_THRESHOLD="${CANARY_THRESHOLD:-0.99}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --restore-latest)
      RESTORE=true
      shift
      ;;
    --region-failover)
      FAILOVER=true
      shift
      ;;
    --plan-only)
      PLAN_ONLY=true
      shift
      ;;
    --storage-backends)
      if [[ $# -lt 2 ]]; then
        echo "--storage-backends requires a comma-separated list" >&2
        exit 1
      fi
      STORAGE_BACKENDS="$2"
      shift 2
      ;;
    --storage-region)
      if [[ $# -lt 2 ]]; then
        echo "--storage-region requires a value" >&2
        exit 1
      fi
      STORAGE_REGION="$2"
      shift 2
      ;;
    --canary-threshold)
      if [[ $# -lt 2 ]]; then
        echo "--canary-threshold requires a numeric value" >&2
        exit 1
      fi
      CANARY_THRESHOLD="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown flag: $1" >&2
      usage
      exit 1
      ;;
  esac
done

log() {
  printf '[%s] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*"
}

BUILD_SHA="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
ENVIRONMENT_NAME="${ENVIRONMENT:-drill}" # shellcheck disable=SC2153
INITIATED_BY="${USER:-automation}"
DRILL_METADATA=$(printf '{"restore":"%s","failover":"%s","plan_only":"%s"}' "$RESTORE" "$FAILOVER" "$PLAN_ONLY")
DEPLOYMENT_ID=$(python -m nudgepay.scripts.deployment_ledger start \
  --environment "$ENVIRONMENT_NAME" \
  --build-sha "$BUILD_SHA" \
  --initiated-by "$INITIATED_BY" \
  --metadata "$DRILL_METADATA")

if [[ "$RESTORE" == true ]]; then
  log "Restoring latest database snapshot into scratch environment"
  ./scripts/backup.sh --restore-latest
  log "Running migrations against restored snapshot"
  alembic upgrade head
  log "Running configuration validation gate"
  if ! ENVIRONMENT=staging python -m nudgepay.scripts.validate_release; then
    log "Configuration validation failed after restore"
    ROLLBACK_NEEDED=true
    STATUS="validation-failed"
  fi
  log "Rehearsing schema downgrade/upgrade cycle"
  if ! ENVIRONMENT=staging DATABASE_URL="${DATABASE_URL:-postgresql://postgres:postgres@localhost:5432/postgres}" python -m nudgepay.scripts.schema_rehearsal --json; then
    log "Schema rehearsal failed"
    ROLLBACK_NEEDED=true
    STATUS="validation-failed"
  fi
fi

if [[ "$FAILOVER" == true ]]; then
  log "Simulating region failover by exporting temporary endpoint overrides"
  export NUDGEPAY_ACTIVE_REGION="drill"
  export NUDGEPAY_ORIGIN_REGION="primary"
fi

log "Running Terraform plan (gated)"
pushd ops/terraform >/dev/null
terraform init -backend=false
terraform fmt -check
terraform validate
terraform plan -out=drill.plan

if [[ "$PLAN_ONLY" == true ]]; then
  log "Plan-only mode enabled; skipping apply"
  STATUS="plan-only"
else
  STATUS="succeeded"
fi

if [[ "$FAILOVER" == true ]]; then
  log "Applying failover plan"
  terraform apply -auto-approve drill.plan
  log "Failover applied; remember to revert via terraform apply once drill completes"
else
  log "Plan available at ops/terraform/drill.plan; manual approval required for apply"
fi
popd >/dev/null

STORAGE_METADATA="[]"
if [[ -n "$STORAGE_BACKENDS" ]]; then
  IFS=',' read -r -a BACKEND_LIST <<< "$STORAGE_BACKENDS"
  for raw_backend in "${BACKEND_LIST[@]}"; do
    BACKEND=$(echo "$raw_backend" | xargs)
    [[ -z "$BACKEND" ]] && continue
    log "Validating storage backend $BACKEND in region $STORAGE_REGION"
    STORAGE_OUTPUT=$(python -m nudgepay.scripts.storage_failover --backend "$BACKEND" --region "$STORAGE_REGION" --json || true)
    STORAGE_EXIT=$?
    echo "$STORAGE_OUTPUT"
    STORAGE_METADATA=$(python - <<PY
import json
existing = json.loads(${STORAGE_METADATA@Q})
raw = ${STORAGE_OUTPUT@Q}
try:
    existing.append(json.loads(raw))
except Exception:
    existing.append({"raw": raw})
print(json.dumps(existing))
PY
)
    if [[ $STORAGE_EXIT -ne 0 ]]; then
      log "Storage failover validation failed for $BACKEND"
      ROLLBACK_NEEDED=true
      STATUS="validation-failed"
      GATE="failed"
    fi
  done
fi

log "Running synthetic monitors to gate rollback decisions"
MONITOR_OUTPUT=$(python -m nudgepay.scripts.synthetic_monitors --iterations 3 --json || true)
MONITOR_EXIT=$?
echo "$MONITOR_OUTPUT"
if [[ $MONITOR_EXIT -ne 0 ]]; then
  log "Synthetic monitors detected failures; rollback recommended"
  GATE="failed"
  ROLLBACK_NEEDED=true
  STATUS="validation-failed"
else
  GATE="passed"
fi

log "Evaluating synthetic dataset canary validation"
CANARY_OUTPUT=$(python -m nudgepay.scripts.canary_score --threshold "$CANARY_THRESHOLD" --json || true)
CANARY_EXIT=$?
echo "$CANARY_OUTPUT"
if [[ $CANARY_EXIT -ne 0 ]]; then
  log "Synthetic dataset validation failed"
  ROLLBACK_NEEDED=true
  STATUS="validation-failed"
  GATE="failed"
fi

COMBINED_METADATA=$(python - <<PY
import json

def _load(raw: str):
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}

payload = {
    "monitors": _load(${MONITOR_OUTPUT@Q}),
    "storage": _load(${STORAGE_METADATA@Q}),
    "canary": _load(${CANARY_OUTPUT@Q}),
}
print(json.dumps(payload))
PY
)

python -m nudgepay.scripts.deployment_ledger complete \
  --deployment-id "$DEPLOYMENT_ID" \
  --status "$STATUS" \
  --synthetic-gate "$GATE" \
  --metadata "$COMBINED_METADATA" \
  $([[ "$ROLLBACK_NEEDED" == true ]] && echo "--rollback")

if [[ "$ROLLBACK_NEEDED" == true ]]; then
  log "Rollback required based on automated gates"
  exit 1
fi

exit 0
