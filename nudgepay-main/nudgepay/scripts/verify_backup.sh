#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <backup-file>" >&2
  exit 1
fi

backup="$1"
if [[ ! -f "${backup}" ]]; then
  echo "Backup file ${backup} not found" >&2
  exit 1
fi

echo "Verifying ${backup}"
case "${backup}" in
  *.db|*.sqlite)
    if ! command -v sqlite3 >/dev/null 2>&1; then
      echo "sqlite3 command is required to validate sqlite backups" >&2
      exit 1
    fi
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "${tmp_dir}"' EXIT
    cp "${backup}" "${tmp_dir}/restore.db"
    result="$(sqlite3 "${tmp_dir}/restore.db" 'PRAGMA integrity_check;')"
    if [[ "${result}" != "ok" ]]; then
      echo "Integrity check failed: ${result}" >&2
      exit 1
    fi
    ;;
  *.sql)
    head_line="$(head -n 1 "${backup}" | tr -d '\r')"
    if [[ -z "${head_line}" ]]; then
      echo "SQL dump appears to be empty" >&2
      exit 1
    fi
    if [[ "${head_line}" == *"PostgreSQL database dump"* ]]; then
      if command -v pg_restore >/dev/null 2>&1; then
        pg_restore --list "${backup}" >/dev/null
      else
        echo "pg_restore not found; validated header only" >&2
      fi
    elif [[ "${head_line}" == *"MySQL dump"* ]]; then
      python3 - <<'PY'
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8", errors="ignore") as fh:
    found_create = any(line.lower().startswith("create table") for line in fh)
if not found_create:
    raise SystemExit("mysqldump did not contain CREATE TABLE statements")
PY
      "${backup}"
    fi
    ;;
  *)
    echo "Unsupported backup format for ${backup}" >&2
    exit 1
    ;;
 esac

sha256sum "${backup}" | awk '{print "sha256=" $1}'
echo "Verification completed successfully"
