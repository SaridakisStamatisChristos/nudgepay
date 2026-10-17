#!/usr/bin/env bash
set -euo pipefail

timestamp="$(date -u +%Y%m%d_%H%M%S)"
backup_dir="${BACKUP_DIR:-backups}"
mkdir -p "${backup_dir}"

if [[ -n "${DATABASE_URL:-}" ]]; then
  url="${DATABASE_URL}"
else
  echo "DATABASE_URL must be set" >&2
  exit 1
fi

case "${url}" in
  postgresql*|postgresql+psycopg2*)
    pg_dump "${url}" > "${backup_dir}/nudgepay_${timestamp}.sql"
    ;;
  mysql*)
    mysqldump "${url}" > "${backup_dir}/nudgepay_${timestamp}.sql"
    ;;
  sqlite*)
    sqlite_file="${url#sqlite:///}"
    cp "${sqlite_file}" "${backup_dir}/nudgepay_${timestamp}.db"
    ;;
  *)
    echo "Unsupported database URL: ${url}" >&2
    exit 1
    ;;
esac

echo "Backup created at ${backup_dir}"
