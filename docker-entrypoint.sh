#!/bin/sh
set -eu

is_truthy() {
  value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

run_migrations() {
  attempts="${UMAI_DB_MIGRATION_MAX_ATTEMPTS:-30}"
  sleep_seconds="${UMAI_DB_MIGRATION_SLEEP_SECONDS:-2}"
  attempt=1

  while [ "$attempt" -le "$attempts" ]; do
    if alembic upgrade head; then
      return 0
    fi

    if [ "$attempt" -eq "$attempts" ]; then
      echo "Database migrations failed after ${attempts} attempts." >&2
      return 1
    fi

    echo "Database migration attempt ${attempt}/${attempts} failed; retrying in ${sleep_seconds}s." >&2
    sleep "$sleep_seconds"
    attempt=$((attempt + 1))
  done
}

if [ -n "${UMAI_DATABASE_URL:-}" ] && is_truthy "${UMAI_RUN_DB_MIGRATIONS:-true}"; then
  run_migrations
fi

if [ -n "${UMAI_DATABASE_URL:-}" ] && is_truthy "${UMAI_RUN_SEED:-false}"; then
  python seed.py
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8080
