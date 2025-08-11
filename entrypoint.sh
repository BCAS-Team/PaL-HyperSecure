#!/usr/bin/env bash
set -euo pipefail

# Load .env if present
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

# Wait for Postgres if DATABASE_URL looks like postgres
if [[ "${DATABASE_URL:-}" == postgresql:* || "${DATABASE_URL:-}" == postgresql://* ]]; then
  echo "Waiting for Postgres to be available..."
  # extract host and port (best-effort)
  HOST=$(echo "$DATABASE_URL" | sed -E 's|.*@([^:/]+).*|\1|' || true)
  PORT=$(echo "$DATABASE_URL" | sed -E 's|.*:([0-9]+)/.*|\1|' || echo 5432)
  if [ -n "$HOST" ]; then
    retries=0
    until nc -z "$HOST" "${PORT:-5432}" >/dev/null 2>&1 || [ $retries -gt 30 ]; do
      echo "Waiting for $HOST:$PORT..."
      sleep 2
      retries=$((retries+1))
    done
    if [ $retries -gt 30 ]; then
      echo "Timed out waiting for Postgres; continuing to attempt startup."
    fi
  fi
fi

# Initialize DB (create tables if missing)
python - <<'PY'
from app.db import init_db
print("Initializing DB (create tables if missing)...")
init_db()
print("DB init complete.")
PY

# Start Gunicorn
exec gunicorn -w 4 -b 0.0.0.0:${PORT:-5000} "app:create_app()"
