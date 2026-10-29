#!/bin/sh
set -e

# Scratch dir for in-flight stream captures before they're encrypted + pushed to R2.
mkdir -p /data/streams

# Postgres (HA): connect through HAProxy, which routes to the current Patroni leader.
# Password comes from a Docker secret; host defaults to the in-overlay HAProxy service.
# NOTE: use an ALPHANUMERIC password (no @ : / # ? chars) — it's embedded in the URL.
# REDIS_SENTINELS / REDIS_MASTER_NAME come from the stack env (non-secret).
if [ -f /run/secrets/sentinel_pg_password ]; then
  PGPW=$(cat /run/secrets/sentinel_pg_password)
  PGHOST="${PGHOST:-haproxy}"
  export DATABASE_URL="postgres://sentinel:${PGPW}@${PGHOST}:5432/sentinel"
fi

exec node /app/server.js
