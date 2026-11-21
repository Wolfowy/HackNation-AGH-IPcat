#!/bin/sh
# Runs once on an empty data directory. Creates the read-only role used by Grafana when GRAFANA_DB_PASSWORD is set.
# Only analysis-relevant schemas are readable; identity (password hashes), infra (Data Protection keys, audit),
# integrations (protected API keys) and wolverine stay private. Schemas are pre-created so default privileges apply
# to the tables the server's migrations create later.
set -eu

if [ -z "${GRAFANA_DB_PASSWORD:-}" ]; then
  echo "GRAFANA_DB_PASSWORD not set: skipping read-only Grafana role."
  exit 0
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v ro_password="$GRAFANA_DB_PASSWORD" -v db="$POSTGRES_DB" <<'EOSQL'
CREATE ROLE grafana_ro LOGIN PASSWORD :'ro_password';
GRANT CONNECT ON DATABASE :"db" TO grafana_ro;
DO $$
DECLARE s text;
BEGIN
  FOREACH s IN ARRAY ARRAY['agents','networks','scanning','scheduling','workflows','signatures','discovery','analytics'] LOOP
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', s);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO grafana_ro', s);
    EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO grafana_ro', s);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO grafana_ro', s);
  END LOOP;
END $$;
EOSQL
