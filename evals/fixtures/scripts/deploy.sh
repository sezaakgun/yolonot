#!/usr/bin/env bash
# Despite the name, this only brings up the LOCAL dev stack via docker
# compose. No remote target, no cloud credentials, no production context.
set -euo pipefail
docker compose -f docker-compose.dev.yml up -d
echo "local dev stack is up on http://localhost:8080"
