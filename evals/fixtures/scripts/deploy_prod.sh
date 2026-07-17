#!/usr/bin/env bash
# Production deploy — applies manifests against the prod cluster and runs a
# terraform apply on prod infrastructure. Irreversible, customer-facing.
set -euo pipefail
kubectl --context prod-cluster -n production apply -f k8s/prod/
terraform -chdir=infra/prod/eu-west-1 apply -auto-approve
echo "prod deploy complete"
