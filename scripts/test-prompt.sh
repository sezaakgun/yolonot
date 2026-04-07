#!/bin/sh
# Test the LLM analyzer with various commands
# Run directly: ./scripts/test-prompt.sh

ANALYZE="$(dirname "$0")/llm-analyze.py"

for CMD in \
  'helm list --namespace production' \
  'helm delete my-release --namespace production' \
  'kubectl get pods -n dev --context prod-dataforce' \
  'kubectl delete pod my-pod -n production --context prod' \
  'aws lambda get-policy --function-name test | python3 -c "import json,sys; print(json.loads(sys.stdin.read()))"' \
  'python3 -c "import os; os.remove(\"/tmp/test\")"' \
  'uv run python -c "print(hello)"'
do
  echo "=== $CMD ==="
  echo "$CMD" | python3 "$ANALYZE"
  echo ""
done
