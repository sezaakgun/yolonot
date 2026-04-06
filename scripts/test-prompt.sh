#!/bin/sh
# Test the LLM analyzer with various commands
# Run directly: ./scripts/test-prompt.sh

ANALYZE="$(dirname "$0")/llm-analyze.py"

for CMD in \
  'helm list --namespace production' \
  'helm delete my-release --namespace production'
do
  echo "=== $CMD ==="
  echo "$CMD" | python3 "$ANALYZE"
  echo ""
done
