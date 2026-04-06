#!/bin/sh
cd "$(dirname "$0")/.."

ANALYZE="scripts/llm-analyze.py"

echo "=== curl localhost (expect: allow rule) ==="
echo 'curl http://localhost:8080/health' | python3 "$ANALYZE"

echo ""
echo "=== curl external (expect: ask rule) ==="
echo 'curl https://example.com/api' | python3 "$ANALYZE"

echo ""
echo "=== test script (expect: allow-path) ==="
echo 'sh scripts/test-prompt.sh' | python3 "$ANALYZE"

echo ""
echo "=== rm -rf (expect: deny rule) ==="
echo 'rm -rf /' | python3 "$ANALYZE"

echo ""
echo "=== print (expect: allow rule) ==="
echo 'python3 -c "print(hello)"' | python3 "$ANALYZE"

echo ""
echo "=== deploy script (expect: ask-path) ==="
echo 'bash deploy/rollout.sh' | python3 "$ANALYZE"

echo ""
echo "=== no rule match (expect: LLM call) ==="
echo 'go test ./...' | python3 "$ANALYZE"
