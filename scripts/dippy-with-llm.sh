#!/bin/sh
# Dippy + LLM wrapper hook for Bash PreToolUse
#
# Flow:
# 1. Call Dippy (instant)
# 2. If Dippy allows/denies → use that
# 3. If Dippy says "ask" → call LLM to analyze the command
#
# Install: replace Dippy hook path in ~/.claude/settings.json with this script

DIPPY_HOOK="/Users/seza/Projects/Dippy/bin/dippy-hook"
LLM_ANALYZE="$(dirname "$0")/llm-analyze.py"
LOG_DIR="$HOME/.dippy-auto"
LOG_FILE="$LOG_DIR/decisions.jsonl"

# Ensure log dir exists
mkdir -p "$LOG_DIR" 2>/dev/null

# Helper: log a structured decision
log_decision() {
  python3 -c "
import json, sys, os
from datetime import datetime, timezone
entry = {
    'ts': datetime.now(timezone.utc).isoformat(),
    'session_id': sys.argv[1],
    'command': sys.argv[2],
    'cwd': sys.argv[3],
    'project': os.path.basename(sys.argv[3]),
    'layer': sys.argv[4],
    'decision': sys.argv[5],
}
# Optional fields
for kv in sys.argv[6:]:
    k, v = kv.split('=', 1)
    try: entry[k] = json.loads(v)
    except: entry[k] = v
print(json.dumps(entry))
" "$@" >> "$LOG_FILE" 2>/dev/null
}

# Read hook payload
INPUT=$(cat)
if [ -z "$INPUT" ] && [ -n "$CLAUDE_TOOL_INPUT" ]; then
  INPUT="{\"hook_event_name\":\"${CLAUDE_HOOK_EVENT_NAME:-PreToolUse}\",\"tool_name\":\"${CLAUDE_TOOL_NAME:-Bash}\",\"session_id\":\"${CLAUDE_SESSION_ID:-unknown}\",\"tool_input\":$CLAUDE_TOOL_INPUT}"
fi

# Extract session_id, command, cwd for logging
SESSION_ID=$(echo "$INPUT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('session_id',''))" 2>/dev/null)
COMMAND=$(echo "$INPUT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('tool_input',{}).get('command',''))" 2>/dev/null)
CWD=$(echo "$INPUT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('cwd',''))" 2>/dev/null)

# Call Dippy first
DIPPY_RESULT=$(echo "$INPUT" | "$DIPPY_HOOK" 2>/dev/null)
DIPPY_EXIT=$?

# If Dippy blocked (exit 2) → deny
if [ $DIPPY_EXIT -eq 2 ]; then
  DIPPY_REASON=$(echo "$DIPPY_RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('hookSpecificOutput',{}).get('permissionDecisionReason',''))" 2>/dev/null)
  log_decision "$SESSION_ID" "$COMMAND" "$CWD" "dippy" "deny" "reason=$DIPPY_REASON"
  echo "$DIPPY_RESULT"
  exit 2
fi

# Check Dippy's decision
DIPPY_DECISION=$(echo "$DIPPY_RESULT" | python3 -c "
import sys, json
try:
    r = json.load(sys.stdin)
    h = r.get('hookSpecificOutput', r)
    print(h.get('permissionDecision', ''))
except: print('')
" 2>/dev/null)

DIPPY_REASON=$(echo "$DIPPY_RESULT" | python3 -c "
import sys, json
try:
    r = json.load(sys.stdin)
    h = r.get('hookSpecificOutput', r)
    print(h.get('permissionDecisionReason', ''))
except: print('')
" 2>/dev/null)

# If Dippy decided allow or deny → use it
if [ "$DIPPY_DECISION" = "allow" ] || [ "$DIPPY_DECISION" = "deny" ]; then
  log_decision "$SESSION_ID" "$COMMAND" "$CWD" "dippy" "$DIPPY_DECISION" "reason=$DIPPY_REASON"
  echo "$DIPPY_RESULT"
  exit 0
fi

# Dippy said "ask" — call LLM
if [ -z "$COMMAND" ]; then
  log_decision "$SESSION_ID" "$COMMAND" "$CWD" "dippy" "ask" "reason=$DIPPY_REASON"
  echo "$DIPPY_RESULT"
  exit 0
fi

LLM_RESULT=$(python3 "$LLM_ANALYZE" "$COMMAND" 2>/dev/null)

if [ -z "$LLM_RESULT" ]; then
  log_decision "$SESSION_ID" "$COMMAND" "$CWD" "dippy" "ask" "reason=$DIPPY_REASON" "llm_error=unavailable"
  echo "$DIPPY_RESULT"
  exit 0
fi

# Extract LLM decision
LLM_DECISION=$(echo "$LLM_RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('decision',''))" 2>/dev/null)
LLM_CONFIDENCE=$(echo "$LLM_RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('confidence',''))" 2>/dev/null)
LLM_REASONING=$(echo "$LLM_RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('reasoning',''))" 2>/dev/null)

if [ "$LLM_DECISION" = "allow" ] || [ "$LLM_DECISION" = "deny" ]; then
  log_decision "$SESSION_ID" "$COMMAND" "$CWD" "llm" "$LLM_DECISION" "confidence=$LLM_CONFIDENCE" "reasoning=$LLM_REASONING"
  cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"$LLM_DECISION","permissionDecisionReason":"LLM: $LLM_REASONING"}}
EOF
  exit 0
fi

# LLM uncertain — return Dippy's ask
log_decision "$SESSION_ID" "$COMMAND" "$CWD" "llm" "ask" "confidence=$LLM_CONFIDENCE" "reasoning=$LLM_REASONING"
echo "$DIPPY_RESULT"
