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
DEBUG_LOG="/tmp/dippy-llm-debug.log"

echo "--- $(date) ---" >> "$DEBUG_LOG"

# Read hook payload — Claude Code passes it on both stdin AND env vars
INPUT=$(cat)
echo "STDIN INPUT: ${INPUT:0:200}" >> "$DEBUG_LOG"
echo "CLAUDE_TOOL_INPUT: ${CLAUDE_TOOL_INPUT:0:200}" >> "$DEBUG_LOG"
if [ -z "$INPUT" ] && [ -n "$CLAUDE_TOOL_INPUT" ]; then
  # Reconstruct minimal payload from env vars
  INPUT="{\"hook_event_name\":\"${CLAUDE_HOOK_EVENT_NAME:-PreToolUse}\",\"tool_name\":\"${CLAUDE_TOOL_NAME:-Bash}\",\"session_id\":\"${CLAUDE_SESSION_ID:-unknown}\",\"tool_input\":$CLAUDE_TOOL_INPUT}"
fi

# Call Dippy first
DIPPY_RESULT=$(echo "$INPUT" | "$DIPPY_HOOK" 2>/dev/null)
DIPPY_EXIT=$?

echo "DIPPY_EXIT: $DIPPY_EXIT" >> "$DEBUG_LOG"
echo "DIPPY_RESULT: ${DIPPY_RESULT:0:200}" >> "$DEBUG_LOG"

# If Dippy blocked (exit 2) → deny
if [ $DIPPY_EXIT -eq 2 ]; then
  echo "$DIPPY_RESULT"
  exit 2
fi

# Check Dippy's decision using python (handles JSON properly)
DIPPY_DECISION=$(echo "$DIPPY_RESULT" | python3 -c "
import sys, json
try:
    r = json.load(sys.stdin)
    h = r.get('hookSpecificOutput', r)
    print(h.get('permissionDecision', ''))
except: print('')
" 2>/dev/null)

echo "DIPPY_DECISION: '$DIPPY_DECISION'" >> "$DEBUG_LOG"

# If Dippy decided allow or deny → use it
if [ "$DIPPY_DECISION" = "allow" ] || [ "$DIPPY_DECISION" = "deny" ]; then
  echo "FAST PATH: dippy $DIPPY_DECISION" >> "$DEBUG_LOG"
  echo "$DIPPY_RESULT"
  exit 0
fi

echo "SLOW PATH: calling LLM" >> "$DEBUG_LOG"

# Dippy said "ask" — extract command and call LLM
COMMAND=$(echo "$INPUT" | python3 -c "
import sys, json, os
try:
    r = json.load(sys.stdin)
    print(r.get('tool_input', {}).get('command', ''))
except:
    # Fallback to env var
    ti = os.environ.get('CLAUDE_TOOL_INPUT', '{}')
    try:
        print(json.loads(ti).get('command', ''))
    except: print('')
" 2>/dev/null)

if [ -z "$COMMAND" ]; then
  echo "$DIPPY_RESULT"
  exit 0
fi

LLM_RESULT=$(python3 "$LLM_ANALYZE" "$COMMAND" 2>/dev/null)

if [ -z "$LLM_RESULT" ]; then
  echo "$DIPPY_RESULT"
  exit 0
fi

# Extract LLM decision
LLM_DECISION=$(echo "$LLM_RESULT" | python3 -c "
import sys, json
try:
    r = json.load(sys.stdin)
    print(r.get('decision', ''))
except: print('')
" 2>/dev/null)

LLM_REASONING=$(echo "$LLM_RESULT" | python3 -c "
import sys, json
try:
    r = json.load(sys.stdin)
    print(r.get('reasoning', ''))
except: print('')
" 2>/dev/null)

if [ "$LLM_DECISION" = "allow" ] || [ "$LLM_DECISION" = "deny" ]; then
  cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"$LLM_DECISION","permissionDecisionReason":"LLM: $LLM_REASONING"}}
EOF
  exit 0
fi

# LLM uncertain — return Dippy's ask
echo "$DIPPY_RESULT"
