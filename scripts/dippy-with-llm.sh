#!/bin/sh
# dippy-auto: LLM-powered Bash command analyzer for Claude Code
#
# Flow:
# 1. Check session memory (exact match → instant allow)
# 2. Check session similarity via LLM (similar to approved → allow)
# 3. Call Dippy if installed (instant, optional)
# 4. Check .dippy-auto rules + LLM to analyze the command
# 5. LLM deny → return "ask" + save to session if user approves later
#
# Works with or without Dippy. Set DIPPY_HOOK env var to override path.
# Install: add as hook in ~/.claude/settings.json

DIPPY_HOOK="${DIPPY_HOOK:-/Users/seza/Projects/Dippy/bin/dippy-hook}"
LLM_ANALYZE="$(dirname "$0")/llm-analyze.py"
SESSION_COMPARE="$(dirname "$0")/session-compare.py"
LOG_DIR="$HOME/.dippy-auto"
LOG_FILE="$LOG_DIR/decisions.jsonl"
SESSION_DIR="$LOG_DIR/sessions"

mkdir -p "$LOG_DIR" "$SESSION_DIR" 2>/dev/null

# Cleanup old session files (older than 24h)
find "$SESSION_DIR" -name "*.approved" -mtime +1 -delete 2>/dev/null

# Helper: log a structured decision (skip if no command)
log_decision() {
  [ -z "$2" ] && return
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

# Extract fields
SESSION_ID=$(echo "$INPUT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('session_id',''))" 2>/dev/null)
COMMAND=$(echo "$INPUT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('tool_input',{}).get('command',''))" 2>/dev/null)
CWD=$(echo "$INPUT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('cwd',''))" 2>/dev/null)

SESSION_FILE="$SESSION_DIR/${SESSION_ID}.approved"

# Step 1: Check session memory
if [ -n "$SESSION_ID" ] && [ -n "$COMMAND" ] && [ -f "$SESSION_FILE" ]; then
  # Exact match check (instant, no LLM)
  if grep -qFx "$COMMAND" "$SESSION_FILE" 2>/dev/null; then
    log_decision "$SESSION_ID" "$COMMAND" "$CWD" "session" "allow" "source=exact_match"
    cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"Previously approved this session"}}
EOF
    exit 0
  fi

  # Step 2: LLM similarity check against approved commands
  COMPARE_RESULT=$(python3 "$SESSION_COMPARE" "$COMMAND" "$SESSION_FILE" 2>/dev/null)
  if [ -n "$COMPARE_RESULT" ]; then
    COMPARE_DECISION=$(echo "$COMPARE_RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('decision',''))" 2>/dev/null)
    COMPARE_REASONING=$(echo "$COMPARE_RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('reasoning',''))" 2>/dev/null)
    COMPARED_TO=$(echo "$COMPARE_RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('compared_to',''))" 2>/dev/null)

    if [ "$COMPARE_DECISION" = "allow" ]; then
      # LLM says it's similar enough — auto-allow and remember
      echo "$COMMAND" >> "$SESSION_FILE"
      log_decision "$SESSION_ID" "$COMMAND" "$CWD" "session_llm" "allow" "reasoning=$COMPARE_REASONING" "compared_to=$COMPARED_TO"
      cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"Similar to approved: $COMPARE_REASONING"}}
EOF
      exit 0
    fi
  fi
fi

# Step 3: Call Dippy (if installed)
DIPPY_DECISION=""
DIPPY_REASON=""
if [ -x "$DIPPY_HOOK" ]; then
  DIPPY_RESULT=$(echo "$INPUT" | "$DIPPY_HOOK" 2>/dev/null)
  DIPPY_EXIT=$?

  if [ $DIPPY_EXIT -eq 2 ]; then
    DIPPY_REASON=$(echo "$DIPPY_RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('hookSpecificOutput',{}).get('permissionDecisionReason',''))" 2>/dev/null)
    log_decision "$SESSION_ID" "$COMMAND" "$CWD" "dippy" "deny" "reason=$DIPPY_REASON"
    echo "$DIPPY_RESULT"
    exit 2
  fi

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

  if [ "$DIPPY_DECISION" = "allow" ] || [ "$DIPPY_DECISION" = "deny" ]; then
    log_decision "$SESSION_ID" "$COMMAND" "$CWD" "dippy" "$DIPPY_DECISION" "reason=$DIPPY_REASON"
    echo "$DIPPY_RESULT"
    exit 0
  fi
fi

# Step 4: Dippy said "ask" — call LLM analyzer
if [ -z "$COMMAND" ]; then
  echo "$DIPPY_RESULT"
  exit 0
fi

LLM_RESULT=$(python3 "$LLM_ANALYZE" "$COMMAND" 2>/dev/null)

if [ -z "$LLM_RESULT" ]; then
  log_decision "$SESSION_ID" "$COMMAND" "$CWD" "dippy" "ask" "reason=$DIPPY_REASON" "llm_error=unavailable"
  echo "$DIPPY_RESULT"
  exit 0
fi

LLM_DECISION=$(echo "$LLM_RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('decision',''))" 2>/dev/null)
LLM_CONFIDENCE=$(echo "$LLM_RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('confidence',''))" 2>/dev/null)
LLM_REASONING=$(echo "$LLM_RESULT" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('reasoning',''))" 2>/dev/null)

if [ "$LLM_DECISION" = "allow" ]; then
  log_decision "$SESSION_ID" "$COMMAND" "$CWD" "llm" "allow" "confidence=$LLM_CONFIDENCE" "reasoning=$LLM_REASONING"
  cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"LLM: $LLM_REASONING"}}
EOF
  exit 0
fi

if [ "$LLM_DECISION" = "deny" ]; then
  # Return "ask" — if user approves, remember the exact command for this session
  # (We detect approval because the command appears in PostToolUse next time)
  log_decision "$SESSION_ID" "$COMMAND" "$CWD" "llm" "deny" "confidence=$LLM_CONFIDENCE" "reasoning=$LLM_REASONING" "returned_as=ask"
  cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"LLM: $LLM_REASONING"}}
EOF
  # Save to session — if this exact command comes again, it means user approved
  [ -n "$SESSION_ID" ] && echo "$COMMAND" >> "$SESSION_FILE"
  exit 0
fi

# LLM uncertain — ask, save to session
log_decision "$SESSION_ID" "$COMMAND" "$CWD" "llm" "ask" "confidence=$LLM_CONFIDENCE" "reasoning=$LLM_REASONING"
[ -n "$SESSION_ID" ] && echo "$COMMAND" >> "$SESSION_FILE"
echo "$DIPPY_RESULT"
