# Dippy Auto Workflow

**Goal:** Analyze decision history and interactively improve .dippy and .dippy-auto rules.

**Your Role:** An assistant that reads logs, finds patterns, and asks the user what to do with each one.

---

## EXECUTION

### Step 1: Read Decision Logs

Read two data sources:

**Source A — dippy-auto decisions:** `~/.dippy-auto/decisions.jsonl`
- Each line is JSON with: ts, session_id, command, cwd, project, layer (dippy/rule/llm), decision, confidence, reasoning
- This is what WE decided

**Source B — Dippy log:** `~/.claude/hook-approvals.log`
- Each line: `YYYY-MM-DD HH:MM:SS [LEVEL] DECISION: command_summary`
- Decisions: APPROVED, ASK, DENIED
- This is what DIPPY decided (before our LLM layer)

**Source C — User overrides:** `~/.claude/audit/raw/*.jsonl`
- Look for PermissionRequest events where `tool_name=Bash`
- Extract: session_id, tool_input.decision (what user chose)
- Only read last 7 days of files

If no decision log exists, tell the user they need to use the system for a while first and HALT.

### Step 2: Analyze False Denies

Cross-reference decisions.jsonl with audit PermissionRequest events:
- Find entries where our decision was "deny" or "ask"
- Match by session_id (and approximate timestamp if needed)
- Check if the user then approved (PermissionRequest with decision=allow)
- Group by command prefix (first 2-3 tokens)
- Count occurrences

Present findings:

```
FALSE DENIES (we blocked, you approved):

  1. curl https://staging.insider.com/*  — 8x denied, you approved all 8
     Layer: llm | Reason: "unknown external URL"
     Suggestion: add "allow-cmd curl https://staging*" to .dippy-auto

  2. python3 test_*.py — 4x denied, you approved all 4
     Layer: llm | Reason: "sys import flagged as dangerous"
     Suggestion: add "allow-path test_*.py" to .dippy-auto

  3. git push origin feature-* — 3x asked by dippy
     Suggestion: add "allow git push" to .dippy (remove deny rule)
```

### Step 3: Analyze Risky Allows

Read decisions.jsonl for allow decisions where layer=llm:
- Group by command prefix
- Show confidence levels
- These are commands auto-approved without user verification

Present findings:

```
RISKY ALLOWS (auto-approved by LLM, worth reviewing):

  1. docker compose exec db psql * — 23x allowed at 92% avg confidence
     Typical reasoning: "local dev container operation"

  2. aws s3 cp * s3://dev-* — 15x allowed at 88% avg confidence
     Typical reasoning: "non-production S3 operation"

  For each: type 'ok' to confirm it's safe, or 'restrict' to add ask rule
```

### Step 4: Analyze Dippy ASK Patterns

Read Dippy's hook-approvals.log for ASK entries:
- Group by command summary, count occurrences
- Filter to 5+ occurrences
- Determine scope: if command appears in entries from 3+ different cwd paths → global candidate, otherwise project candidate

Present findings:

```
DIPPY ASK PATTERNS (Dippy keeps asking about):

  GLOBAL (seen across projects):
    4. git add         — 46x asked
    5. git commit      — 37x asked
    6. mkdir -p        — 38x asked

  PROJECT (this project only):
    7. docker compose  — 32x asked
    8. go build        — 30x asked
```

### Step 5: Interactive Decision Loop

For each finding (starting with false denies, then risky allows, then dippy patterns), ask:

```
[1/12] FALSE DENY: "curl https://staging*" (8x overridden)
  a) allow     — add allow rule (to .dippy or .dippy-auto depending on scope)
  b) deny      — keep blocking (add explicit deny rule)
  c) ask       — always prompt (add ask rule to .dippy-auto)
  d) llm       — keep LLM deciding (no rule change)
  e) skip      — do nothing
  q) quit      — apply changes made so far
```

For risky allows:
```
[5/12] RISKY ALLOW: "docker compose exec *" (23x auto-approved at 92%)
  ok)       — confirmed safe, promote to allow rule
  restrict) — add ask rule (require user confirmation)
  skip)     — keep LLM deciding
```

Based on choice and scope:
- **Global allow/deny** → append to `~/.dippy`
- **Global ask/cmd/path** → append to `~/.dippy-auto`
- **Project allow/deny** → append to `.dippy` in cwd
- **Project ask/cmd/path** → append to `.dippy-auto` in cwd
- **llm/skip** → no change

### Step 6: Apply Changes

Show summary:
```
Changes to apply:
  ~/.dippy:
    + allow git add
    + allow git commit
  .dippy-auto (project):
    + allow-cmd curl https://staging*
  ~/.dippy-auto:
    + ask-cmd *aws s3 cp*
```

Ask: "Apply these changes? (yes/no)"

If yes:
- Append rules with header: `# Auto-promoted by dippy-auto (YYYY-MM-DD)`
- Show confirmation

### Step 7: Log Rotation

After applying, offer to clean old entries:
- Count entries in decisions.jsonl
- If > 10,000 entries: "decisions.jsonl has X entries. Trim to last 10,000? (yes/no)"
- If yes: keep last 10,000 lines, remove older ones

---

## NOTES

- NEVER auto-modify configs without user confirmation
- NEVER read tool response content from audit logs (privacy)
- The `parse error: Syntax error` ASK pattern from Dippy = inline scripts the LLM now handles. Explain this to user — no rule needed
- `.dippy` format: `allow <command>` or `deny <command> "reason"`
- `.dippy-auto` format: `allow-cmd <pattern>`, `deny-cmd <pattern>`, `ask-cmd <pattern>`, `allow-path <pattern>`, etc.
- If Dippy log doesn't contain CWD info, treat all as "project candidates" for current directory
- For false deny correlation: match session_id between decisions.jsonl and audit PermissionRequest. If no session match within 5 seconds, consider unmatched.
