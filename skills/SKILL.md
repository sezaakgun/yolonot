---
name: yolonot
description: "Manage yolonot session state: view approved/denied/asked commands, override decisions, reset session, view decision logs, show rules, and suggest rules from history. Use when user says /yolonot, or mentions yolonot status, session state, approved commands, denied commands, decision logs, or evolving rules."
user_invocable: true
---

# Yolonot Session Manager

View and manage yolonot's session state, rules, and decision history.

## COMMANDS

Parse the user's input to determine which command to run. The argument after `/yolonot` determines the action.

### `/yolonot` (no args) — Show menu + session summary

Show a brief session summary followed by available commands:

1. Find the current session ID from `$CLAUDE_SESSION_ID` or most recent session file in `~/.yolonot/sessions/`
2. Count entries in `.approved`, `.asked`, `.denied` files
3. Display:

```
yolonot session: {SESSION_ID}
  {approved_count} approved · {asked_count} asked · {denied_count} denied

Commands:
  /yolonot status          — full session state (approved/asked/denied lists)
  /yolonot approve <cmd>   — move command to approved
  /yolonot deny <cmd>      — move command to denied
  /yolonot reset           — clear session state
  /yolonot pause           — disable yolonot for this session (total bypass)
  /yolonot resume          — re-enable yolonot for this session
  /yolonot log             — recent decisions
  /yolonot rules           — show active rules
  /yolonot suggest          — learn from history, update rules
  /yolonot init            — create rule files for this project
```

### `/yolonot pause` — Disable for this session

Run `yolonot pause --current`. This creates a marker
file that makes the hook bypass yolonot entirely for the current session —
no rules, no LLM, no session memory. Claude Code's native permissions handle
commands as if yolonot weren't installed.

### `/yolonot resume` — Re-enable for this session

Run `yolonot resume --current`. Removes the pause
marker, yolonot takes effect again.

### `/yolonot status` — Full session state

1. Read session files:
   - `~/.yolonot/sessions/{SESSION_ID}.approved`
   - `~/.yolonot/sessions/{SESSION_ID}.asked`
   - `~/.yolonot/sessions/{SESSION_ID}.denied`
2. Deduplicate entries within each list
3. Display:

```
APPROVED ({count}):
  ✓ kubectl get pods -n dev --context prod-cluster
  ✓ uv run pytest -v

ASKED ({count}):
  ? curl https://example.com
  ? chmod +x script.sh

DENIED ({count}):
  ✗ rm -rf /tmp/test-data
  ✗ git push --force origin main
```

If all files are empty/missing: "No decisions recorded for this session yet."

### `/yolonot approve <command>` — Move command to approved

1. Find the command in `.asked` or `.denied` files (partial match is OK)
2. Remove it from `.denied` if present
3. Add it to `.approved`
4. Confirm: "Moved to approved: {command}"

If command not found in any file, add it to `.approved` directly and confirm.

### `/yolonot deny <command>` — Move command to denied

1. Find the command in `.asked` or `.approved` files (partial match is OK)
2. Remove it from `.approved` if present
3. Add it to `.denied`
4. Confirm: "Moved to denied: {command}"

### `/yolonot reset` — Clear session files

1. Ask for confirmation: "This will clear all approved/denied/asked lists for this session. Continue?"
2. If confirmed, delete all session files for current session ID
3. Confirm: "Session state cleared."

### `/yolonot log` — Show recent decisions

1. Read `~/.yolonot/decisions.jsonl`
2. Show the last 20 entries, formatted as:

```
Recent decisions:

  12:34:05  allow   session        kubectl get pods -n dev
  12:34:12  ask     llm            curl https://example.com  (0.7 SENSITIVE)
  12:34:30  deny    session_deny   curl https://example.com  (previously rejected)
  12:35:01  allow   llm            uv run pytest -v  (0.9)
```

### `/yolonot rules` — Show active rules

1. Read `.yolonot` from current directory (project rules)
2. Read `~/.yolonot` from home directory (global rules)
3. Display both:

```
Project rules (.yolonot):
  allow-path  scripts/*
  allow-cmd   curl localhost*
  deny-cmd    *rm -rf /*
  ask-cmd     *curl *

Global rules (~/.yolonot):
  (none)
```

### `/yolonot suggest` — Learn from history, update rules

Analyze decision history and interactively promote patterns to permanent rules.

**Step 1: Analyze decisions**

Read `~/.yolonot/decisions.jsonl`. Cross-reference with audit data in `~/.claude/audit/raw/*.jsonl` (last 7 days). Group commands by pattern (first 2-3 tokens). Find:

1. **False asks** — commands yolonot asked about that the user always approved (PermissionRequest events with decision=allow matching session_id). These should become allow rules.
2. **Risky allows** — commands auto-approved by LLM with low confidence (<0.8). These might need ask rules.
3. **Repeated asks** — same command pattern asked 3+ times across sessions. Candidates for permanent rules.

**Step 2: Present findings**

```
EVOLVE: Analyzing last 7 days of decisions...

FALSE ASKS (you always approved these — make them allow rules?):
  1. curl https://staging.example.com/*  — 8x asked, approved all 8
     Suggestion: allow-cmd curl https://staging*
  2. python3 test_*.py — 4x asked, approved all 4
     Suggestion: allow-path test_*.py

RISKY ALLOWS (auto-approved, worth reviewing):
  3. docker compose exec db psql * — 12x allowed at 0.7 avg confidence
     Suggestion: ask-cmd *docker compose exec*

REPEATED ASKS (same pattern keeps coming up):
  4. chmod +x scripts/* — 6x asked across 3 sessions
     Suggestion: allow-cmd chmod +x scripts/*
```

**Step 3: Interactive loop**

For each finding, ask the user:
```
[1/4] "curl https://staging*" (8x false ask)
  a) allow  — add allow-cmd rule
  b) deny   — add deny-cmd rule
  c) ask    — add ask-cmd rule (keep asking)
  d) skip   — no change
  q) quit   — apply changes made so far

Scope: (p)roject .yolonot or (g)lobal ~/.yolonot?
```

**Step 4: Apply**

Show summary of all changes, ask for confirmation, then append rules:
```
# Evolved by yolonot (YYYY-MM-DD)
allow-cmd curl https://staging*
ask-cmd *docker compose exec*
allow-cmd chmod +x scripts/*
```

### `/yolonot init` — Create rule files

Set up yolonot for the current project and globally.

1. Check what exists:
   - `~/.yolonot` (global rules file)
   - `~/.yolonot/` (data directory)
   - `.yolonot` in current directory (project rules)

2. Create what's missing:

   **Global rules** (`~/.yolonot` file) — if not exists, create with sensible defaults:
   ```
   # ~/.yolonot — global rules (apply to all projects)
   # Format: <action>-<type> <pattern>
   # Actions: allow, deny, ask
   # Types: cmd (command pattern), path (script file path)

   # --- Safe patterns ---
   allow-cmd curl localhost*
   allow-cmd curl 127.0.0.1*
   allow-cmd curl http://localhost*
   allow-cmd curl http://127.0.0.1*

   # --- Dangerous patterns ---
   deny-cmd *rm -rf /*
   deny-cmd *sudo *
   deny-cmd *chmod 777*
   deny-cmd *> /dev/sd*
   deny-cmd *mkfs*
   deny-cmd *dd if=*

   # --- Uncertain ---
   ask-cmd *curl *
   ask-cmd *wget *
   ```

   **Data directory** (`~/.yolonot/`) — create with `sessions/` and `cache/` subdirs.

   **Project rules** (`.yolonot` in cwd) — if not exists, create a starter template:
   ```
   # .yolonot — project rules for {project_name}
   # Format: <action>-<type> <pattern>

   # --- Project scripts ---
   allow-path scripts/*
   allow-path tests/*
   allow-path test_*
   ```

   Then scan the project for tech stack hints and suggest additional rules:
   - If `pyproject.toml` exists: `allow-cmd uv run python -c "print*`
   - If `package.json` exists: `allow-cmd npm test*`, `allow-cmd npm run build*`
   - If `go.mod` exists: `allow-cmd go test*`, `allow-cmd go build*`
   - If `Dockerfile` exists: `allow-cmd docker build*`, `allow-cmd docker compose*`
   - If `k8s/` or `helm/` exists: suggest ask rules for kubectl/helm mutations
   - If `deploy/` or `infra/` exists: `ask-path deploy/*`, `ask-path infra/*`

   Show the generated file to the user before writing. Ask for confirmation.

3. Show summary:
   ```
   yolonot initialized:
     ✓ ~/.yolonot (global rules — 12 rules)
     ✓ ~/.yolonot/sessions/ (session data)
     ✓ .yolonot (project rules — 5 rules)
   ```

   If files already exist, show which were skipped:
   ```
     ✓ ~/.yolonot (already exists — 8 rules)
     ✓ .yolonot (created — 5 rules)
   ```

## NOTES

- Use `yolonot <cmd> --current` for pause/resume (resolves via most recent session file)
- For reading session state directly, use `$CLAUDE_SESSION_ID` if set, otherwise the most recently modified `.approved` or `.asked` file
- For partial match in approve/deny: match if stored command contains user's input as substring
- All session files live in `~/.yolonot/sessions/`
- Display commands truncated to 80 chars with `...` if longer
- NEVER auto-modify rules without user confirmation
- NEVER read tool_response content from audit logs (privacy)
- `.yolonot` rule format: `allow-cmd <pattern>`, `deny-cmd <pattern>`, `ask-cmd <pattern>`, `allow-path <pattern>`, `deny-path <pattern>`, `ask-path <pattern>`
- For suggest cross-reference: match session_id between decisions.jsonl and audit PermissionRequest events
