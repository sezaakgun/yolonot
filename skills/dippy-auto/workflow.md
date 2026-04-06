# Dippy Sync Workflow

**Goal:** Analyze Dippy's decision history and interactively promote frequent patterns to config rules.

**Your Role:** An assistant that reads Dippy logs, finds patterns, and asks the user what to do with each one.

---

## EXECUTION

### Step 1: Read Dippy Logs

Read the Dippy hook-approvals log file at `~/.claude/hook-approvals.log`.

Parse each line to extract:
- Timestamp
- Decision type: `APPROVED`, `ASK`, `DENIED`
- Command summary (the text after the decision type)

If the file doesn't exist or is empty, tell the user and HALT.

### Step 2: Analyze Patterns

Group ASK entries by command summary. Count occurrences.

Filter to patterns with **5+ occurrences** (configurable via argument).

Sort by count descending.

Also group by the **project/cwd** where the command was run (if available in the log). If a pattern appears in 3+ different projects, mark it as a "global candidate." Otherwise mark it as "project candidate."

### Step 3: Present Findings

Show the user a summary:

```
Found X patterns from Y total ASK decisions.

GLOBAL CANDIDATES (appeared in 3+ projects):
  1. git add         — 46x asked across 5 projects
  2. git commit      — 37x asked across 4 projects
  3. mkdir -p        — 38x asked across 6 projects

PROJECT CANDIDATES (specific to current project):
  4. docker compose  — 32x asked (only in claude-auto-mode)
  5. go build        — 30x asked (only in claude-auto-mode)
```

### Step 4: Interactive Decision Loop

For each pattern (starting with highest count), ask the user:

```
Pattern: "git add" (46x asked)
Scope: global (seen in 5 projects)

What should we do?
  a) allow — auto-approve, add to .dippy
  b) deny  — auto-block, add to .dippy
  c) ask   — always prompt user (add to .dippy-auto as ask rule)
  d) llm   — let LLM decide each time (add to .dippy-auto as LLM fallback — no rule)
  e) skip  — do nothing, move to next
  q) quit  — stop and apply changes so far
```

Based on user's choice and scope:
- **Global + allow/deny** → append to `~/.dippy`
- **Global + ask** → append to `~/.dippy-auto`
- **Project + allow/deny** → append to `.dippy` in current project
- **Project + ask** → append to `.dippy-auto` in current project
- **llm** → skip (the LLM layer already handles unmatched commands)
- **skip** → do nothing

### Step 5: Apply Changes

After the user finishes (quit or all patterns processed):

1. Show a summary of all changes to be made:
   ```
   Changes to apply:
     ~/.dippy:
       + allow git add
       + allow git commit
     .dippy (project):
       + allow docker compose
     ~/.dippy-auto:
       + ask-cmd *aws kinesis*
   ```

2. Ask user to confirm: "Apply these changes? (yes/no)"

3. If confirmed:
   - Append rules to the appropriate files with a timestamp comment
   - Format: `# Auto-promoted by dippy-auto (YYYY-MM-DD)` header
   - Show confirmation of what was written

4. If not confirmed, discard and exit.

### Step 6: Cleanup Suggestion

After applying, optionally suggest:
- "These patterns won't appear as ASK anymore. Old log entries will naturally age out."
- "Run /dippy-auto again anytime to check for new patterns."

---

## NOTES

- NEVER modify Dippy's source code or global config without user approval
- NEVER auto-apply rules — always show and confirm first
- The log file format is: `YYYY-MM-DD HH:MM:SS [LEVEL] DECISION: command_summary`
- The log may not contain CWD/project info — if not available, treat all patterns as "project candidates" for the current directory
- `.dippy` uses Dippy's native format: `allow <command>` or `deny <command> "reason"`
- `.dippy-auto` uses dippy-auto's format: `allow-cmd <pattern>` or `deny-cmd <pattern>` or `ask-cmd <pattern>`
- Rules with glob patterns should use `*` for wildcards
- If a pattern like "parse error: Syntax error" appears, explain that this is Dippy failing to parse inline scripts and the LLM layer handles it — no rule needed
