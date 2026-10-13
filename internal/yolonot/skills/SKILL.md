---
name: yolonot
description: "Manage yolonot session state: view approved/denied/asked commands, override decisions, reset session, view decision logs, show rules, and suggest rules from history. Use when user says /yolonot, or mentions yolonot status, session state, approved commands, denied commands, decision logs, or evolving rules."
user_invocable: true
---

# Yolonot Session Manager

View and manage yolonot's session state, rules, and decision history.

> **Claude Code only.** This skill ships through `~/.claude/skills/` and is invoked via Claude Code's `/yolonot` slash command. It is not installed for Codex / OpenCode / Gemini hosts — those hosts run the same `yolonot` binary, but without the TUI skill. Users on those hosts can still invoke every command shown below directly in the terminal (`yolonot status`, `yolonot check <cmd>`, …).

## COMMANDS

Parse the user's input to determine which command to run. The argument after `/yolonot` determines the action.

### Safety invariants — READ FIRST

**Never auto-invoke `pause`, `resume`, or `reset`.** These commands disable the safety layer the user installed. The correct behavior:

- If you are blocked by yolonot and want to proceed, use `/yolonot approve <cmd>` — it allows that **one specific command** for the remainder of the session. Nothing else is relaxed.
- Only invoke `pause` / `resume` / `reset` when the user types those exact words (e.g. "pause yolonot", "reset the session"). Do not invoke them on your own initiative to work around a deny, ask, or rule match — that is a safety bypass, not a workaround.
- Running a destructive command (kube ops, production state, irreversible writes) through pause is a failure mode. Prefer `approve` with the exact command string; if the command isn't narrow enough for approve, surface the block to the user and let them decide.

### Execution policy — mutations print, reads run

The skill is split into two classes of commands. Match exactly:

**Run directly (read-only):** `status`, `log [n]`, `rules` (and `rules --trace`), `stats`, `check`, `profile` (no args / `list` / `show`), `risk` (show forms), `judges` (list), `models` (list / `test`), `prompt` (all forms), `quiet` (no args), `escalation` (no args / `test`), `migrate --dry-run`.

**Print the command, do NOT execute (mutating / safety-sensitive):** `pause`, `resume`, `reset`, `approve`, `deny`, `profile use|reset|create|delete`, `risk <h> <tier> <action>` and `risk <h> reset`, `judges add|remove|move`, `models add|remove`, `quiet on|off`, `escalation on|off|setup`, `suggest`, `init`, `setup`, `install`, `uninstall`, `migrate` (and `--undo`), `upgrade`, `config` (the interactive settings screen; it needs the user's terminal).

Removed verbs (`provider`, `decision`, `pre-check`, `classifier`, `local-allow`, `threshold`) print their replacement and exit 2; never suggest them.

For mutations, format the response as:

```
Run this when you're ready:

    yolonot profile use fast --session

What it does: pins the `fast` profile to this Claude session only. Clears when the session ends.
```

Show the exact, copy-pasteable command and a one-line explanation of effect + reversibility. Never wrap it in `bash -lc`, never silently invoke it, never assume you can re-run it later. If the user follows up with "go ahead" / "run it" / "yes" — only then execute.

This protects the user from agent-driven config drift: the user typed `/yolonot profile use fast`, but the *act of changing config* should still be deliberate and visible.

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
  /yolonot suggest         — learn from history, update rules
  /yolonot check <cmd>     — dry-run pipeline test
  /yolonot stats           — show decision analytics
  /yolonot profile [...]   — pick risk profile (fast/balanced/strict/paranoid + custom)
  /yolonot risk [...]      — show/set per-harness risk tier → action policy
  /yolonot judges          — the judge chain: fast_allow, exec:<hook>, model names
  /yolonot models          — model catalog (chat + typed decision models + exec hooks)
  /yolonot prompt          — prompt customization (defaults|config|review|verify)
  /yolonot escalation      — second-opinion model status (on|off|setup|test)
  /yolonot quiet [on|off]  — silence banners for allow decisions
  /yolonot config          — interactive settings screen (judges, models, policy, prompt)
  /yolonot migrate         — rewrite a 0.x config.json as 1.x (--dry-run | --undo)
  /yolonot init            — create rule files for this project
```

### `/yolonot pause` — Disable for this session

**Mutation — print, do not run.** This command disables the safety layer; the user must execute it themselves.

Print:

```
Run this when you're ready:

    yolonot pause --current --confirm-bypass

What it does: total bypass of yolonot for this session — no rules, no LLM, no session memory. Reversible with `yolonot resume --current`.
```

Only print the command when the user explicitly says "pause" / "disable yolonot" / "turn off yolonot for this session". Never print it to work around a deny/ask — use `/yolonot approve <cmd>` for that.

### `/yolonot resume` — Re-enable for this session

**Mutation — print, do not run.** Print:

```
Run this when you're ready:

    yolonot resume --current

What it does: removes the pause marker, yolonot active again for this session.
```

### `/yolonot status` — Full session state

1. Read session files (project-scoped):
   - `~/.yolonot/sessions/{SESSION_ID}_{PROJECT_HASH}.approved`
   - `~/.yolonot/sessions/{SESSION_ID}_{PROJECT_HASH}.asked`
   - `~/.yolonot/sessions/{SESSION_ID}_{PROJECT_HASH}.denied`
   
   Where `{PROJECT_HASH}` is derived from the git root or cwd. A command approved in project A is NOT auto-approved in project B.
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

There is no `yolonot approve` verb: session state is plain files, one command per line, under `~/.yolonot/sessions/{SESSION_ID}_{PROJECT_HASH}.{approved,asked,denied}`. The hook treats a command on `.approved` as an instant allow and a command on `.denied` (or on `.asked` with no approval recorded) as an instant deny.

**Mutation — print, do not run.** Resolve the session file (see NOTES), then print the exact lines for the user:

```
Run this when you're ready:

    printf '%s\n' '<command>' >> ~/.yolonot/sessions/<SESSION_ID>_<PROJECT_HASH>.approved
    grep -vxF '<command>' ~/.yolonot/sessions/<SESSION_ID>_<PROJECT_HASH>.denied > /tmp/denied && mv /tmp/denied ~/.yolonot/sessions/<SESSION_ID>_<PROJECT_HASH>.denied   # only if it was denied

What it does: yolonot allows this exact command string for the rest of this session in this project. A command that runs a script is also content-pinned (`.approvedhash`); a hand-added approval has no hash, so the script is re-judged once and then remembered.
```

### `/yolonot deny <command>` — Move command to denied

**Mutation — print, do not run.** Same file mechanism:

```
Run this when you're ready:

    printf '%s\n' '<command>' >> ~/.yolonot/sessions/<SESSION_ID>_<PROJECT_HASH>.denied

What it does: yolonot denies this exact command for the rest of the session. Reversible via `/yolonot approve`.
```

### `/yolonot reset` — Clear session files

**Mutation — print, do not run.** Print:

```
Run this when you're ready:

    rm -f ~/.yolonot/sessions/<SESSION_ID>_<PROJECT_HASH>.{approved,approvedhash,asked,denied}

What it does: clears approved/asked/denied lists for this session + project. Decision log (`~/.yolonot/decisions.jsonl`) is preserved; the pause marker is not touched.
```

Only print when the user explicitly types "reset". Never print to work around a deny.

### `/yolonot log` — Show recent decisions

Run: `yolonot log` (last 20) or `yolonot log <n>`. Output:

```
Recent decisions (last 4):

  12:34:05  allow   fast_allow     kubectl get pods -n dev  (built-in allow: kubectl get is read-only)
  12:34:12  ask     jev-1.13       curl https://example.com  (decision: exfil)  310ms
  12:34:30  deny    session_deny   curl https://example.com  (previously rejected)
  12:35:01  allow   gemini-flash   uv run pytest -v  (routine test run)  820ms  ⤴esc 2400ms
```

The layer column is the judge that decided: `rule`, `session`, `session_deny`, `session_llm` (similarity), `cache`, `fast_allow`, `exec:<hook>`, a model name from `yolonot models` (`+esc` when escalation changed the verdict), `human` (the user's answer to an ask), `oversize`. Multiline commands are shown on one row with `⏎`.

### `/yolonot rules` — Show active rules

1. Walk up from cwd collecting every `.yolonot` encountered (stops at the git repo root or `$HOME`; outside a git repo only the cwd file is read). Closer-to-cwd files win (first match).
2. Read `~/.yolonot/rules` (generated by setup) and `~/.yolonot` file form if present. `yolonot rules --trace` prints where every active rule came from.
3. Display all with their source:

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

**Mutation — print, do not run.** `suggest` writes to `~/.yolonot/rules` and project `.yolonot` files; the user must run it themselves so the interactive TUI runs in their terminal.

Print:

```
Run this when you're ready:

    yolonot suggest

What it does: analyzes decision history, opens an interactive TUI to promote patterns to permanent allow/ask rules. Writes to `~/.yolonot` and/or project `.yolonot`.
```

Below is what `suggest` does — explanatory only, do NOT execute the analysis yourself:

**Step 1: Analyze decisions**

Read `~/.yolonot/decisions.jsonl` (the user's answers to asks are logged there as `layer: "human"` entries). Group commands by pattern, stripping variable parts (UUIDs, hashes, timestamps) for better grouping. Use time-weighted scoring (recent decisions count more). Skip patterns already covered by existing rules. Find:

1. **False asks** — commands yolonot asked about that the user always approved. These should become allow rules.
2. **Risky allows** — commands auto-approved by LLM at `moderate`/`high` risk tiers. These might need ask rules.
3. **Repeated asks** — same command pattern asked 3+ times across sessions. Candidates for permanent rules.

**Step 2: Present TUI menu**

The suggest command now presents findings via a TUI menu (not raw text). The user selects which suggestions to act on interactively.

**Step 3: Apply**

Show summary of all changes, ask for confirmation, then append rules:
```
# Evolved by yolonot (YYYY-MM-DD)
allow-cmd curl https://staging*
ask-cmd *docker compose exec*
allow-cmd chmod +x scripts/*
```

### `/yolonot check <command>` — Dry-run pipeline test

Test what the pipeline would decide for a command without running through Claude Code. Shows each layer's result.

Run: `yolonot check "<command>"`

Example output:
```
$ yolonot check "sudo rm -rf /"
Command: sudo rm -rf /

  [1] Deny rules:      DENY — matched deny-cmd *rm -rf /*

  → Result: DENY (layer: rule, absolute block)
```

The check command walks the pipeline (deny rules → allow/ask rules → the judge chain → escalation → risk map) and shows the result at each layer, stopping at the first decisive one. Session memory is not consulted and `exec:` hooks are listed but skipped, so it shows what a fresh session would decide.

### `/yolonot stats` — Show decision analytics

Show aggregate stats from the decision log.

Run: `yolonot stats`

Displays:
- Total decisions, allow/ask/deny counts, passthroughs, ask resolutions (approved / rejected by the user)
- Layer distribution (rules, session, fast_allow, exec hooks, each model by name)
- Model call latency, instant allows, escalation counters (fired / rescued / hardened)
- Top asked commands (rule candidates)
- Per-project breakdown

### `/yolonot profile [...]` — Pick a named risk policy

Profiles bundle tier→action decisions. Built-ins: `fast` (allow everything reversible, deny only prod-breaking — no ask prompts), `balanced` (default), `strict`, `paranoid`.

**Read-only — run directly:**
- `yolonot profile` — show active profile + overrides
- `yolonot profile list` — list built-in + custom profiles
- `yolonot profile show <name>` — show one profile's tier map

**Mutation — print, do not run.** When the user wants to change profile, print the exact command. Default to a session pin for "now I want fast" / "switch to strict" requests inside a running Claude session, since that's the only change that takes effect mid-session without restart.

**Resolve the session id BEFORE printing** so the user gets a copy-pasteable command that doesn't depend on env vars in their shell. Run (read-only):

```bash
echo "${CLAUDE_SESSION_ID:-$(ls -t ~/.yolonot/sessions/*.approved ~/.yolonot/sessions/*.asked ~/.yolonot/sessions/*.denied 2>/dev/null | head -1 | xargs basename 2>/dev/null | sed 's/\.[^.]*$//')}"
```

Substitute the resolved id into the printed command via `--session-id`. Example:

```
Run this when you're ready:

    yolonot profile use fast --session-id abc123_d8b9e2c1

What it does: pins `fast` profile for session abc123_d8b9e2c1 only. Auto-clears when session ends. Reset: yolonot profile reset --session-id abc123_d8b9e2c1
```

If the session id can't be resolved (no session files yet), fall back to:

```
    yolonot profile use fast --session
```

(the binary self-resolves to the most-recent session, but printing the id explicitly makes it transparent to the user which session is being modified).

```
Run this when you're ready:

    yolonot profile use strict

What it does: sets `strict` as the persistent global profile. Affects all future sessions. Override per-harness with `--harness=<h>`. Reset with `yolonot profile reset`.
```

Other mutating forms (also print, don't run): `yolonot profile create <name> --base=<existing>`, `yolonot profile delete <name>`, `yolonot profile reset [--session|--harness=<h>]`.

Env pins (per-session, dies with shell): `YOLONOT_PROFILE=fast` global, `YOLONOT_<HARNESS>_PROFILE=fast` per-harness — print as a one-line shell prefix when the user wants a one-shot launch.

### `/yolonot risk [...]` — Per-harness risk → action policy

Every LLM decision carries a 5-tier risk tag (`safe` / `low` / `moderate` / `high` / `critical`). Each harness ships a default tier → action map (`allow` / `ask` / `deny` / `passthrough`) that you can override per-cell.

**Read-only — run directly:** `yolonot risk` (active harness), `yolonot risk <harness>` (named).

**Mutation — print, do not run.** Print the override or reset command for the user:

```
Run this when you're ready:

    yolonot risk codex moderate deny

What it does: pins codex/moderate → deny in `~/.yolonot/config.json`, beating the active profile at that one cell. Reset with `yolonot risk codex reset moderate`.
```

Env vars override config at runtime: `YOLONOT_CODEX_RISK_MODERATE=deny` (single shell session only).

### `/yolonot judges [add|remove|move] [...]` — The judge chain

The chain is the ordered list of judges in `~/.yolonot/config.json` (`judges`). Entries are `fast_allow` (built-in Go bash parser, no subprocess), `exec:<path>` (an external hook binary: dippy, a local classifier, any PreToolUse-compatible program) or a model name from the `models` catalog (a typed decision model like TypeSafe Jev or Cloudflare Clef, or a chat model). The first judge whose verdict is permitted wins; by default `fast_allow` and `exec:` judges may only allow, models may allow or ask. An entry can be an object `{"use": "<name>", "may": ["allow"]}` to narrow what that judge may decide; a verdict outside `may` is dropped and the next judge runs. Rules and session memory run before the chain; escalation and the risk map run once after it.

**Read-only — run directly:** `yolonot judges` (lists entries in execution order with kind and permitted decisions), `yolonot models` (the catalog: name, chat/typed, model id, whether the API key env var is set), `yolonot models test <name>` (one live request).

**Mutation — print, do not run.** Print the command for the user:

```
Run this when you're ready:

    yolonot judges add fast_allow

What it does: appends the built-in bash parser to the chain. Skips model calls for syntactically safe commands. Remove with `yolonot judges remove fast_allow`; reorder with `yolonot judges move fast_allow up`.
```

Other mutating forms: `yolonot judges add exec:/opt/homebrew/bin/dippy`, `yolonot judges add <model-name>`, `yolonot judges remove <n|entry>`, `yolonot judges move <n|entry> up|down`, `yolonot models add` (chat; interactive picker, then a name, then a connection test and an offer to append it to the chain), `yolonot models add typed` (TypeSafe Jev, OpenRouter System One, OpenAI Decisions, Cloudflare Workers AI Clef, or a custom System One URL), `yolonot models remove <name>` (refused while the name is in the chain or used for escalation). The same catalog and chain are editable in `yolonot config`, where exec hooks are listed under MODELS with Test / Replace path / Remove.

External hooks receive the standard Claude Code PreToolUse JSON on stdin and must return a standard hook response on stdout within 3 seconds. Only `permissionDecision: "allow"` short-circuits; `ask`/`deny`/empty/timeout/error all fall through to the next judge. A yolonot deny rule always beats a judge allow. Their decisions show in logs as `exec:<basename>`.

A typed decision model does not read the chat prompt. It answers a fixed set of questions (risk tier plus nine yes/no conditions); `context`, `allow_hints` and `ask_hints` are appended to its input as "Project context / Allow when / Ask when" sections and one condition fires when an ask hint describes the command. `system_prompt` only affects chat models.

**`fast_allow` details.** Only fires when the command parses cleanly and contains no command substitution, no redirect except to `/dev/null` (or paths matched by `allow-redirect` rules — see below), no chaining, no subshell, no prefix assignment, and the head command (or `git <sub>` / `docker <sub>` / etc.) is in the built-in allowlist. Multiplex-tool config-injection flags (`git -c`, `git --config-env`, `docker --config`, `kubectl --kubeconfig`, `helm --kube-apiserver` / `--kube-ca-file`, `aws --ca-bundle`, `npm --userconfig` / `--globalconfig`) are rejected — they can execute arbitrary code. Anything else falls through to the next judge. Decisions show up as `fast_allow`, `exec:<hook>` or the model name in logs and stats.

### Rule file syntax — messages, redirects, walk-up

**Per-rule messages.** Any rule accepts a trailing `"quoted"` message. When the rule fires, that message is what Claude Code sees in `permissionDecisionReason`. The opening quote must be whitespace-preceded; embedded quotes escape with `\"`.

```
deny-cmd  *rm -rf /*      "Never. This kills production."
deny-cmd  *force-push*    "We don't force-push shared branches."
ask-cmd   *curl *         "Confirm the URL is intentional."
allow-cmd git status      "read-only inspection"
```

**`allow-redirect`** declares write targets that should not kick a command out of the `fast-allow` path. Patterns are globs matched against the **literal** redirect target only (`$VAR`/`$(...)` targets are never matched — still rejected):

```
allow-redirect /tmp/*
allow-redirect ./dist/*
allow-redirect ./build/**
```

`deny-redirect` and `ask-redirect` are accepted by the parser for forward-compat but are not yet enforced — use `deny-cmd *> /etc/*` for now.

**Walk-up discovery.** yolonot loads `.yolonot` from cwd upward, stopping at the git repo root or `$HOME` (outside a git repo, only the cwd file). Closer files win first-match. Commit a repo-root `.yolonot` with team defaults; let subdirs loosen as needed.

### Classifier hints — `context`, `allow-hint`, `ask-hint`

`.yolonot` files also accept prose hints that get injected into the LLM classifier's system prompt. Unlike rules, hints are **not pattern-matched** — the model reads them verbatim and uses them to classify commands the rules don't cover.

```
context     "cvp service runs in namespace staging (non-prod) and api (prod)"
allow-hint  "kubectl read/exec/edit on namespace staging is routine"
ask-hint    "any kubectl write against namespace api requires confirmation"
```

Hints stack across the walk-up chain (no first-match — union) and merge with prompt hints in `~/.yolonot/config.json` (`prompt.context` / `prompt.allow_hints` / `prompt.ask_hints`). Inspect the resolved merged set with `yolonot prompt config` (read-only); audit for ambiguity / redundancy with `yolonot prompt review`. See `docs/prompt.md` for the full schema and the `$defaults` sentinel.

**Skill behavior — hints are AI-suggest-only.** When the user asks the assistant to "add a hint" / "tell yolonot about this namespace" / similar, the assistant must:

1. Ask scope (project `.yolonot` vs `~/.yolonot/config.json`) and type (`context` / `allow-hint` / `ask-hint`). No silent default.
2. **Print** the line(s) for the user to append. Mutation — do not run.

```
Append to .yolonot:

    allow-hint  "kubectl read/exec on namespace staging is routine"

What it does: nudges the LLM classifier toward `allow` on commands matching this
description. Reversible — delete the line.
```

Never invoke `Edit`, `Write`, `tee >>`, or `echo >>` against `.yolonot`, `~/.yolonot/rules`, or `~/.yolonot/config.json`. Read-only inspection (`yolonot prompt config`, `yolonot prompt review`) may be invoked directly.

The interactive way to author global hints is the PROMPT section of `yolonot config` (each list opens in `$EDITOR`, one entry per line, `$defaults` kept). That is a mutation too: print `yolonot config`, do not run it.

### `/yolonot quiet [on|off]` — Silence allow banners

Toggle whether yolonot emits a `systemMessage` banner for allow decisions. When `on`, only ask/deny decisions show a banner — allows pass through silently.

**Read-only — run directly:** `yolonot quiet` (show current state).

**Mutation — print, do not run.** Print:

```
Run this when you're ready:

    yolonot quiet on

What it does: silences the systemMessage banner for `allow` decisions. Reverse with `yolonot quiet off`.
```

Only affects the user-facing banner. `permissionDecision` + `permissionDecisionReason` + the decision log are unchanged.

### `/yolonot init` — Create rule files

**Mutation — print, do not run.** `init` creates / writes config and rule files; the user runs it.

Print:

```
Run this when you're ready:

    yolonot init

What it does: creates `~/.yolonot/rules` (global) and `.yolonot` in the cwd (project) if missing. Both contain only commented examples; nothing is enabled until the user uncomments a line. Existing files are left alone.
```

Below is the exact behavior of `init` — explanatory only:

1. **Global rules** (`~/.yolonot/rules`): a header explaining that read-only commands are cleared by `fast_allow` and everything else by the judges, then commented examples (`deny-cmd *rm -rf /*`, `deny-cmd *sudo *`, `ask-cmd *curl *`, `allow-cmd npm test*`) and commented `sensitive` patterns (`.ssh/`, `.aws/`, `.env`, `id_rsa`).
2. **Project rules** (`.yolonot` in cwd): commented `allow-path scripts/*` style lines plus commented stack-specific examples detected from the project (`pyproject.toml`, `package.json`, `go.mod`, `Dockerfile`, `k8s/`/`helm/`, `deploy/`/`infra/`).
3. Prints `Created <path> (examples only, nothing enabled)` per file. `yolonot setup` runs `init` as its second step.

## NOTES

- Use `yolonot <cmd> --current` for pause/resume (resolves via most recent session file)
- For reading session state directly, use `$CLAUDE_SESSION_ID` if set, otherwise the most recently modified `.approved` or `.asked` file
- For partial match in approve/deny: match if stored command contains user's input as substring
- All session files live in `~/.yolonot/sessions/`
- Session files are project-scoped: `{SESSION_ID}_{PROJECT_HASH}.{approved,asked,denied}` — a command approved in project A is NOT auto-approved in project B. Pause is session-wide (not project-scoped).
- Session similarity runs once before the first model judge and pre-filters approved commands by executable prefix before calling the chat model. If no approved commands share the same executable, the LLM similarity call is skipped entirely.
- When the LLM is unavailable or returns unparseable output, yolonot emits a systemMessage: "yolonot: LLM unreachable, falling back to host permissions" instead of silently falling back.
- Per-harness risk → action policy (set via `yolonot risk`) decides what each tier does. Defaults ship with the binary; `policy.harness.<name>.risk_map` in `~/.yolonot/config.json` and `YOLONOT_<HARNESS>_RISK_<TIER>` env vars override.
- Display commands truncated to 80 chars with `...` if longer
- NEVER auto-modify rules without user confirmation
- NEVER read tool_response content from audit logs (privacy)
- `.yolonot` rule format: `allow-cmd <pattern>`, `deny-cmd <pattern>`, `ask-cmd <pattern>`, `allow-path <pattern>`, `deny-path <pattern>`, `ask-path <pattern>`
- `suggest` reads only `~/.yolonot/decisions.jsonl`; the user's answers to asks are the `layer: "human"` entries there
- Config file is `~/.yolonot/config.json`, v1 shape: `models` (catalog by name), `judges` (ordered chain), `escalation`, `prompt`, `policy` (`profile`, `profiles`, `harness` pins), `quiet_on_allow`, `attach_outside_root`. A 0.x file still loads; `yolonot migrate` rewrites it (`--dry-run` prints, `--undo` restores `.bak`)
- Model response schema (returned by a chat model, consumed by the hook; typed decision models are folded into the same shape):
  ```json
  {"decision":"allow|ask","risk":"safe|low|moderate|high|critical","short":"≤6-word banner","reasoning":"one sentence","compared_to":"optional"}
  ```
  `decision` is a 2-class label; `risk` is a 5-tier categorical tag (reversibility × blast radius). The active harness's RiskMap maps tiers to final actions (allow/ask/deny/passthrough). `deny` never originates from the LLM decision field — it comes from rules or from the risk map. Legacy outputs that emit `confidence` instead of `risk` are mapped to a tier for backward compatibility. Unparseable output falls through to the host's native permission prompt.
- Escalation (optional second-opinion model, `yolonot escalation`): when the primary classifier's verdict would surface an ask (never confident allows, never `critical`), a configured bigger model re-judges the same prompt once. Adoption guardrails are hard-coded: rescue only on an explicit `allow` + `safe`/`low` verdict; a more dangerous tier hardens the verdict upward; any escalation error keeps the primary ask. `escalation on|off|setup` are mutations (print, don't run); bare `escalation` and `escalation test` are read-only. Decision log lines carry `escalation_*` fields and `⤴esc` markers; `yolonot stats` shows fired/rescued/hardened counters.
