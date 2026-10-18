# Analytics and logging

yolonot records every decision to `~/.yolonot/decisions.jsonl` with timestamp, decision, layer that produced it, and model timing where applicable. One JSON record per line; multiline commands are stored escaped, so the file is always one record per line even when several hooks write at once. Three tools surface that data.

The `layer` field names what decided: `rule`, `session`, `session_llm` (similarity to an approved command), `session_deny`, `cache`, `fast_allow`, `exec:<hook>`, the model name from your catalog (`jev-1.13`, `gemini-2.5-flash-lite`), the same with `+esc` when the escalation model changed the verdict, `human` for ask resolutions, `oversize`, `timeout` and `passthrough`. Logs written before 1.0 carry the old names (`llm`, `pre_check`); `stats` and `suggest` read both.

When [escalation](models.md#escalation-second-opinion-model) is configured, each affected line also carries the full second-opinion record — built for post-mortems of unattended runs: `escalated`, `escalation_model`, `escalation_decision`, `escalation_risk`, `escalation_reasoning` (truncated), `escalation_ms`, `escalation_error` (`timeout`/`api`/`transport`/`parse`), `escalation_outcome` (`rescued`/`hardened`/`kept`/`error`/`skipped:<reason>`), and `primary_risk` (the pre-adoption tier when a verdict was adopted). Cache replays of an escalation-earned verdict keep `escalated: true` so provenance survives.

## Human ask resolutions

Explicit human resolutions are logged with `layer: "human"`. Native completion
events expose less information than the Claude mod's choice dialog:

- `decision: "allow", source: "ask_approved"` — an explicit remembered approval from CLI approve or a bound mod session grant completed by PostToolUse.
- `decision: "allow", source: "allow_once"` — a mod one-time choice or a completed pending native ask whose scope the host does not expose. It does not establish a session grant. Cursor's ambiguous completion event and ask-less harnesses (e.g. OpenCode V1) do not fabricate this human label.
- `decision: "deny", source: "ask_rejected"` — an explicit mod Deny selection or CLI deny action. An unanswered, cancelled or interrupted ask does not establish a human rejection. Classic hooks without an explicit rejection event cannot record that answer.

A log entry naming a model with `decision: "passthrough"` and `LLM unavailable`
is a failure fallback, not a successful model judgment. Check this when a
command executes despite missing Desktop API keys; see [the host credential
caveat](harnesses.md#claude-desktop-model-credentials).

These entries are labels, not gate decisions — `yolonot stats` reports them on a separate "Ask resolutions" line and keeps them out of the allow/ask/deny percentages. They feed `yolonot suggest` (`approved`, `once`, `rejected` tallies and repeated-ask candidates). See [commands.md](commands.md#suggesting-rules-and-hints-from-your-answers-yolonot-suggest) and [security.md](security.md).

## `yolonot log`

Shows recent decisions with the reason string, layer (rule / session / cache / fast_allow / exec:<hook> / the model name), and model latency. Decisions where the [escalation model](models.md#escalation-second-opinion-model) fired carry a `⤴esc` marker with the escalation latency; calls that requested host sandbox bypass carry `[unsandboxed]` (`bypass_sandbox: true` in `decisions.jsonl`). Multiline commands are shown on one row with `⏎` between lines.

```bash
yolonot log                  # last 20
yolonot log 50               # last 50 (also: yolonot log -n 50)
yolonot log --session current
```

Useful when you want to understand why a specific command was allowed/asked/denied.

## `yolonot stats`

Aggregate view (`--session <id|current>`, `--since today|24h|7d`, `--project <name>`). Shows:

- **Impact summary** at the top:
  - `Auto-approved`: total allowed decisions (and percentage) with a breakdown of instant local allows (`fast_allow`, rules, session memory, cache) vs AI-judged allows.
  - `Speed saved`: estimated prompt interruptions avoided (~5s per instant allow) plus average AI judge latency.
  - `Threats stopped`: total commands blocked (`deny`) or caught (`ask`) by rules, judges, or escalation hardening, followed by up to 5 recent blocked/hardened incidents (`BLOCKED` / `HARDENED`, command, layer, and reason).
- Total decisions and allow / ask / deny percentages (plus `Passthrough` and `Unsandboxed` counts when present).
- Layer distribution (rule / session / cache / fast_allow / exec:<hook> / model names).
- Escalation counters when configured: fired / rescued (rescue-%) / hardened / errors / latency p50 and p90 against the configured timeout.
- Noisy-session diagnostics: main-thread vs subagent asks, commands asked twice in one session, commands the second model answered differently, asks whose script the judge could not see, ask resolutions, top asked commands, and top 10 projects / sessions breakdown.

```bash
yolonot stats
yolonot stats --since today
yolonot stats --session current
```

## `yolonot suggest`

Analyzes your decision history (including human ask resolutions `approved`, `once`, `rejected` and repeated-ask candidates) and suggests permanent `.yolonot` rules or `allow-hint` / `ask-hint` directives.

```bash
yolonot suggest          # interactive TUI picker
yolonot suggest --list   # non-interactive report (also auto-selected when piped / invoked by a skill)
yolonot suggest --json   # structured JSON output
```

## Quiet mode

By default yolonot emits a short banner for every decision (`🧑‍🚀 <layer> -> <command>`, e.g. `🧑‍🚀 fast_allow -> ls -la`). If you only want to hear from yolonot when it blocks or asks, turn allow banners off:

```bash
yolonot config quiet          # show current state
yolonot config quiet on       # silence allow banners (ask/deny still show)
yolonot config quiet off      # restore default
```

The same toggle is the "Quiet on allow" row of `yolonot config`.

Quiet mode only affects the user-facing `systemMessage`. The underlying `permissionDecision` + `permissionDecisionReason` still flow to the host CLI, and the decision log is unchanged — so `yolonot log` / `yolonot stats` stay accurate.
