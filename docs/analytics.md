# Analytics and logging

yolonot records every decision to `~/.yolonot/decisions.jsonl` with timestamp, decision, layer that produced it, and LLM timing where applicable. Three tools surface that data.

When [escalation](providers.md#escalation-second-opinion-model) is configured, each affected line also carries the full second-opinion record — built for post-mortems of unattended runs: `escalated`, `escalation_model`, `escalation_decision`, `escalation_risk`, `escalation_reasoning` (truncated), `escalation_ms`, `escalation_error` (`timeout`/`api`/`transport`/`parse`), `escalation_outcome` (`rescued`/`hardened`/`kept`/`error`/`skipped:<reason>`), and `primary_risk` (the pre-adoption tier when a verdict was adopted). Cache replays of an escalation-earned verdict keep `escalated: true` so provenance survives.

## Human ask resolutions

When yolonot answers "ask", the final verdict belongs to the user. That verdict is logged as its own entry with `layer: "human"`:

- `decision: "allow", source: "ask_approved"` — the command ran after an ask (the host's PostToolUse event fired), meaning the user approved it.
- `decision: "deny", source: "ask_rejected"` — the user rejected the ask. This is inferred: the command was asked, never ran, and the agent retried it. A rejection the agent never retries is not observed.

These entries are labels, not gate decisions — `yolonot stats` reports them on a separate "Ask resolutions" line and keeps them out of the allow/ask/deny percentages. They give `yolonot suggest` (and any future learning on top of the log) ground truth about what the user actually decided, rather than only what yolonot decided.

## `yolonot log`

Shows recent decisions with the reason string, layer (rule / session / cache / LLM / fast_allow / pre_check), and LLM latency. Decisions where the [escalation model](providers.md#escalation-second-opinion-model) fired carry a `⤴esc` marker with the escalation latency.

```bash
yolonot log
yolonot log --limit 50
```

Useful when you want to understand why a specific command was allowed/asked/denied.

## `yolonot stats`

Aggregate view. Shows:

- Total decisions.
- Allow / ask / deny percentages.
- Layer distribution (rule / session / cache / LLM / fast_allow / pre_check).
- Average LLM latency.
- Instant allows (no LLM needed).
- Escalation counters when configured: fired / rescued (rescue-%) / hardened / errors / average latency — the numbers that say whether the second model is earning its keep.
- Top asked commands (candidates for permanent rules).
- Per-project breakdown.

```bash
yolonot stats
```

## `yolonot suggest`

Analyzes your decision history and suggests permanent rules for commands you've approved (or rejected) repeatedly. Good way to turn session decisions into durable `.yolonot` rules.

```bash
yolonot suggest
```

## Quiet mode

By default yolonot emits a short banner for every decision (`yolonot: 🧑‍🚀 <reason>`). If you only want to hear from yolonot when it blocks or asks, turn allow banners off:

```bash
yolonot quiet          # show current state
yolonot quiet on       # silence allow banners (ask/deny still show)
yolonot quiet off      # restore default
```

Quiet mode only affects the user-facing `systemMessage`. The underlying `permissionDecision` + `permissionDecisionReason` still flow to the host CLI, and the decision log is unchanged — so `yolonot log` / `yolonot stats` stay accurate.
