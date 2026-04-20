# Analytics and logging

yolonot records every decision to `~/.yolonot/decisions.jsonl` with timestamp, decision, layer that produced it, and LLM timing where applicable. Three tools surface that data.

## `yolonot log`

Shows recent decisions with the reason string, layer (rule / session / cache / LLM / fast_allow / pre_check), and LLM latency.

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
