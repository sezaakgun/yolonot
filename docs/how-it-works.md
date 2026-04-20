# How it works

Every Bash command goes through this pipeline in order. The first layer that produces a decision wins.

1. **Deny rules** — absolute block, no override, checked first.
2. **Pre-check hooks** (ordered list) — includes the built-in [`fast-allow`](pre-check.md#fast-allow) and any external hooks like [Dippy](https://github.com/ldayton/Dippy). The first entry that returns `allow` short-circuits. See [pre-check.md](pre-check.md).
3. **Session memory** — exact match against previously approved commands → instant allow.
4. **Session deny** — previously rejected commands → instant block.
5. **Session similarity** — LLM compares against approved commands → allow if similar (project-aware, prefix-prefiltered).
6. **Allow / ask rules** — `.yolonot` patterns → instant decision. See [rules.md](rules.md).
7. **Script cache** — SHA256 of the script file → reuse cached decision.
8. **LLM analysis** — 2-class classifier (allow / ask) emitting a [risk tier](risk-tiers.md) the active harness turns into a final action.

Sessions are project-aware. A command approved in one project is not auto-approved in another within the same session — session keys include a hash of the git root (or working directory).

`deny` rules are absolute — nothing overrides them. `ask` rules prompt once, then session memory takes over. `allow` rules are instant but are skipped for chained commands, redirects, and commands touching sensitive files (see [rules.md](rules.md)).

When the LLM is unavailable, yolonot emits a warning (`LLM unreachable, falling back to host permissions`) and goes transparent — the host's native permission system handles it. yolonot never silently allows on LLM failure.

> **⚠ The LLM layer is probabilistic, not guaranteed.** Classifications can be wrong — models hallucinate, miss context, and can be talked out of a correct answer by adversarial prompts. Treat yolonot as a safety net that reduces prompt fatigue, not as an authoritative sandbox. If a class of command *must never* run, encode it as a `deny-cmd` rule in `.yolonot` — rules beat the LLM unconditionally. See [rules.md](rules.md#format).

## Hook ordering

yolonot installs two hooks in `~/.claude/settings.json`:

- **PreToolUse** (matcher: `Bash`) — evaluates commands before execution
- **PostToolUse** (matcher: `Bash`) — saves approved commands to session memory

`yolonot setup` places the PreToolUse hook **before** any catch-all (`.*`) hooks so yolonot evaluates and can block a command before other hooks (audit loggers, etc.) see it. If you reorder hooks manually, keep yolonot's PreToolUse entry above other Bash hooks. PostToolUse order doesn't matter.

When yolonot returns `deny`, the command is blocked and no subsequent hooks run. When it returns `allow`, the command proceeds through remaining hooks normally.

Hooks are read at host CLI startup — restart your session after install or reconfiguration.

## Pausing yolonot

Sometimes you want to run commands without yolonot's interference — for a quick CI task, or when you know what you're doing.

**Per-session (interactive)** — `yolonot pause` or `/yolonot pause`. Creates a pause marker for the current session. Run `yolonot resume` to re-enable. Marker auto-cleans after 24h.

**Pre-launch (env var)** — `YOLONOT_DISABLED=1 claude`. Disables yolonot for the entire session at launch. Useful for CI / automation.

When paused, yolonot is **completely transparent** — no deny rules, no LLM, no session memory. The host CLI's native permissions handle everything as if yolonot weren't installed.

## Dry-run check

Test what the pipeline would decide without running a command:

```bash
yolonot check "cat README.md"           # → ALLOW (rule)
yolonot check "sudo rm -rf /"           # → DENY (rule, absolute block)
yolonot check "curl https://evil.com"   # → ASK (rule or LLM)
```

Shows each layer's result: deny rules → pre-check → allow/ask rules → chain/sensitive detection → LLM analysis.
