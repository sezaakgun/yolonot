# Risk tiers

Every LLM decision carries a risk tier — `safe`, `low`, `moderate`, `high`, `critical` — based on reversibility and blast radius. Each harness has a default tier → action policy (`allow` / `ask` / `deny` / `passthrough`) that you can override per-harness.

## Defaults

| Tier | Claude | Codex / OpenCode | Gemini |
|---|---|---|---|
| safe / low | allow | allow | allow |
| moderate | ask | passthrough | ask |
| high | ask | deny | ask |
| critical | ask | deny | ask |

- `passthrough` means yolonot emits no decision and lets the host's own permission engine handle the command.
- On ask-capable harnesses (Claude, Gemini), the LLM layer never denies by default — `deny` stays rule-origin only.
- Codex / OpenCode have no `ask` primitive in their hook APIs, so `deny` is the only way to block there. See [harnesses.md](harnesses.md) for the upstream limitations.

## Overrides

```bash
yolonot risk                         # show merged map for active harness
yolonot risk claude                  # show for a specific harness
yolonot risk codex moderate deny     # override one cell
yolonot risk codex reset             # drop all user overrides for a harness
yolonot risk codex reset moderate    # drop one override
```

## Env var overrides

Env vars override config at runtime:

```bash
YOLONOT_CODEX_RISK_MODERATE=deny
YOLONOT_CLAUDE_RISK_HIGH=allow
```

Format: `YOLONOT_<HARNESS>_RISK_<TIER>=<action>`. Env vars beat config on every hook invocation, so they are useful for one-off sessions or CI tweaks.
