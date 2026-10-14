# Risk tiers

Every LLM decision carries a risk tier — `safe`, `low`, `moderate`, `high`, `critical` — based on reversibility and blast radius. Each harness has a default tier → action policy (`allow` / `ask` / `deny` / `passthrough`) that you can override per-harness.

## Defaults

| Tier | Claude / Antigravity | Codex / Cursor default | OpenCode V2 | OpenCode V1 |
|---|---|---|---|---|
| safe / low | allow | allow | allow | allow |
| moderate | ask | passthrough | ask | allow |
| high | ask | deny | deny | deny |
| critical | ask | deny | deny | deny |

- `passthrough` means yolonot emits no decision and lets the host's own permission engine handle the command.
- On ask-capable harnesses (Claude, Antigravity), the LLM layer never denies by default — `deny` stays rule-origin only.
- OpenCode V2 supports native asks. Cursor native ask is opt-in; otherwise
  it defers alongside Codex. Native ask support does not relax their existing
  high/critical deny floor. See [harnesses.md](harnesses.md).

## Profiles (recommended starting point)

Most users should pick a [risk profile](risk-profiles.md) instead of editing tiers cell-by-cell:

```bash
yolonot profile use fast        # allow cells through moderate; deny high/critical
yolonot profile use balanced    # ask on moderate+, translated per harness
yolonot profile use strict      # ask earlier, hard-deny on high+
yolonot profile use paranoid    # ask on safe; deny moderate+
```

Profiles set the baseline; per-cell overrides below still win.
An allow cell preserves a model's ask; it does not automatically approve it.

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
