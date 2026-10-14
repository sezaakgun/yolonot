# Risk profiles

A **profile** is a named bundle of tier→action decisions. Pick one with `yolonot profile use <name>` instead of editing tiers cell-by-cell. Profiles set the baseline; per-cell `risk` overrides and env vars still win on top.

## Built-in profiles

| Profile | safe | low | moderate | high | critical | Use when |
|---------|------|-----|----------|------|----------|----------|
| `fast` | allow | allow | allow | **deny** | **deny** | Tier decisions are allow or deny. Host permissions and model-failure behavior still apply. See caveats below. |
| `balanced` | allow | allow | ask | ask | ask | Default. Auto-allow safe/low, ask on anything riskier. Matches the shipped Claude / Antigravity maps; rules (`deny-cmd`) are what hard-block `critical`. |
| `strict` | allow | ask | ask | deny | deny | Cautious. Ask earlier; never auto-allow on `low`; hard-deny on high. |
| `paranoid` | ask | ask | deny | deny | deny | Lockdown. Ask even on read-only commands; deny anything past local writes. |

Profiles translate model risk tiers. Earlier rule, session, parser or exec
allows can decide before a model runs; `paranoid` does not force every tool
call to show a prompt. An allow cell also preserves a model's ask.

### `fast` profile caveats — read before enabling

`fast` maps `safe`/`low`/`moderate` to `allow` and `high`/`critical` to `deny`.
An allow cell does not turn a model's `ask` into allow. The model is still
stochastic: if it returns `allow` with an underestimated tier, policy may let
that judgment through. Commands whose effects deserve closer review include:

- `docker push`, `npm publish`, `pip upload`, `gh release create` — irreversible publish to a remote registry.
- `kubectl apply -f` against a namespace not obviously named "prod".
- `terraform apply` against a non-prod-named workspace.
- `aws s3 cp`, `gcloud storage cp` of local data to a remote bucket.
- `curl -X POST` / `gh api` mutating external APIs.

If you run any of these regularly, pin them via deny-rules in `~/.yolonot/rules`
or choose a stricter profile. See the adapter translation below and the
[failure behavior](security.md) before relying on a profile for unattended work.

### Per-harness translation

Profiles use `{allow, ask, deny}`. Each adapter translates ask according to its
runtime capabilities; host-deferred behavior is not a guaranteed human prompt:

- **Claude / Antigravity** — `ask` stays `ask`.
- **Codex / Cursor** — `ask` on safe/low/moderate → `passthrough` (host permissions decide); `ask` on high+critical → `deny`.
- **OpenCode V2** — `ask` stays ask on safe/low/moderate; high/critical stay
  deny. V1 maps lower-tier asks to allow/host permission handling.
- **Cursor native-ask opt-in** — lower-tier asks stay ask; high/critical stay deny.

This keeps each harness's safety floor identical to its shipped defaults while letting you swap policy with one command.

## Commands

```bash
yolonot profile                                    # show active profile + per-harness overrides
yolonot profile use strict --session-id <id>        # pin the intended conversation
yolonot profile list                               # list built-in + custom profiles
yolonot profile show fast                          # show one profile's tier map
yolonot profile use fast                           # set global profile
yolonot profile use strict --harness=claude        # per-harness override
yolonot profile reset                              # clear global → balanced
yolonot profile reset --harness=claude             # clear one override
```

## Custom profiles

You can define your own. Names must match `[a-z][a-z0-9_-]{0,31}` and cannot collide with built-ins.

```bash
# Clone and tweak:
yolonot profile create my-prof --base=balanced --high=deny

# Fully inline (all 5 tiers required):
yolonot profile create lab \
  --safe=allow --low=allow --moderate=ask --high=deny --critical=deny

yolonot profile use my-prof
yolonot profile delete lab     # refuses while active or pinned by a harness; switch first
```

The same lives in `yolonot config` under POLICY: the active profile with
its five tier rows (changing a tier of a built-in saves a custom copy and
activates it), "Use another / Create new / Delete" on the Profile row, and
a Harness overrides row for per-harness pins and cell overrides.

Custom profiles use the same `{allow, ask, deny}` action set as built-ins; `passthrough` is a per-harness translation result, not something profile authors write.

## Per-session via env vars

Profiles can be pinned for a single shell session without touching config:

```bash
YOLONOT_PROFILE=fast claude                  # global, this session only
YOLONOT_CLAUDE_PROFILE=strict claude         # per-harness, this session only
```

Env pins apply to processes launched with those variables; exporting a new
value does not update an already-running host. More-specific harness pins
and session pins can override a global env pin, as listed below.

## Mid-session via session pin

Sometimes you want to switch profile **after** Claude Code is already running — env vars set in your shell now won't reach the hook. Use a session pin:

```bash
yolonot profile use fast --session-id <id>
yolonot profile reset --session-id <id>
```

The pin is stored in `~/.yolonot/sessions/<id>.profile` and survives hook
invocations. Reset removes it explicitly; stale files become eligible for
cleanup after 24 hours, not immediately when a chat closes. `--session` uses
the host session variable when available and otherwise falls back to the
latest recorded session, which may belong to another chat. Prefer an explicit
ID. Session pins beat env vars and config.

## Resolution order

`ResolveActiveProfile` resolves the profile name, highest precedence last:

1. `DefaultProfileName` (`balanced`)
2. `policy.profile` in `config.json` (global, persistent)
3. `YOLONOT_PROFILE` env (global, per-session)
4. `policy.harness.<harness>.profile` (per-harness, persistent — beats global env because more-specific wins at same scope)
5. `YOLONOT_<HARNESS>_PROFILE` env (per-harness, per-session)
6. Session pin file (explicit reset or stale-file cleanup removes it)

`ResolveRiskMap(harness)` then layers, highest precedence last:

1. Harness shipped default (`Harness.RiskMap()`).
2. Active profile (resolved above), translated through the harness's ask-fallback rules.
3. `~/.yolonot/config.json` `policy.harness.<name>.risk_map` per-cell override for that harness.
4. `YOLONOT_<HARNESS>_RISK_<TIER>=<action>` env vars.

This means profile changes are non-destructive: any per-cell tweak you've already made via `yolonot risk <harness> <tier> <action>` keeps winning.

```bash
yolonot risk                              # merged map for the active harness, with the source of each cell
yolonot risk codex                        # for a named harness
yolonot risk codex high deny              # override one cell (allow|ask|deny|passthrough)
yolonot risk codex reset high             # drop one override
yolonot risk codex reset                  # drop every override for that harness
```

In `config.json` all of this is the `policy` block:

```json
"policy": {
  "profile": "balanced",
  "profiles": {"lab": {"safe": "allow", "low": "allow", "moderate": "ask", "high": "deny", "critical": "deny"}},
  "harness": {"codex": {"profile": "strict", "risk_map": {"high": "deny"}}}
}
```
