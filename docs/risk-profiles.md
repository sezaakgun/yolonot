# Risk profiles

A **profile** is a named bundle of tier→action decisions. Pick one with `yolonot profile use <name>` instead of editing tiers cell-by-cell. Profiles set the baseline; per-cell `risk` overrides and env vars still win on top.

## Built-in profiles

| Profile | safe | low | moderate | high | critical | Use when |
|---------|------|-----|----------|------|----------|----------|
| `fast` | allow | allow | allow | **deny** | **deny** | You want skip-permissions speed but still want yolonot to block prod-breaking / irreversible actions. **No ask prompts** anywhere — only allow or deny. See caveats below. |
| `balanced` | allow | allow | ask | ask | deny | Default. Auto-allow safe/low, ask on anything riskier, hard-deny critical. |
| `strict` | allow | ask | ask | deny | deny | Cautious. Ask earlier; never auto-allow on `low`; hard-deny on high. |
| `paranoid` | ask | ask | deny | deny | deny | Lockdown. Ask even on read-only commands; deny anything past local writes. |

### `fast` profile caveats — read before enabling

`fast` collapses `safe`/`low`/`moderate` to `allow` and only blocks `high`+`critical`. The tier itself is assigned by the LLM classifier, which is stochastic. Real-world commands that *should* land at `high` but the classifier may tag `moderate` (silently allowed under `fast`):

- `docker push`, `npm publish`, `pip upload`, `gh release create` — irreversible publish to a remote registry.
- `kubectl apply -f` against a namespace not obviously named "prod".
- `terraform apply` against a non-prod-named workspace.
- `aws s3 cp`, `gcloud storage cp` of local data to a remote bucket.
- `curl -X POST` / `gh api` mutating external APIs.

If you run any of these regularly, either pin them via deny-rules in `~/.yolonot` (rules beat the classifier, always) or use `balanced`/`strict` which fall back to `ask` on `moderate`. Use `fast` for short, well-scoped sessions on disposable infra — not as a long-running global default.

### Per-harness translation

Profiles use the canonical action set `{allow, ask, deny}`. Harnesses without a real `ask` primitive (Codex, Cursor, OpenCode) translate at apply time:

- **Claude / Gemini** — `ask` stays `ask` (real TUI prompt).
- **Codex / Cursor** — `ask` on safe/low/moderate → `passthrough` (host's native engine prompts); `ask` on high+critical → `deny`.
- **OpenCode** — `ask` on safe/low/moderate → `allow` (no native prompt path); `ask` on high+critical → `deny`.

This keeps each harness's safety floor identical to its shipped defaults while letting you swap policy with one command.

## Commands

```bash
yolonot profile                                    # show active profile + per-harness overrides
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
yolonot profile delete lab     # refuses while active; switch first
```

Custom profiles use the same `{allow, ask, deny}` action set as built-ins; `passthrough` is a per-harness translation result, not something profile authors write.

## Per-session via env vars

Profiles can be pinned for a single shell session without touching config:

```bash
YOLONOT_PROFILE=fast claude                  # global, this session only
YOLONOT_CLAUDE_PROFILE=strict claude         # per-harness, this session only
```

Env pins beat config and die with the shell. Useful for one-off "go fast on this branch" or CI pipelines that want lockdown.

## Mid-session via session pin

Sometimes you want to switch profile **after** Claude Code is already running — env vars set in your shell now won't reach the hook. Use a session pin:

```bash
yolonot profile use fast --session     # apply to current Claude session
yolonot profile reset --session        # clear the pin
```

Inside Claude, ask the assistant to run `/yolonot profile use fast --session`. The pin is a marker file in `~/.yolonot/sessions/<id>.profile`; it survives across hook invocations within the running session and is swept when the session ends (`CleanOldSessions`). Session pin beats env vars and config.

## Resolution order

`ResolveActiveProfile` resolves the profile name, highest precedence last:

1. `DefaultProfileName` (`balanced`)
2. `Config.Profile` (global, persistent)
3. `YOLONOT_PROFILE` env (global, per-session)
4. `Config.ProfileOverride[<harness>]` (per-harness, persistent — beats global env because more-specific wins at same scope)
5. `YOLONOT_<HARNESS>_PROFILE` env (per-harness, per-session)
6. Session pin file (mid-session, dies with session)

`ResolveRiskMap(harness)` then layers, highest precedence last:

1. Harness shipped default (`Harness.RiskMap()`).
2. Active profile (resolved above), translated through the harness's ask-fallback rules.
3. `~/.yolonot/config.json` `risk_maps` per-cell override for that harness.
4. `YOLONOT_<HARNESS>_RISK_<TIER>=<action>` env vars.

This means profile changes are non-destructive: any per-cell tweak you've already made via `yolonot risk <harness> <tier> <action>` keeps winning.
