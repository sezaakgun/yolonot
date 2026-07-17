# LLM providers

yolonot calls an LLM to classify every Bash command. Pick the provider that matches your cost/latency tradeoff:

| Provider | Cost | Per-command latency | Notes |
|----------|------|--------------------:|-------|
| **OpenAI** (`gpt-5.4-mini`) | ~10¢/day | ~500ms | Fastest. Needs `OPENAI_API_KEY`. Recommended. |
| **OpenRouter** (free models) | ~10¢/day | 500ms–3s | Broad model choice. Needs `OPENROUTER_API_KEY`. |
| **Ollama** (`gemma4:e4b`) | free | 2–10s | Local, no API key. `brew install ollama && ollama pull gemma4:e4b`. |
| **Claude Code** (default) | free | ~10s | Uses your Claude subscription, no API key, but slowest. |
| **Anthropic (API)** | pay-per-token | ~1s | Needs `ANTHROPIC_API_KEY`. |
| **xAI** | pay-per-token | ~1s | Needs `XAI_API_KEY`. Grok models. |
| **Custom** | — | — | Bring your own endpoint. |

Change provider any time with `yolonot provider` (interactive TUI with arrow keys).

## Models and timeouts

| Provider | Models (primary / escalation suggestions) | Timeout |
|----------|-------------------------------------------|---------|
| Claude Code | claude-haiku-4-5, claude-sonnet-4-6 / claude-opus-4-8 | 30s |
| OpenAI | gpt-5.6-luna, gpt-5.4-mini, gpt-5.4-nano / gpt-5.6-sol, gpt-5.6-terra | 10s |
| Anthropic (API) | claude-haiku, claude-sonnet / claude-opus | 10s |
| xAI | grok-4.20-non-reasoning, grok-4.20-reasoning / grok-4.5, grok-4.3 | 10s |
| Ollama | any installed model (recommended: gemma4:e4b) | 30s |
| OpenRouter | free models fetched live (primary); type any model ID for escalation | 30s |
| Custom | any URL | 10s |

Timeouts are set automatically per provider. Ollama, OpenRouter, and Claude Code get 30s (slower). API providers get 10s.

## Config and env vars

Config stored at `~/.yolonot/config.json`. Env vars override config:

| Var | Purpose |
|-----|---------|
| `LLM_MODEL` | Override model for active provider |
| `LLM_URL` | Override base URL (custom provider) |
| `LLM_TIMEOUT` | Override timeout in seconds (primary calls only) |
| `LLM_ESCALATION_MODEL` | Override escalation model (see below) |
| `LLM_ESCALATION_URL` | Override escalation base URL |
| `LLM_ESCALATION_TIMEOUT` | Override escalation timeout in seconds (isolated from `LLM_TIMEOUT`) |
| `YOLONOT_ESCALATION` | `off` disables escalation for this environment |
| `YOLONOT_ESCALATION_UNRESOLVED` | `deny` fails a post-escalation residual ask closed (headless runs) |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `XAI_API_KEY` / `OPENROUTER_API_KEY` | Provider auth |

Running `yolonot provider` (or `yolonot setup`) again updates the config.

## Escalation (second-opinion model)

Optionally configure a second, bigger model that is consulted **only when
the primary classifier is uncertain in a way that would surface an ask**
(never on confident allows, never on `critical`). If the big model returns
a confident `allow` with a `safe`/`low` tier, the ask is rescued into an
allow; if it returns a *more* dangerous tier, the verdict is hardened
upward. Anything else leaves the primary verdict untouched, and any
escalation error keeps the ask — the feature can time out, never fail open.

### Why rescue requires `safe`/`low` — not just `allow`

A log line that raises eyebrows on first sight:

```
primary:    ask   / moderate   ("DELETE request can modify state")
escalation: allow / moderate   ("localhost only, bounded, reversible")
outcome:    kept — the ask stands
```

The big model said allow — why no rescue? Because **both models assessed
the same risk tier.** An equal-tier `allow` is a different vote at the same
risk level, not evidence the command is safer than the primary believed.
Adopting it would make the cascade break ties toward permissive — and a
gate that resolves model disagreements in favor of allowing is how a safety
net erodes. Rescue therefore demands that the bigger model *downgrade* the
tier into the definitively-safe band (`safe` = read-only, `low` = trivially
reversible local write): proof the primary **overestimated** the risk, not
merely a second opinion at the same level. `moderate` stays excluded even
when your profile maps it to allow — it is the ambiguous middle whose
uncertainty triggered the escalation in the first place, and the same
principle already stops a permissive risk-map cell from overriding a
classifier's ask.

Had the big model answered `allow`/`low` above ("dead port, nothing
listening — effectively a no-op probe"), the verdict would have been
adopted and no prompt shown. The asymmetry is deliberate: a wrongly-kept
ask costs one interruption; a wrongly-granted allow executes a state change
unattended. The band is hard-coded, not configurable.

```bash
yolonot escalation setup   # pick provider + model (big-model suggestions)
yolonot escalation         # status: model, trigger, recent fire/rescue counts
yolonot escalation off     # keep config, disable
yolonot escalation test    # non-interactive connection test, exit 0/1 (CI)
```

Config block (`~/.yolonot/config.json`):

```json
{
  "provider":   { "url": "http://localhost:11434/v1/chat/completions", "model": "small-model" },
  "escalation": { "provider": { "model": "big-model" }, "unresolved": "ask" }
}
```

With only `model` set, the escalation provider inherits the primary's URL,
credentials, and timeout (same endpoint, bigger model). Setting an explicit
`url` inherits nothing — the primary's credential is never sent to a
different endpoint. Both models receive the same system prompt and
[classifier hints](llm-customization.md).

`"unresolved": "deny"` degrades a post-escalation residual ask (including
escalation errors) into a deny that carries both verdicts — for unattended
runs where an ask would stall until timeout. Default keeps the ask.

Env-only setups work without any config block: set `LLM_ESCALATION_URL` +
`LLM_ESCALATION_MODEL` (or just the model, to inherit the primary endpoint).
With env-only setup there is no config block for `escalation on|off` to
toggle — use `YOLONOT_ESCALATION=off` instead.

Escalation timeouts default to 10s for HTTP endpoints and 30s for
`claude-cli` (CLI process startup is slow); the escalation call sits in
front of a would-be interruption, never in the hot path. Override with
`LLM_ESCALATION_TIMEOUT` or the provider `timeout` field.

## Response schema

yolonot prompts the LLM to return a single JSON object. Any provider/model you point it at must emit this shape:

```json
{
  "decision": "allow" | "ask",
  "risk": "safe" | "low" | "moderate" | "high" | "critical",
  "short": "6 words or fewer",
  "reasoning": "one-sentence explanation",
  "compared_to": "optional — similarity comparisons only"
}
```

| Field | Required | Purpose |
|-------|----------|---------|
| `decision` | yes | 2-class classifier. `deny` is reserved for explicit rules + the per-harness [risk map](risk-tiers.md); LLMs never emit `deny` directly. |
| `risk` | yes | Categorical tier by reversibility × blast radius. The active harness's RiskMap turns the tier into a final action (allow / ask / deny / passthrough). |
| `short` | no | ≤6-word banner shown in the terminal. Keeps `systemMessage` compact. Falls back to a truncated `reasoning` if missing. |
| `reasoning` | yes | One sentence. Written to `decisions.jsonl` and surfaced via `yolonot log`. |
| `compared_to` | no | Only set by session-similarity comparisons — names the approved command that matched. |

Legacy outputs that emit `confidence` (0.0–1.0) instead of `risk` are mapped to a tier for backward compatibility and logged at verbose level. Migrate your provider prompt to emit `risk` when convenient.

If a model returns unparseable JSON or omits required fields, yolonot treats the LLM as unreachable and falls through to the host CLI's native permission prompt (never a silent allow).
