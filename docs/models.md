# Models

Every model yolonot can call lives in one catalog, `models` in
`~/.yolonot/config.json`, keyed by a short name you choose. Judges and the
escalation step refer to models by that name, and the name is what you see
in banners (`🧑‍🚀 gemini -> npm test`) and in `decisions.jsonl` (`layer`).

```json
"models": {
  "jev":      {"url": "https://openrouter.ai/api/v1/systemone",        "model": "typesafe/jev-1.13",            "env_key": "OPENROUTER_API_KEY"},
  "gemini":   {"url": "https://openrouter.ai/api/v1/chat/completions", "model": "google/gemini-2.5-flash-lite", "env_key": "OPENROUTER_API_KEY", "timeout": 30},
  "deepseek": {"url": "https://openrouter.ai/api/v1/chat/completions", "model": "deepseek/deepseek-v4-flash",   "env_key": "OPENROUTER_API_KEY", "timeout": 30}
},
"judges": ["fast_allow", "jev", "gemini"],
"escalation": {"model": "deepseek"}
```

A model is **chat** or **typed**, decided by its URL: a System One
(`/systemone`) or OpenAI Decisions (`/decisions`) endpoint is typed, anything
else is chat. Chat models judge with a prompt and also power session
similarity, `yolonot suggest` and `yolonot prompt review`. Typed models answer
fixed questions with probabilities and cannot generate text.

```bash
yolonot models                 # list: name, kind, model id, key status, role
yolonot models add             # pick a chat provider, then name it
yolonot models add typed       # pick a typed decision endpoint, then name it
yolonot models test <name>     # connection test, exit 0/1
yolonot models remove <name>   # refused while a judge or escalation uses it
```

Names: lowercase letters, digits, `. _ : -`. Reserved: `fast_allow`, `exec`
and the fixed layer names (`rule`, `session`, `cache`, `human`, …). API keys
are never written to disk; `env_key` names the variable to read.

## Chat providers

| Provider | Cost | Per-command latency | Notes |
|----------|------|--------------------:|-------|
| **OpenAI** (`gpt-5.4-mini`) | ~10¢/day | ~500ms | Fastest chat model. Needs `OPENAI_API_KEY`. |
| **OpenRouter** (free models) | ~10¢/day | 500ms–3s | Broad model choice. Needs `OPENROUTER_API_KEY`. |
| **Ollama** (`gemma4:e4b`) | free | 2–10s | Local, no API key. `brew install ollama && ollama pull gemma4:e4b`. |
| **Claude Code** (default) | free | ~10s | Uses your Claude subscription, no API key, but slowest. |
| **Anthropic (API)** | pay-per-token | ~1s | Needs `ANTHROPIC_API_KEY`. |
| **xAI** | pay-per-token | ~1s | Needs `XAI_API_KEY`. Grok models. |
| **Custom** | — | — | Bring your own OpenAI-compatible endpoint. |

### Models and timeouts

| Provider | Models (primary / escalation suggestions) | Timeout |
|----------|-------------------------------------------|---------|
| Claude Code | claude-haiku-5-5, claude-sonnet-5-5 / claude-opus-5-5 | 30s |
| OpenAI | gpt-6-luna, gpt-5.6-luna, gpt-5.4-mini / gpt-6.1-sol, gpt-6-sol | 10s |
| Anthropic (API) | claude-haiku-5-5, claude-sonnet-5-5 / claude-opus-5-5 | 10s |
| xAI | grok-4.3, grok-4.20-0309-non-reasoning / grok-4.7, grok-4.6 | 10s |
| Ollama | any installed model (recommended: gemma4:e4b) | 30s |
| OpenRouter | free models fetched live (primary); type any model ID for escalation | 30s |
| Custom | any URL | 10s |

Timeouts are set per provider at add time and stored in the entry's `timeout`.

## Env vars

| Var | Purpose |
|-----|---------|
| `YOLONOT_DISABLED=1` | Hook is a no-op for this environment |
| `YOLONOT_HARNESS` | Pin the harness adapter (claude, codex, opencode, gemini, cursor) |
| `YOLONOT_PROFILE`, `YOLONOT_<HARNESS>_PROFILE` | Risk profile for this session (see [risk-profiles.md](risk-profiles.md)) |
| `YOLONOT_<HARNESS>_RISK_<TIER>` | One tier → action cell for this session |
| `YOLONOT_ESCALATION=off` | Disable escalation for this environment |
| `YOLONOT_ESCALATION_UNRESOLVED=deny` | Fail a post-escalation residual ask closed (headless runs) |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `XAI_API_KEY` / `OPENROUTER_API_KEY` / `TYPESAFE_API_KEY` | Provider auth, named per model by `env_key` |

Model endpoints are config only; there is no env override for a model's URL
or id. Edit the catalog with `yolonot models` or `yolonot config`.

## Judges

The chain that decides is a list of names: `fast_allow`, `exec:<path>`, or a
model from the catalog. See [judges.md](judges.md).

## Typed decision models

A decision model does not generate text. It answers typed questions with
calibrated probabilities: a risk-tier choice plus nine independent yes/no
conditions (production mutation, destructive, secrets read, exfiltration,
redirect write, persistence, obfuscated code, unclear effect, and whether
one of your `ask_hints` describes the command). The verdict
is `ask` when any condition is at or above 0.5 or the tier is
`high`/`critical`; the fired conditions become the reason text.

Presets in `yolonot models add typed` (all verified live against the yolonot
question set):

| Endpoint | Models | Key | Schema |
|----------|--------|-----|--------|
| [TypeSafe Jev](https://docs.typesafe.ai) | `jev-latest` | `TYPESAFE_API_KEY` | System One |
| OpenRouter (`/api/v1/systemone`) | `typesafe/jev-1.13`, `microsoft/microsoft-decision-1` | `OPENROUTER_API_KEY` | System One |
| OpenAI Decisions API (`/v1/decisions`) | `gpt-6-luna` | `OPENAI_API_KEY` | OpenAI (translated: predicate questions, choices array) |
| Cloudflare Workers AI (`/ai/run/@cf/cloudflare/…`) | `clef-flash`, `clef` | `CLOUDFLARE_API_TOKEN` + account id | System One inside the Workers AI envelope |
| Custom | any | any | System One |

Open-weight decision models that serve the System One API locally work
through "Custom": [Kev](https://huggingface.co/jaredpalmer/kev-4b) (Qwen3.5
LoRA, MLX on Apple Silicon, `python -m kev.serve`),
[Clef](https://huggingface.co/Cloudflare/clef-flash) via SGLang. Point the URL at `http://127.0.0.1:<port>/v1/systemone`.

`yolonot setup` step 3b offers TypeSafe Jev. A typed entry looks like any
other catalog entry; the `/systemone` or `/decisions` URL makes it typed:

```json
"jev": {"url": "https://api.typesafe.ai/v1/systemone", "model": "jev-latest", "env_key": "TYPESAFE_API_KEY"}
```

Measured on the shipped greenfield suite (176 cases, one run): 92.0%
decision accuracy, 100% dangerous catch, zero errors, ~300ms p50 — against
88.1% for `gemini-2.5-flash-lite` and 80.1% for `deepseek-v4-flash`.

What a decision model does not do:

- `system_prompt` is not sent to it; the tier and condition criteria are
  fixed in code. `context`, `allow_hints` and `ask_hints` (config and
  `.yolonot` walk-up) are appended to the command as "Project context",
  "Allow when" and "Ask when" sections; the ninth condition fires when an
  "Ask when" line matches, and "Allow when" lines tell the model what this
  project treats as routine.
- Session similarity compare (`session_llm`), `yolonot suggest` smart
  mode and `yolonot prompt review` use the first chat model in the chain;
  with no chat model they are skipped or refuse with a clear message.
- It is never offered as the escalation model.

For eval: `--model <catalog name>` runs a suite against any configured
model; `--model jev-latest` (TypeSafe), `--model systemone/<id>`
(OpenRouter, e.g. `systemone/microsoft/microsoft-decision-1`) and
`--model decisions/gpt-6-luna` (OpenAI) need no catalog entry.

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
yolonot escalation setup   # pick a chat model from the catalog, or add one
yolonot escalation         # status: model, trigger, recent fire/rescue counts
yolonot escalation off     # keep config, disable
yolonot escalation test    # non-interactive connection test, exit 0/1 (CI)
```

Config block (`~/.yolonot/config.json`):

```json
{
  "models": {
    "small": { "url": "http://localhost:11434/v1/chat/completions", "model": "small-model" },
    "big":   { "url": "http://localhost:11434/v1/chat/completions", "model": "big-model" }
  },
  "judges": ["fast_allow", "small"],
  "escalation": { "model": "big", "unresolved": "ask" }
}
```

`escalation.model` names a catalog entry; `disabled: true` keeps the
reference but turns the step off (`yolonot escalation off`). Credentials
follow the entry's own `env_key`; nothing is shared between endpoints. Both
models receive the same system prompt and [prompt hints](prompt.md).

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
