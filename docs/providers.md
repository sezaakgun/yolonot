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

| Provider | Models | Timeout |
|----------|--------|---------|
| Claude Code | claude-haiku, claude-sonnet | 30s |
| OpenAI | gpt-5.4-mini, gpt-5.4-nano, gpt-4o-mini | 10s |
| Anthropic (API) | claude-haiku, claude-sonnet | 10s |
| xAI | grok-4-1-fast-reasoning, grok-4-1-fast-non-reasoning | 10s |
| Ollama | any installed model (recommended: gemma4:e4b) | 30s |
| OpenRouter | free models fetched live | 30s |
| Custom | any URL | 10s |

Timeouts are set automatically per provider. Ollama, OpenRouter, and Claude Code get 30s (slower). API providers get 10s.

## Config and env vars

Config stored at `~/.yolonot/config.json`. Env vars override config:

| Var | Purpose |
|-----|---------|
| `LLM_MODEL` | Override model for active provider |
| `LLM_URL` | Override base URL (custom provider) |
| `LLM_TIMEOUT` | Override timeout in seconds |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `XAI_API_KEY` / `OPENROUTER_API_KEY` | Provider auth |

Running `yolonot provider` (or `yolonot setup`) again updates the config.

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
