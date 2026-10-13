<p align="center">
  <img src="assets/logo.png" alt="yolonot" width="180">
</p>

<h1 align="center">yolonot</h1>

<p align="center">
  Smart auto-mode for AI coding assistants. The safe alternative to <code>--dangerously-skip-permissions</code>.<br>
  Built for Claude Code. Also works with Codex CLI, OpenCode, Gemini CLI, and Cursor.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://github.com/sezaakgun/yolonot/actions"><img src="https://github.com/sezaakgun/yolonot/actions/workflows/test.yml/badge.svg" alt="Tests"></a>
  <img src="https://img.shields.io/badge/go-1.25+-00ADD8.svg" alt="Go 1.25+">
</p>

---

yolonot sits between your AI coding assistant and your shell. It uses an LLM to classify every Bash command as **safe** (allow) or **needs-review** (ask), with session memory so approved commands don't ask twice and rejected commands stay blocked. Deny rules give you absolute blocks nothing can override. Optionally, an [escalation model](docs/models.md#escalation-second-opinion-model) — a second, bigger LLM — gets one look at uncertain verdicts before you're interrupted: confident false alarms get rescued into allows, sneaky-dangerous ones get hardened, and everything else still asks.

> **Claude Code first.** yolonot was designed for Claude Code and that's where it gets the richest UX (full allow/ask/deny). Cursor, Codex CLI, OpenCode, and Gemini CLI adapters ship in-tree but have upstream hook-API limitations — see [docs/harnesses.md](docs/harnesses.md) for each host's caveats.

> **⚠ LLMs are not deterministic.** yolonot's classifier is a probabilistic safety net, not a guarantee. Models hallucinate, miss context, and can be tricked by adversarial prompts. Use yolonot at your discretion: keep your own judgment in the loop, write **deny rules** for anything you truly never want run (rules beat the LLM, always), and don't treat it as a substitute for reviewing what your AI assistant is doing. If yolonot allows a destructive command, **you** are still the one who installed it on your machine.

## Quick start

### 1. Pick a model

| Model | Kind | Cost | Latency | Key |
|-------|------|------|--------:|-----|
| **TypeSafe Jev** `jev-latest` | typed | <1¢/day | ~300ms | `TYPESAFE_API_KEY` |
| **OpenAI** `gpt-5.4-mini` | chat | ~10¢/day | ~500ms | `OPENAI_API_KEY` |
| **Kev-4B** self-hosted ([Kev](https://github.com/jaredpalmer/kev)) | typed | free | ~40ms on a GPU box, seconds on a laptop | — (local) |
| **Ollama** `gemma4:e4b` | chat | free | 2–10s | — (local) |
| **Claude Code** (default) | chat | free | ~10s | — (subscription) |

Full matrix in [docs/models.md](docs/models.md). Models live in a named catalog; the judge chain and the escalation step refer to them by name. A typed decision model answers in ~300ms and runs before the chat model, which then only sees what it could not decide. The chain can also hold `fast_allow` (a built-in read-only parser) and `exec:<path>` hooks, any binary that reads the PreToolUse JSON; see [docs/judges.md](docs/judges.md). After setup, `yolonot config` opens a settings screen for judges, models, policy and prompt, keyboard or mouse.

### 2. Install and run setup

```bash
go install github.com/sezaakgun/yolonot@latest

# Make sure Go bin is in PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# First-run wizard: hooks + rules + models + judge chain
yolonot setup

# Optional, Claude Code 2.1.296+: verdicts in the transcript, a status row above
# the prompt, and a four-way ask (allow once / this session / explain / deny)
yolonot install --mod
```

Upgrading from 0.x? Your config keeps working; `yolonot migrate` rewrites it in the 1.x shape when you are ready. See [docs/upgrading.md](docs/upgrading.md).

### 3. Restart your host CLI

Hooks are read at startup, so restart Claude Code (or whichever harness you're using) to activate yolonot.

That's it. Every Bash command now runs through [the pipeline](docs/how-it-works.md).

## Docs

| Topic | File |
|-------|------|
| How the pipeline decides — layers, hook ordering, pausing, dry-run | [docs/how-it-works.md](docs/how-it-works.md) |
| All CLI + `/yolonot` skill commands | [docs/commands.md](docs/commands.md) |
| `.yolonot` rule files — format, walk-up, messages, redirects, sensitive files | [docs/rules.md](docs/rules.md) |
| Judges — the chain, `fast_allow` internals, Dippy and other hooks, security model | [docs/judges.md](docs/judges.md) |
| Risk tiers — per-harness action policy, overrides | [docs/risk-tiers.md](docs/risk-tiers.md) |
| Risk profiles — `fast`/`balanced`/`strict`/`paranoid` + custom | [docs/risk-profiles.md](docs/risk-profiles.md) |
| Models — catalog, chat providers, typed decision models, env vars, escalation (second-opinion model) | [docs/models.md](docs/models.md) |
| Prompt customization — prose hints or a full `system_prompt` override, plus `prompt verify` | [docs/prompt.md](docs/prompt.md) |
| Upgrading from 0.x — what changed in config.json and the CLI, `yolonot migrate` | [docs/upgrading.md](docs/upgrading.md) |
| Harnesses — install flags, runtime pinning, per-host caveats | [docs/harnesses.md](docs/harnesses.md) |
| Analytics — `yolonot log`, `stats`, `suggest`, quiet mode | [docs/analytics.md](docs/analytics.md) |
| Eval suite — test prompt quality across models | [docs/eval.md](docs/eval.md) |
| Architecture — code layout, data directory | [docs/architecture.md](docs/architecture.md) |

## Uninstall

```bash
yolonot uninstall    # removes hooks + skill, preserves data
```

Data at `~/.yolonot/` is preserved. Delete manually if wanted.

## Acknowledgements

The built-in `fast_allow` judge is heavily inspired by [**Dippy**](https://github.com/ldayton/Dippy) by Lily Dayton — specifically its `SIMPLE_SAFE` allowlist, subcommand-gating approach for multiplex tools (`git`, `docker`, `kubectl`, …), and its hostile-input test corpus. yolonot ports the allowlist tables into Go and re-walks the AST via [`mvdan.cc/sh`](https://github.com/mvdan/sh) instead of Dippy's hand-written Python bash parser (Parable). Where yolonot's parser reaches ambiguity it defers to the LLM — a fallback Dippy doesn't rely on — so the Go port can be stricter (reject-to-LLM) without hurting UX. The `dippy_parity_test.go` corpus and the rules system owe a direct debt to the Dippy project. MIT-licensed, credited in file headers.

## License

MIT. See [LICENSE](LICENSE).
