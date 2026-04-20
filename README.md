<p align="center">
  <img src="assets/logo.png" alt="yolonot" width="180">
</p>

<h1 align="center">yolonot</h1>

<p align="center">
  Smart auto-mode for AI coding assistants. The safe alternative to <code>--dangerously-skip-permissions</code>.<br>
  Built for Claude Code. Also works with Codex CLI, OpenCode, and Gemini CLI.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://github.com/sezaakgun/yolonot/actions"><img src="https://github.com/sezaakgun/yolonot/actions/workflows/test.yml/badge.svg" alt="Tests"></a>
  <img src="https://img.shields.io/badge/go-1.25+-00ADD8.svg" alt="Go 1.25+">
</p>

---

yolonot sits between your AI coding assistant and your shell. It uses an LLM to classify every Bash command as **safe** (allow) or **needs-review** (ask), with session memory so approved commands don't ask twice and rejected commands stay blocked. Deny rules give you absolute blocks nothing can override.

> **Claude Code first.** yolonot was designed for Claude Code and that's where it gets the richest UX (full allow/ask/deny). Codex CLI, OpenCode, and Gemini CLI adapters ship in-tree but have upstream hook-API limitations — see [docs/harnesses.md](docs/harnesses.md) for each host's caveats.

> **⚠ LLMs are not deterministic.** yolonot's classifier is a probabilistic safety net, not a guarantee. Models hallucinate, miss context, and can be tricked by adversarial prompts. Use yolonot at your discretion: keep your own judgment in the loop, write **deny rules** for anything you truly never want run (rules beat the LLM, always), and don't treat it as a substitute for reviewing what your AI assistant is doing. If yolonot allows a destructive command, **you** are still the one who installed it on your machine.

## Quick start

### 1. Pick an LLM provider

| Provider | Cost | Latency | Key |
|----------|------|--------:|-----|
| **OpenAI** `gpt-5.4-mini` | ~10¢/day | ~500ms | `OPENAI_API_KEY` |
| **Ollama** `gemma4:e4b` | free | 2–10s | — (local) |
| **Claude Code** (default) | free | ~10s | — (subscription) |

Full matrix in [docs/providers.md](docs/providers.md).

### 2. Install

```bash
go install github.com/sezaakgun/yolonot@latest

# Make sure Go bin is in PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# First-run wizard: hooks + rules + provider pick
yolonot setup
```

### 3. Restart your host CLI

Hooks are read at startup, so restart Claude Code (or whichever harness you're using) to activate yolonot.

That's it. Every Bash command now runs through [the pipeline](docs/how-it-works.md).

## Docs

| Topic | File |
|-------|------|
| How the pipeline decides — layers, hook ordering, pausing, dry-run | [docs/how-it-works.md](docs/how-it-works.md) |
| All CLI + `/yolonot` skill commands | [docs/commands.md](docs/commands.md) |
| `.yolonot` rule files — format, walk-up, messages, redirects, sensitive files | [docs/rules.md](docs/rules.md) |
| Pre-check hooks — `fast-allow` internals, Dippy integration, security model | [docs/pre-check.md](docs/pre-check.md) |
| Risk tiers — per-harness action policy, overrides | [docs/risk-tiers.md](docs/risk-tiers.md) |
| LLM providers — matrix, env vars, response schema | [docs/providers.md](docs/providers.md) |
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

The built-in `fast-allow` pre-checker is heavily inspired by [**Dippy**](https://github.com/lilydayton/dippy) by Lily Dayton — specifically its `SIMPLE_SAFE` allowlist, subcommand-gating approach for multiplex tools (`git`, `docker`, `kubectl`, …), and its hostile-input test corpus. yolonot ports the allowlist tables into Go and re-walks the AST via [`mvdan.cc/sh`](https://github.com/mvdan/sh) instead of Dippy's hand-written Python bash parser (Parable). Where yolonot's parser reaches ambiguity it defers to the LLM — a fallback Dippy doesn't rely on — so the Go port can be stricter (reject-to-LLM) without hurting UX. The `dippy_parity_test.go` corpus and the rules system owe a direct debt to the Dippy project. MIT-licensed, credited in file headers.

## License

MIT. See [LICENSE](LICENSE).
