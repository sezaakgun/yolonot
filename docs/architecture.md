# Architecture

## Code layout

```
yolonot/
├── main.go                 # binary entry point — thin shim, calls yolonot.Run()
├── internal/
│   ├── yolonot/            # core package — everything the CLI does
│   │   ├── run.go              # command switch + Verbosef + stripGlobalFlags + setup
│   │   ├── hook.go             # PreToolUse hook handler pipeline
│   │   ├── llm.go              # LLM client + prompts + claude -p support
│   │   ├── rules.go            # rule loading + chain/redirect/sensitive detection
│   │   ├── session.go          # approved/asked/denied session files
│   │   ├── config.go           # config + settings.json + install targets + many cmd* handlers
│   │   ├── classifier.go       # risk tier → action mapping
│   │   ├── tui.go              # interactive TUI (charmbracelet/huh)
│   │   ├── update.go           # GitHub release update checker + `upgrade` command
│   │   ├── embed.go            # embedded SKILL.md + OpenCode plugin TS
│   │   ├── eval.go             # LLM evaluation runner with timing
│   │   ├── check.go            # dry-run command checker
│   │   ├── stats.go            # decision analytics
│   │   ├── similarity.go       # session similarity pre-filtering
│   │   ├── log.go              # decision logging (JSONL)
│   │   ├── pause.go            # session pause/resume marker handling
│   │   ├── harness.go          # Harness interface + registry + resolution
│   │   ├── harness_claude.go   # Claude Code adapter
│   │   ├── harness_codex.go    # Codex CLI adapter
│   │   ├── harness_opencode.go # OpenCode plugin adapter
│   │   ├── harness_opencode_plugin.ts  # OpenCode plugin shim (embedded)
│   │   ├── harness_gemini.go   # Gemini CLI adapter
│   │   └── skills/
│   │       └── SKILL.md        # Claude Code skill (embedded in binary)
│   ├── fastallow/          # built-in bash-AST fast-path (Dippy-inspired)
│   │   ├── localallow.go       # mvdan/sh AST walk — IsLocallySafe / IsLocallySafeWith
│   │   ├── allowlist.go        # safeCommands, wrapperCommands, subcommandReadOnly tables
│   │   └── handlers*.go        # per-command CLI handlers (git, curl, sed, awk, …)
│   └── glob/
│       └── glob.go             # fnmatch-style glob.Match (shared by fastallow + rules)
└── evals/
    └── suites/             # test cases (JSONL)
```

## Data directory

All yolonot data lives at `~/.yolonot/`:

| Path | Purpose |
|------|---------|
| `config.json` | Provider, model, timeout, pre-check list, risk overrides, harness settings |
| `rules` | Global rules (allow/deny/ask) |
| `sessions/` | Per-session per-project approved/asked/denied lists |
| `cache/` | Script file hash → cached LLM decisions |
| `decisions.jsonl` | Decision log with timestamps and LLM timing |
| `update-check` | Cached update check (once per day) |

Session files are keyed by a hash of the git root (or cwd), so approvals in one project don't bleed into another.
