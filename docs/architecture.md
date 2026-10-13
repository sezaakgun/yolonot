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
│   │   ├── classifier.go       # risk tiers + risk map resolution
│   │   ├── config_v1.go        # model catalog, judge list encoding, v0 → v1 fold
│   │   ├── judge.go            # the judge chain: fast_allow, exec hooks, typed and chat models
│   │   ├── decision.go         # typed decision-model backend (System One / OpenAI Decisions / Workers AI)
│   │   ├── escalation.go       # second-opinion model after the chain
│   │   ├── profile.go          # risk profiles, per-harness pins, `profile` verb
│   │   ├── cmd_classifier.go   # `prompt` verb (defaults / config / review / verify)
│   │   ├── suggest_llm.go      # `suggest` smart mode
│   │   ├── models.go           # `models` and `migrate` verbs
│   │   ├── tui.go              # text prompts (charmbracelet/huh)
│   │   ├── tui_menu.go         # mouse-aware menus and option groups (bubbletea)
│   │   ├── tui_config.go       # `yolonot config` rows and editors
│   │   ├── tui_config_view.go  # the settings page model
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
│   │   ├── harness_cursor.go   # Cursor adapter
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

## Judges

The chain in `config.json` (`judges`) is an ordered list; the first judge
whose verdict is permitted (`may`) wins. Four kinds, all in `judge.go`:

| Kind | Entry | Runs | Verdicts |
|------|-------|------|----------|
| built-in parser | `fast_allow` | `internal/fastallow` bash AST walk, no network | allow |
| exec hook | `exec:<path>` | the binary with Claude's PreToolUse JSON on stdin (`runPreCheck`, 3 s timeout) | allow |
| typed decision model | a catalog name whose URL is a System One, OpenAI Decisions or Workers AI endpoint | one request with the risk-tier choice and nine yes/no conditions (`decision.go`) | allow / ask |
| chat model | any other catalog name | the system prompt plus `Command: …` and attached scripts (`llm.go`) | allow / ask / deny |

Rules and session memory run before the chain; escalation, the unresolved
policy and the risk map run once after it (`hook.go`). The pipeline order
is in [how-it-works.md](how-it-works.md).

## Data directory

All yolonot data lives at `~/.yolonot/`:

| Path | Purpose |
|------|---------|
| `config.json` | Model catalog, judge chain, escalation, prompt hints, policy (see [models.md](models.md)) |
| `config.json.bak` | Previous config, written by `yolonot migrate` and by saves from `yolonot config` |
| `rules` | Global rules (allow/deny/ask) |
| `sessions/` | Per-session per-project approved/asked/denied lists, plus `<id>.paused` and `<id>.profile` pins |
| `cache/` | Attached-script content hash (command + full-file sha256s) → cached model decisions |
| `decisions.jsonl` | Decision log with timestamps and model timing, one record per line |
| `suggest-cache.json` | `yolonot suggest` cache |
| `migrate-declined` | Marker: the one-time migration offer was declined |
| `update_check.json` | Cached update check (once per day) |

Session files are keyed by a hash of the git root (or cwd), so approvals in one project don't bleed into another.
