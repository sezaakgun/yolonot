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
│   │   ├── llm_attach.go       # Script attachment, auto-detected project context, and transcript user-prompt sanitization
│   │   ├── rules.go            # rule loading + chain/redirect/sensitive detection
│   │   ├── discover.go         # `rules discover` host permission & sandbox policy scanner
│   │   ├── open_nofollow_*.go  # O_NOFOLLOW safe file reader for scripts, transcripts, and snapshots
│   │   ├── session.go          # approved/asked/denied session files
│   │   ├── config.go           # config + settings.json + install targets + many cmd* handlers
│   │   ├── classifier.go       # risk tiers + risk map resolution
│   │   ├── config_v1.go        # model catalog, judge list encoding, v0 → v1 fold
│   │   ├── judge.go            # the judge chain: fast_allow, exec hooks, typed and chat models
│   │   ├── budget.go           # shared hook deadline and bounded external judges
│   │   ├── decision.go         # shared tier/ask-condition criteria + typed decision-model backend
│   │   ├── escalation.go       # second-opinion model after the chain (`judges escalation`)
│   │   ├── profile.go          # risk profiles, per-harness pins & tier maps (`profile` verb)
│   │   ├── cmd_classifier.go   # `rules` prompt subcommands (defaults / config / review / verify / discover)
│   │   ├── suggest_llm.go      # `suggest` smart mode
│   │   ├── models.go           # `models` and `migrate` verbs
│   │   ├── tui.go              # text prompts (charmbracelet/huh)
│   │   ├── tui_menu.go         # mouse-aware menus and option groups (bubbletea)
│   │   ├── tui_config.go       # `yolonot config` rows and editors
│   │   ├── tui_config_view.go  # the settings page model
│   │   ├── tui_rules.go        # staged rule edits, conflict checks and save rollback
│   │   ├── update.go           # GitHub release update checker + `upgrade` command
│   │   ├── embed.go            # embedded SKILL.md + OpenCode plugin TS
│   │   ├── eval.go             # LLM evaluation runner with timing
│   │   ├── check.go            # dry-run command checker
│   │   ├── stats.go            # decision analytics
│   │   ├── similarity.go       # session similarity pre-filtering
│   │   ├── log.go              # decision logging (JSONL)
│   │   ├── learn.go            # project repeated-ask candidate extraction for `suggest`
│   │   ├── mod.go              # optional Claude mod lifecycle and bound verdict replay
│   │   ├── executable_snapshot.go # local native executable identity for approval/replay
│   │   ├── pause.go            # session pause/resume marker handling
│   │   ├── harness.go          # Harness interface + registry + resolution
│   │   ├── harness_claude.go   # Claude Code adapter
│   │   ├── harness_codex.go    # Codex CLI adapter
│   │   ├── harness_opencode.go # OpenCode plugin adapter
│   │   ├── harness_opencode_plugin.ts  # OpenCode plugin shim (embedded)
│   │   ├── harness_antigravity.go # Antigravity CLI adapter
│   │   ├── harness_gemini.go   # retired Gemini compatibility/cleanup
│   │   ├── harness_cursor.go   # Cursor adapter
│   │   └── skills/
│   │       └── SKILL.md        # Shared management skill (embedded in binary)
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
| typed decision model | a catalog entry with a typed protocol (or legacy inferred URL) | one request with the shared risk-tier criteria and nine independent yes/no ask conditions (`decision.go`) | allow / ask |
| chat model | any other catalog name | the system prompt built from the same shared tier and ask-condition criteria (`decision.go` + `llm.go`), plus `Command: …`, attached scripts, auto-detected project context, and the sanitized session user prompt (`llm_attach.go`) | allow / ask / deny |

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
| `sessions/` | Per-session per-project approved/asked/denied lists, script/native executable hashes and allow-once markers; session-wide `<id>.paused` and `<id>.profile` pins |
| `sessions/<id>.mod` | Claude mod verdicts bound to tool ID, command, cwd and snapshot, with explicit grant scope and completion state |
| `mod/` | Optional Claude plugin manifest and TypeScript module |
| `cache/` | Attached-script content hash (command + full-file sha256s) → cached model decisions plus a policy/prompt/model context fingerprint |
| `decisions.jsonl` | Decision log with timestamps, human ask resolutions and model timing, one record per line |
| `suggest-cache.json` | `yolonot suggest` cache |
| `migrate-declined` | Marker: the one-time migration offer was declined |
| `update_check.json` | Cached update check (once per day) |

Session files are keyed by a hash of the git root (or cwd), so approvals in one project don't bleed into another.

## Configuration and operational controls

`config_validate.go` owns strict decoding and semantic validation;
`protocol.go` selects provider wire formats. `failure.go` and `budget.go`
apply configurable failure actions and the shared deadline. `diagnostics.go`
implements `doctor`, `audit` and `status --all` / `status --json` without exposing API keys.

`session_commands.go` implements project-scoped approve/deny/reset, with
script and supported native executable snapshots. Multiline commands use one JSON-encoded physical record
in session files; old single-line records remain readable.
`cache_context.go` invalidates verdicts when their decision context changes.
`harness_skill.go` installs managed native skills while preserving unrelated
user files. See [configuration.md](configuration.md).
