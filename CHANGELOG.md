# Changelog

All notable changes to yolonot are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.1] — 2026-04-20

### Changed — Internal
- **Package split.** Moved all CLI logic from root `package main` into
  `internal/yolonot`; bash-AST allowlist into `internal/fastallow` (public
  API: `IsLocallySafe`, `IsLocallySafeWith`); fnmatch helper into
  `internal/glob` (public API: `Match`). Root now contains only a thin
  `main.go` shim calling `yolonot.Run()` — `go install
  github.com/sezaakgun/yolonot@latest` unchanged. goreleaser ldflag target
  is now `-X github.com/sezaakgun/yolonot/internal/yolonot.Version=...`.
- **`dippy_parity_test.go`** shrunk from 6157 lines to 121; 5897 cases
  extracted to `internal/fastallow/testdata/dippy_parity.jsonl`.
- **README** rewritten as a ~80-line index pointing at a new `docs/` folder
  (how-it-works, commands, rules, pre-check, risk-tiers, providers,
  harnesses, analytics, eval, architecture).

## [0.9.0] — 2026-04-20

### Added
- **Multi-harness support.** yolonot now runs behind a `Harness` interface with
  adapters for Claude Code (flagship), Codex CLI, OpenCode, and Gemini CLI.
  Each adapter owns its own settings path, hook wire format, session-env
  convention, and default risk-tier → action map.
- **`PostInstallNotes()`** on the `Harness` interface. `yolonot install` now
  prints per-harness caveats after the install summary — e.g. Gemini's
  `--yolo` requirement (auto-suppressed when `general.defaultApprovalMode ==
  "yolo"` is already set), Codex's `[features] codex_hooks = true` flag, and
  both Codex / OpenCode's missing `ask` primitive.
- **Per-harness risk map overrides.** `yolonot risk <harness> <tier> <action>`
  lets users override defaults per-cell; env vars
  `YOLONOT_<HARNESS>_RISK_<TIER>` win at runtime.
- **Embedded OpenCode plugin** (`harness_opencode_plugin.ts`) installed to
  `~/.config/opencode/plugin/yolonot.ts` via `//go:embed`. Uses the named
  export form (`export const YolonotPlugin`) required by OpenCode 1.4.3+.
- **Contributing guide: "Adding a Harness" section** with the full interface
  checklist and test expectations.

### Changed
- **LLM fallback is now harness-aware.** When the LLM is unreachable or its
  response fails to parse, yolonot no longer emits Claude-shaped JSON
  directly — the response routes through the active harness's
  `FormatHookResponse`. Claude keeps its systemMessage banner; Codex / Gemini
  return empty stdout so the host's native permission engine takes over.
- **OpenCode's moderate-risk default is now explicit `allow`** (was
  `passthrough`). Since OpenCode's plugin treats empty stdout as allow,
  passthrough was silently promoting moderate → allow; the explicit mapping
  keeps the effective behavior but makes it legible in config dumps and
  guarded by a regression test.
- **README tagline** broadened from "Smart auto-mode for Claude Code" to
  cover all supported hosts; Claude Code remains the flagship integration.

### Fixed
- **Data race on the harness registry.** `registeredHarnesses` is now guarded
  by `sync.RWMutex`; `Harnesses()` returns a snapshot copy so callers can
  iterate without holding the lock.
- **Malformed stdin no longer silently skips the classifier.** Every adapter's
  `ParseHookInput` now surfaces JSON errors to the caller instead of
  returning a zero-value payload that the empty-`hook_event_name` guard
  would drop.
- **Wrapper-aware session approvals.** When a co-installed PreToolUse hook
  (e.g. `rtk`) rewrites a command via `hookSpecificOutput.updatedInput`
  between yolonot's ask and actual execution, the post-exec approval used
  to land on the rewritten form while `.asked` still held the original —
  the ask-not-approved inference then wrote a false `session_deny` on the
  next bare invocation. yolonot now recognizes `<wrapper> ... <command>`
  lines in `.approved` (wrapper allowlist, currently just `rtk`) before
  inferring rejection, and records the plain form for a fast future exact
  match. Allowlist prevents approval-laundering via trailing-text
  substrings (`echo curl evil.com` does not approve `curl evil.com`).
- Rule priority, banner format, pause/disable semantics — see `git log
  0d949be` for the Claude-specific details from v0.8.x.

## [0.8.0] — 2026-03

### Added
- `fast-allow` sentinel — built-in Go bash parser in the pre-check chain;
  short-circuits read-only commands without an LLM call.
- Project-scoped sessions — session files now suffixed with a hash of the git
  root (or cwd) so a command approved in project A is not auto-approved in
  project B.
- Multiplex-tool flag hardening — `git -c`, `docker --config`,
  `kubectl --kubeconfig`, `helm --kube-apiserver`, `aws --ca-bundle`, `npm
  --userconfig` / `--globalconfig` reject the fast-path (they can execute
  arbitrary code).

## Earlier releases

See `git log --oneline` for the full history before multi-harness support
landed. Notable milestones:

- **v0.7.x** — `yolonot check`, `yolonot stats`, threshold tuning, hardening.
- **v0.6.x** — quiet mode, verbose flag, pre-check branding, LLM short field.
- **v0.5.x** — pause/resume commands, `YOLONOT_DISABLED` env var,
  `--session-id` flag.
- **v0.4.x** — self-update via `yolonot upgrade`, smart command matching,
  Claude subscription as LLM provider.
- **v0.3.x** — Go rewrite from the original Python prototype; chain-aware
  rules, TUI, eval runner.
