# Changelog

All notable changes to yolonot are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] — 2026-04-20

### Security — classifier-bypass fixes (SECURITY)

Multiple classifier-bypass findings from an internal security audit. Every
bypass below was confirmed live against the prior binary and is corrected
in this release. Users on ≤0.9.1 should upgrade.

- **Fast-allow: drop `git submodule foreach`.** `foreach` takes a shell
  command and runs it in each submodule — git's documented escape hatch
  into the shell. Previously marked "read-only"; now falls through to the
  LLM/user layer. (F-14)
- **Fast-allow: drop macOS `security` credential-read subcommands.**
  `dump-keychain`, `find-generic-password`, `find-internet-password`,
  `find-key`, `find-certificate`, `find-identity`, `show-keychain-info`,
  `get-identity-preference`, `dump-trust-settings` removed from the safe
  list. With `-g` / `-d` they print secrets in cleartext; not safe. (F-20)
- **Fast-allow: reject `awk` programs with `| getline`.** The `"cmd" |
  getline` form opens a shell pipeline from inside awk (equivalent to
  `system()`). Previously approved as "read-only". (F-18)
- **Fast-allow: detect `sed` alternative-delimiter exec flag.**
  `sed 's|…|…|e'` and `sed 's#…#…#e'` were approved because
  `sedHasExecuteCommand` only matched `/e` suffixes. Now honors any
  delimiter via `findLastSedDelimiter`. (F-19)
- **Fast-allow: reject `env VAR=value cmd` when VAR is dangerous.**
  `envHandler` now mirrors `isSafeAssign`'s check against
  `dangerousEnvNames` and the `GIT_CONFIG_*` prefix, so
  `env GIT_SSH_COMMAND='…' git fetch` no longer fast-allows. (F-05)
- **Fast-allow: shell `-c` no longer approves `-lc` / `-ic` / `--login`
  / `--rcfile` / `--init-file` / `--posix`.** Login/interactive shells
  source rc files before the `-c` string runs. (F-06)
- **Rules layer: `hasChainOperator` rewritten as AST walk.** The prior
  character scanner missed lone `&` (background operator), `||`-
  adjacent forms, process substitution `<(…)` / `>(…)`, and multi-
  statement `;`. Now parses with `mvdan.cc/sh` and rejects any
  `BinaryCmd`, `CmdSubst`, `ProcSubst`, backgrounded `Stmt`, or non-
  `2>&1` redirect. Legacy character-scan remains as a fail-closed
  fallback when the parser rejects the input. (F-01, F-21)
- **LLM client: scheme + loopback host validation on `LLM_URL`.**
  Rejects `file://`, `gopher://`, and plain `http://` to non-loopback
  hosts. Prevents SSRF / exfiltration via a malicious `LLM_URL`. (F-04)
- **LLM client: response body capped at 1 MiB.** Prior `io.ReadAll`
  with no `io.LimitReader` would OOM the hook on a malicious provider
  response and fall through to the host's native permission layer.
  (F-03)
- **LLM prompt: script-file reader restricted to project root + secret
  scrubbing.** `BuildAnalyzePrompt` previously read any
  `[...].py|.sh|...` path from the command and shipped the first 100
  lines to the provider. Now requires the path to resolve inside the
  current cwd subtree (EvalSymlinks) and redacts lines matching
  common secret patterns before inclusion. (F-09)
- **OpenCode plugin: fail closed.** `harness_opencode_plugin.ts` now
  returns `{decision:"deny"}` on hook crash/timeout/JSON-parse error
  instead of `{decision:"allow"}`. Prevents one transient failure from
  turning into a full bypass for the rest of the session. (F-22)
- **`~/.yolonot/decisions.jsonl` and `config.json` perms.** Apply
  `os.Chmod(path, 0600)` after every write to repair legacy 0644 files
  that pre-date the current default. Cache directory created 0700
  instead of 0755. Decision log frequently contains inline secrets
  (`Bearer sk-…`, `postgres://user:pass@…`). (Secrets-audit Highs)
- **Atomic settings writes + symlink rejection.** All harness adapters
  (Claude, Gemini, Codex, OpenCode) now write settings/plugin files via
  a same-dir tempfile + rename, refusing to overwrite if the target is
  a pre-existing symlink. Prevents a TOCTOU redirect of writes to
  `~/.claude/settings.json`, `~/.gemini/settings.json`,
  `~/.codex/hooks.json`, or `~/.config/opencode/plugin/yolonot.ts`.
  Same helper used for `~/.yolonot/config.json`. (F-10)
- **API key no longer persisted to disk.** `SaveConfig` scrubs
  `Provider.APIKey` before serialisation; the TUI now prints
  `export <ENV_VAR>=…` instructions instead of writing the key to
  `~/.yolonot/config.json`. Keys entered via TUI are used only for the
  current process's connection-test LLM call. (Secrets-audit Medium)
- **`findRepoRoot` depth cap (64).** Prevents AI-controlled deep `cwd`
  values from DoS'ing the hook with thousands of `os.Stat` lookups.
  (F-08)
- **`.yolonot` walk-up: reject symlinks.** `os.Lstat` instead of
  `os.Stat`; rule files that are symlinks are ignored. Prevents
  attacker-planted symlinks pointing at permissive rule bodies. (F-23)

### Other

- **Go toolchain** pinned to `go1.26.2` (`toolchain` directive).
  Resolves 8 symbol-reachable stdlib CVEs: GO-2026-4870 (TLS-DoS),
  GO-2026-4866 / 4599 / 4600 (x509 auth-bypass / panic), GO-2026-4947
  / 4946 (x509 DoS), GO-2026-4601 (net/url IPv6), GO-2026-4602
  (os.ReadDir Root).
- **CI: `test.yml` permissions block.** Declares `contents: read`
  explicitly rather than inheriting repo default.
- **`mvdan.cc/sh/v3`** promoted from indirect → direct require
  (now used by the rules-layer AST walker).
- **`.dippy` removed from git tracking** (`git rm --cached`).

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
