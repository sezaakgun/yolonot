# Contributing to yolonot

Thanks for your interest in contributing!

## Getting Started

```bash
git clone https://github.com/sezaakgun/yolonot.git
cd yolonot
go build -o yolonot .
go test ./...
```

Requires Go 1.25+.

## Making Changes

1. Fork the repo and create a branch from `main`
2. Write your code
3. Add or update tests as needed
4. Run `go test ./...` and make sure everything passes
5. Run `go vet ./...` for static analysis
6. Open a pull request

## Project Structure

```
main.go                       Thin CLI entry point
internal/yolonot/             CLI, hooks, config, judges, models, TUI and adapters
internal/yolonot/*_test.go    Unit, integration and security regression tests
internal/yolonot/mod/         Claude function-hook module and Bun tests
internal/yolonot/skills/      Shared native management skill template
internal/fastallow/           Conservative shell AST parser and allowlist
internal/glob/                Shared glob matcher
evals/suites/                 Model evaluation cases (JSONL)
```

See [docs/architecture.md](docs/architecture.md) for the full file map.
The shared hook deadline is in `internal/yolonot/budget.go`; new network or
subprocess stages must honor its context. Tests that change cwd should use
`t.Chdir` so they restore it before temporary directories are removed.

Install Bun to run the embedded OpenCode shim and Claude mod tests. Install
Codex CLI to verify generated TOML with the host's own parser. These tests
explicitly skip if their runtime is absent; the core Go tests still run.
CI installs Bun so the TypeScript middleware tests run on every PR.

## Adding a Harness

yolonot supports multiple AI coding assistants through the `Harness` interface in `internal/yolonot/harness.go`. Add a new host under that package:

1. **Implement the interface.** Create `harness_<name>.go` with a type that satisfies every method on `Harness`:
   - `Name()`, `IsDetected()`, `IsInstalled()`
   - `Install(binPath)`, `Uninstall()`
   - `SettingsPath()`, `SessionIDFromEnv()`
   - `ParseHookInput([]byte) (HookPayload, error)` — canonicalize stdin to our `HookPayload` shape
   - `FormatHookResponse(HookResponse) string` — serialize to the host's wire format (return `""` for passthrough)
   - `RiskMap() map[string]string` — tier (`safe`/`low`/`moderate`/`high`/`critical`) → action (`allow`/`ask`/`deny`/`passthrough`)
   - `InstallSkill() (string, error)`, `UninstallSkill() error` — return `("", nil)` if skill installation is not implemented, and document that limitation
   - `PostInstallNotes() []string` — caveats printed after `yolonot install` (e.g. required flags, restart reminders)

2. **Register it** via a `func init() { RegisterHarness(&YourHarness{}) }` block.

3. **Document caveats.** Describe the adapter's exact hooks, allow/ask/deny behavior and skill support in [docs/harnesses.md](docs/harnesses.md). Surface setup caveats via `PostInstallNotes`. Distinguish limitations of our adapter from capabilities available elsewhere in the host.

4. **Add tests.** At minimum: `Registered`, `SettingsPath`, `ParseHookInput` (canonical + malformed JSON), `FormatHookResponse` (deny + matches-Claude byte-for-byte where applicable), `Install`/`Uninstall` round-trip, `IsDetected`, `RiskMap` defaults, `PostInstallNotes`, and `ActiveHarnessPicks…BySessionEnv`. See `harness_codex_test.go` or `harness_opencode_test.go` for reference.

5. **Keep the canonical shape.** The `HookPayload` and `HookResponse` structs are modeled on Claude's protocol — the adapter's job is to translate *into* that shape on input and *out of* it on output. Don't leak host-specific fields into the core.

## Running Evals

To test LLM prompt quality across models:

```bash
./yolonot eval --all --model gpt-5.4-mini --runs 1 --verbose
```

## Adding Eval Cases

Add JSONL lines to `evals/suites/greenfield.jsonl` (command classification) or `evals/suites/brownfield.jsonl` (session similarity). Follow the existing format and include meaningful IDs, categories, and notes.

## Reporting Bugs

Open an issue with:
- What you expected vs what happened
- The command that triggered the issue
- The harness (Claude Code / Codex / OpenCode / Antigravity / Cursor), CLI or desktop surface, version and permission mode
- Relevant `yolonot log` entries and `doctor` output, with sensitive command arguments redacted; never include key values

## Code Style

- Follow standard Go conventions (`gofmt`)
- Keep functions focused and small
- Add tests for new features and bug fixes
- No unnecessary abstractions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Native harness verification

`go test ./... -count=1 -race -timeout=120s` runs adapter, subprocess,
configuration, lifecycle and security regression coverage. Bun is needed for
the OpenCode plugin and Claude mod middleware tests. Model-provider live
probes are separate and opt-in.

A passing adapter fixture is not proof of a host approval dialog. The `e2e/`
package drives real hosts against a freshly built binary:

```bash
go test -tags e2e ./e2e/ -v                     # Claude CLI, Claude mod (tmux), Codex, OpenCode V2, Antigravity, Cursor CLI
YOLONOT_E2E_AUTH=1 go test -tags e2e ./e2e/ -v  # also live Cursor CLI checks (logged-in account, real model)
```

Hosts that allow it point at a scripted local model (base URL settings).
Cursor CLI has no such setting, so `cursor_test.go` fakes the slice of
Cursor's backend a run needs (`CURSOR_API_ENDPOINT`, plus the CLI's
`AGENT_CLI_E2E` switch that skips sign-in). Its hand-encoded messages follow
the schema strings embedded in the CLI and may need updating when a new CLI
version changes them; the live checks below catch that.

The auth tier keeps the host's real HOME for its login and starts the host
with `YOLONOT_DISABLED=1`, so a globally installed yolonot neither decides
nor records the test commands.

Missing hosts are skipped; `YOLONOT_E2E_<NAME>` (for example
`YOLONOT_E2E_CURSOR_AGENT`) points at a binary outside `PATH`, and
`YOLONOT_E2E_DEBUG=1` prints each scripted model request. Desktop apps stay
manual: follow [e2e/MANUAL.md](e2e/MANUAL.md). For new native checks, prefer isolated HOME/XDG directories, install the candidate there, use a
scripted local model or native tool API, and assert harmless marker execution
for allow/deny/ask/reject. Codex also needs trusted hook hashes and a
PermissionRequest client; verify untrusted hooks are skipped. Never change
a developer's live settings without explicit authorization. Local scripted
providers use dummy credentials; real account tests require separate opt-in.
If a test requires the user's authenticated native app, preserve existing
settings, record that scope and never copy credentials into fixtures or logs.
Record exact versions, expected host deferrals and untested UI surfaces in
[the compatibility guide](docs/harnesses.md#verification-scope). Keep raw account
metadata and machine-specific test captures out of version control.

### Merge sign-off

`main` requires one commit status per harness, posted by a maintainer after
running the checks locally on the PR's final commit:

```bash
scripts/signoff all                    # every check below
scripts/signoff codex opencode         # selected checks
scripts/signoff --skip "docs only" claude-desktop codex-desktop cursor-ide
scripts/signoff --dry-run codex        # run without posting
```

| Status | Source |
|--------|--------|
| `e2e/claude-cli`, `e2e/claude-mod`, `e2e/codex`, `e2e/opencode`, `e2e/agy`, `e2e/cursor-cli` | e2e tests, no account |
| `manual/claude-desktop`, `manual/codex-desktop`, `manual/cursor-ide` | guided run of [e2e/MANUAL.md](e2e/MANUAL.md): you act in the app, the script checks markers and the decision log |

The script refuses a working tree that differs from `HEAD` and fails a check
whose tests were skipped. A status belongs to one commit: a new push needs a
new sign-off, so sign off last. `--skip` posts success with the reason shown
on the PR. Unit tests run in CI (`test` workflow).
