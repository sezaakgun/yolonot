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
main.go                       CLI entry point
hook.go                       Hook handler pipeline
llm.go                        LLM client + prompts + response parsing
classifier.go                 Risk classifier → action mapping
rules.go                      Rule loading + glob matching + chain detection
session.go                    Session files (approved/asked/denied, project-scoped)
config.go                     Config + settings.json + install/uninstall + suggest
check.go                      Dry-run command pipeline checker
stats.go                      Decision analytics
similarity.go                 Session similarity pre-filtering
tui.go                        Interactive TUI (charmbracelet/huh)
log.go                        Decision logging (JSONL)
eval.go                       LLM evaluation runner
embed.go                      Embedded SKILL.md
update.go                     GitHub release update checker

harness.go                    Harness interface + registry (sync.RWMutex)
harness_claude.go             Claude Code adapter (canonical hook protocol)
harness_codex.go              Codex CLI adapter (~/.codex/hooks.json)
harness_opencode.go           OpenCode adapter (writes TS plugin)
harness_opencode_plugin.ts    Embedded OpenCode plugin (//go:embed)
harness_gemini.go             Gemini CLI adapter (~/.gemini/settings.json)

main_test.go                  Unit tests
hook_integration_test.go      End-to-end hook pipeline tests
harness_*_test.go             Per-adapter tests (install/parse/format/risk-map)
evals/suites/                 LLM eval test cases (JSONL)
```

## Adding a Harness

yolonot supports multiple AI coding assistants through the `Harness` interface in `harness.go`. To add a new host:

1. **Implement the interface.** Create `harness_<name>.go` with a type that satisfies every method on `Harness`:
   - `Name()`, `IsDetected()`, `IsInstalled()`
   - `Install(binPath)`, `Uninstall()`
   - `SettingsPath()`, `SessionIDFromEnv()`
   - `ParseHookInput([]byte) (HookPayload, error)` — canonicalize stdin to our `HookPayload` shape
   - `FormatHookResponse(HookResponse) string` — serialize to the host's wire format (return `""` for passthrough)
   - `RiskMap() map[string]string` — tier (`safe`/`low`/`moderate`/`high`/`critical`) → action (`allow`/`ask`/`deny`/`passthrough`)
   - `InstallSkill() (string, error)`, `UninstallSkill() error` — return `("", nil)` if the host has no skill surface
   - `PostInstallNotes() []string` — caveats printed after `yolonot install` (e.g. required flags, restart reminders)

2. **Register it** via a `func init() { registerHarness(&YourHarness{}) }` block.

3. **Document caveats.** If the host's hook API lacks a primitive (e.g. no `ask`), add a short `<harness>_limitation.md` style note in the README's "Other AI harnesses" table and surface it via `PostInstallNotes`.

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
- The harness you're running (Claude Code / Codex / OpenCode / Gemini) and its version
- Output from `yolonot log` if relevant

## Code Style

- Follow standard Go conventions (`gofmt`)
- Keep functions focused and small
- Add tests for new features and bug fixes
- No unnecessary abstractions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
