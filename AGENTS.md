# yolonot — Agent Instructions

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/architecture.md](docs/architecture.md) for full architecture and contributor workflows.

## Live State & Host Protection (Mandatory)
- **Never mutate live user or host state**: Do NOT run `yolonot pause`, `resume`, `install`, `uninstall`, `setup`, `risk`, `profile`, `models`, or `judges` against the user's real `$HOME` (`~/.yolonot`, `~/.claude`, `~/.gemini`, `~/.codex`, `~/.cursor`) unless explicitly requested by the user.
- In tests, reproductions, or CLI experiments, always isolate state with a temporary `HOME` (e.g., `HOME=$(mktemp -d) yolonot ...` or `withFakeHome(t)` in Go tests).

## Repository Sync & Verification Rules
- **Embedded skill**: `internal/yolonot/skills/SKILL.md` is embedded into the binary via `go:embed`; reinstall (`yolonot install`) in isolated test sandboxes when testing skill changes.
- **Security invariants**:
  - `critical` risk tier must never map to `allow` or `force_allow`.
  - Script attachment (`internal/yolonot/llm.go`) must never attach sensitive home directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, etc.) or attach pre-mutation file contents when an earlier segment overwrites a script.
- **Verify before finishing**: Run `go test ./...` and ensure a clean working tree (`git status`) before sign-off.
