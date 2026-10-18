# yolonot — Agent Instructions

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/architecture.md](docs/architecture.md) for full architecture and contributor workflows.

## Live State & Host Protection (Mandatory)
- **Never mutate live user or host state**: Do NOT run `yolonot pause`, `resume`, `install`, `uninstall`, `setup`, `profile`, `models`, `judges`, or `config` against the user's real `$HOME` (`~/.yolonot`, `~/.claude`, `~/.gemini`, `~/.codex`, `~/.cursor`) unless explicitly requested by the user.
- In tests, reproductions, or CLI experiments, always isolate state with a temporary `HOME` (e.g., `HOME=$(mktemp -d) yolonot ...` or `withFakeHome(t)` in Go tests).

## Repository Sync & Verification Rules
- **Embedded skill**: `internal/yolonot/skills/SKILL.md` is embedded into the binary via `go:embed`; reinstall (`yolonot install`) in isolated test sandboxes when testing skill changes.
- **Security invariants**:
  - `critical` risk tier must never map to `allow` or `force_allow`.
  - Script attachment (`internal/yolonot/llm.go`) must never attach sensitive home directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, etc.) or attach pre-mutation file contents when an earlier segment overwrites a script.
- **Cross-Harness & Subcommand Parity Invariants**:
  - **5 Supported Harnesses**: `claude` (settings hooks + Claude Mod), `codex`, `antigravity`, `opencode` (V1 `tool.execute.before` + V2 `permission.asked`/`permission.replied`), and `cursor`.
  - **Sandbox Bypass Isolation**: When a harness payload requests unsandboxed execution (`dangerouslyDisableSandbox`, `BypassSandbox`, `sandbox: false`, `sandbox_permissions: "require_escalated"`, `with_escalated_permissions: true`), `HookPayload.BypassSandbox` and `DecisionEntry.BypassSandbox` MUST be set. Unsandboxed commands must:
    1. Never auto-allow via `.yolonot` `allow-cmd`/`allow-path` rules or `fast_allow`.
    2. Use isolated session memory (`approved_unsandboxed` / `approved_unsandboxedhash`), script cache keys, and mod replay bindings so a prior sandboxed approval never silently authorizes an unsandboxed replay.
    3. Include `[Sandbox: agent requested unsandboxed execution (host sandbox bypass)]` in LLM judge prompts.
    4. Never be promoted into `yolonot suggest` rule/hint findings or repeated-ask candidates.
  - **Dual-Phase & Paired Hooks**:
    - Codex `PreToolUse` → `PermissionRequest` pairs for the same command must deduplicate via `.codexpre` so the LLM is not called twice and `decisions.jsonl` / `stats` do not double-count, while still re-checking newly added `deny` rules on `PermissionRequest`.
    - `PostToolUse` may only infer `allow_once` human resolutions on harnesses that support native `ask` (`harnessSupportsAsk(harness)`), preventing ask-less harnesses (e.g. OpenCode V1) from fabricating human approvals.
  - **Subcommand & Project-Root Parity**:
    - All subcommands (`hook`, `log`, `stats`, `suggest`, `check`, `status`, `approve`/`deny`/`reset`, `doctor`, `audit`) must resolve project roots consistently across subdirectories and linked git worktrees (`projectRoot` / `ProjectSessionID`).
    - When `applyRiskMap` returns `passthrough`, `DecisionEntry.Decision` must be logged as `"passthrough"` and `OrigDecision` preserved so `stats`, `log`, and `suggest` see original `ask` verdicts.
    - `yolonot check` must mirror `yolonot hook` step-for-step (including `selfPolicyVerb`, rule priority `deny > ask > allow`, `attach_outside_root`, and custom `wrappers`).
    - `yolonot doctor` checks health, installation, `config.json` validation, and latency (with a 1-line summary pointer to `yolonot audit`); `yolonot audit` performs the security, rule-lint, policy, and host permission/sandbox audit.
    - `yolonot suggest` enriches findings with human resolutions (`ask_approved`, `allow_once`, `ask_rejected`) from `decisions.jsonl`, includes repeated-ask candidates, and supports `--list` / `--json` (auto-selecting `--list` when stdin is not a TTY so skills never hang).
- **Verify before finishing**: Run `go test ./...` and `go test -tags e2e ./e2e/ -v`, and ensure a clean working tree (`git status`) before sign-off.
