# yolonot — Agent Instructions

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/architecture.md](docs/architecture.md) for full architecture and contributor workflows.

## Live State & Host Protection (Mandatory)
- **Never mutate live user or host state**: Do NOT run `yolonot pause`, `resume`, `install`, `uninstall`, `setup`, `profile`, `models`, `judges`, or `config` against the user's real `$HOME` (`~/.yolonot`, `~/.claude`, `~/.gemini`, `~/.codex`, `~/.cursor`) unless explicitly requested by the user.
- In tests, reproductions, or CLI experiments, always isolate state with a temporary `HOME` (e.g., `HOME=$(mktemp -d) yolonot ...` or `withFakeHome(t)` in Go tests).
- **Never hardcode or copy local commands/paths/orgs into the repository**: Never copy real commands from `~/.yolonot/decisions.jsonl`, local paths (`~/my-work`, `/Users/<user>/...`), organization/domain names, or local plugin/script names into code, prompts, tests, eval suites, or docs. Always obscure/anonymize test fixtures (`acme`, `~/workspace`, `*/acme-plugin/*/scripts/run-check.sh`) and write judge prompts/criteria as generic principles.

## Repository Sync & Verification Rules
- **Embedded skill**: `internal/yolonot/skills/SKILL.md` is embedded into the binary via `go:embed`; reinstall (`yolonot install`) in isolated test sandboxes when testing skill changes.
- **Security invariants**:
  - `critical` risk tier must never map to `allow` or `force_allow`.
  - Script attachment (`internal/yolonot/llm_attach.go`) must never attach sensitive home directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, etc.) or attach pre-mutation file contents when an earlier segment overwrites a script.
- **Cross-Harness & Subcommand Parity Invariants**:
  - **24 Supported Harnesses (plus retired `gemini`) on unified `baseHarness` (`internal/yolonot/harness_base.go`)**: `claude` (settings hooks + Claude Mod), `codex`, `antigravity`, `opencode` (V1 `tool.execute.before` + V2 `permission.asked`/`permission.replied`), `cursor`, `qwen`, `copilot`, `grok`, `crush`, `goose`, `kilo`, `pi`, `openhands`, `kimi`, `zcode`, `cline`, `muse`, `kiro`, `hermes`, `deepseek`, `devin`, `openclaw`, `mirror`, and `amp`.
  - **Sandbox Bypass Isolation**: When a harness payload requests unsandboxed execution (`dangerouslyDisableSandbox`, `BypassSandbox`, `sandbox: false`, `sandbox_permissions: "require_escalated"`, `with_escalated_permissions: true`), `HookPayload.BypassSandbox` and `DecisionEntry.BypassSandbox` MUST be set. Unsandboxed commands must:
    1. Never auto-allow via `fast_allow` (explicit user `.yolonot` `allow-cmd`/`allow-path` rules remain authoritative).
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

## Full Review Workflow
Whenever the user requests a "full review" (or asks to run the full review suite):
1. Launch these 4 review skills **in parallel** (via subagents in read-only mode):
   - `/security-audit`
   - `/open-code-review-delegate`
   - `/ponytail-review`
   - `/ponytail-audit`
2. Wait until all 4 reports complete, then perform a **mandatory verification pass** against the actual code and existing tests before reporting:
   - Check every finding against existing functionality, unit/E2E tests, and prior review fixes to catch false positives or suggestions that would regress existing behavior.
   - Explicitly separate findings into: (a) **Verified safe fixes** (clear bugs/gaps with zero regression), (b) **Rejected/adjusted suggestions** (proposals that would break existing behavior or prior fixes, explaining why), and (c) **Decisions needed** (if any item requires a product/design choice).
3. **Never take action or modify code based on the review findings without waiting for explicit user instruction.**


