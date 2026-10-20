# Harness compatibility

yolonot shares a shell-command policy across 24 supported adapters (plus retired `gemini` cleanup) unified on `baseHarness` (`internal/yolonot/harness_base.go`). Native prompts,
hook trust and sandbox enforcement remain host-specific. Versions below were
checked in **October 2026**; installed and upstream versions are separate.

| Harness | Installed here | Latest channel checked | Integration |
|---|---|---|---|
| Claude Code CLI | 2.1.299 | [2.1.299 stable](https://github.com/anthropics/claude-code/releases/tag/v2.1.299) | PreToolUse/PostToolUse; allow/ask/deny |
| Claude Desktop (local Code) | 2.37337.1 | App version recorded during native testing; bundled Code version is separate | Classic hooks and optional mod; local model credentials need host env |
| Codex CLI | 0.162.1 | [0.162.1 stable](https://github.com/openai/codex/releases/tag/rust-v0.162.1) | PreToolUse denial plus PermissionRequest approval |
| OpenCode | 2.0.28 | [2.0.28 V2 changelog](https://opencode.ai/changelog) | Final shell transform and native permission evaluation |
| Antigravity CLI (`agy`) | 1.3.5 | [1.3.5 stable](https://github.com/google-antigravity/antigravity-cli/releases/tag/1.3.5) | auto_approve/force_ask/deny |
| Gemini CLI (retired adapter) | 0.46.0 | [0.63.0 upstream](https://github.com/google-gemini/gemini-cli/releases/latest) | Unsupported by yolonot; cleanup only |
| Cursor IDE | 3.24.18 | [3.24 IDE release notes](https://prod.cursor.com/docs/release-notes) | beforeShellExecution/afterShellExecution |
| Cursor CLI | 2026.10.14-0f9edde | Official installer checked 2026-10-14 | Actual CLI hooks and interactive approval tested |

OpenCode's GitHub `releases/latest` currently describes the V1 maintenance
channel (1.19.0), whose notes point to `upgrade --major`. It is not the latest
V2 release. Cursor IDE, Agents Window and CLI version tracks also differ.

## Install and inspect

```bash
yolonot setup --harness opencode
yolonot install --harness claude
yolonot install --harness codex
yolonot install --harness antigravity   # agy is an alias
yolonot uninstall --harness gemini      # remove retired integration
yolonot install --harness cursor
yolonot doctor --harness codex
yolonot audit --harness codex
yolonot status --harness opencode --json
```

Without a target, install/setup use detected harnesses; uninstall uses
installed adapters. `--all` installs all supported adapters; uninstall also includes retired adapters. Targeted
operations leave other hosts alone. Restart the host after installation,
then perform its trust/activation steps. `doctor` confirms registration and
configuration, not that a running agent executes the hooks.

Installers pin the runtime harness. CLI session operations accept
`--session-id`, `--current` and host environment overrides; see
[configuration.md](configuration.md).

## Claude Code CLI and desktop

Installation uses an exec-form command with literal args, a
`Bash|PowerShell` matcher and `onFailure: "block"` for PreToolUse when the
`claude` on PATH reports 2.1.295+. For an older or unreadable version it writes
the quoted shell-command form instead, since an older Claude ignores exec args. `CLAUDE_CONFIG_DIR` is respected, and invalid
settings are reported without overwriting them.
[Claude hook reference](https://code.claude.com/docs/en/hooks).

Classic hooks honor Claude's `bypassPermissions` mode, along with yolonot
pause/disabled mode. Headless runs cannot answer a native ask interactively;
choose an appropriate unresolved/failure policy for automation.

### Claude Desktop model credentials

> **Terminal exports do not prove Desktop key access.** On macOS, Desktop
> imports only `PATH` and selected Claude variables from shell profiles; other
> exports in `.zshrc`/`.bashrc` may be absent. Windows inherits user/system env
> but does not read PowerShell profiles.

In Desktop, open the environment dropdown, choose **Local → gear**, add each
model's `env_key` variable, and start a new local session. The native editor
stores these values encrypted. User-level `~/.claude/settings.json` `env` is
another supported option for Claude sessions. Use the local environment, not
shared project settings, for credentials.
[Claude Desktop environment reference](https://code.claude.com/docs/en/desktop#local-sessions).

This affects model judges and Explain, which may use different keys. A rule,
parser or exec judge can succeed without a model request. A model failure can
also end in `passthrough` under your failure policy: command execution alone
does not prove the model worked. Inspect the exact command in `yolonot log`.
`doctor --probe-models` tests its own process environment; a terminal probe
does not verify a Desktop mod subprocess. See [credential diagnostics](configuration.md#credentials-in-desktop-hosts).

### Claude Code mod

The optional mod (`yolonot install --harness claude --mod`, 2.1.296+) adds a
transcript verdict and Allow once/Allow this session/Explain/Deny dialog.
Replay checks current rules and binds the tool ID, command, cwd and exact
inspected script snapshot. A completed call cannot replay its one-time grant.
Changed or withheld scripts cannot reuse it. The mod does
not receive Claude's permission mode, so it also judges under skip-permissions;
pause yolonot explicitly when intended. Headless mod asks are denied.
The mod judges with the session's current directory and leaves subagent and
teammate calls to the classic hook, which receives their real working
directory; their asks use Claude's own prompt. A `yolonot hook` crash, timeout
or unreadable answer blocks the call.

The mod currently intercepts Bash calls. It is optional: classic hooks work
without it, and skills are independent of it. Allow once grants one tool call;
Allow this session records an exact command/script approval for the current
project and session. Explain calls the configured chat model, then returns to
the choice dialog. Deny blocks the call and records rejection. Explicit deny
rules still win; script changes invalidate approval/replay.

Refresh/removal occurs only when Claude is targeted. Production middleware
fixtures pass, and the candidate mod was driven on CLI 2.1.299 in isolated
tmux sessions: Allow once re-prompted on repetition, Allow this session reused
its grant, Explain returned a live model explanation, and Deny blocked.
Auto mode also preserved the mod ask and explicit allow/deny rules.

Desktop 2.37337.1 was driven in local Auto mode: session reuse, one-time
re-prompt and Deny passed. Duplicate global/project completion hooks exposed
an Allow once scope bug, fixed with explicit grant scope and a native retest.
Desktop Explain initially returned provider HTTP 401; the user subsequently
reported success after adding the key to Desktop's local environment editor.

Direct native ELF/Mach-O executable paths such as `/usr/bin/touch` now have a
separate local snapshot of their full bytes, resolved target and execution
mode (up to 64 MiB), so unchanged files can replay a bound mod answer. Binary
contents are never attached to a model prompt. Snapshotting is limited to
unambiguous direct paths; withheld scripts still prevent replay. This fix was
tested on the actual CLI with global and project hooks; the user subsequently
reported that the Desktop issue appears resolved after retesting. An unanswered ask no longer creates a session rejection; explicit
Deny does. Dismissed or unavailable mod dialogs block only that call without
fabricating a human rejection or session deny.

Classic desktop hooks were tested in Auto mode: allow, deny and native ask
approval/rejection worked. A repeated native Allow once asked again after the
approval-scope fix. Managed deployments can disable user-tier classic hooks,
so inspect the host's effective policy.

## Codex CLI and local desktop

PreToolUse emits explicit deny; allow/ask otherwise defer to Codex. A separate
PermissionRequest hook returns `decision.behavior: allow|deny` for an actual
host approval request; ask leaves that request for the configured host reviewer.
With `approvals_reviewer = "auto_review"`, a reviewer agent can approve it
without a human dialog. Use the app's Ask for approval mode for human review;
PreToolUse alone still cannot force a prompt on every command. Because Codex
may run a deferred ask without a human, a completed call after an ask is not
logged as a human approval. Current rules
are checked again. A paired PermissionRequest is not mistaken for a rejected
retry.

Hooks are enabled by default in current Codex. `features.hooks` is canonical;
`codex_hooks` is deprecated; installation migrates it to `hooks`, preserving
comments and unrelated TOML. If both exist, only the canonical flag remains
active. Installation
respects `CODEX_HOME`. **Review/trust the exact hook in `/hooks`** after
install or changes: an untrusted user hook is skipped. Registration alone
is insufficient. [Codex hook reference](https://learn.chatgpt.com/docs/hooks).

`codex exec` reports `bypassPermissions` for its Never approval policy; this
does not disable yolonot's Codex adapter. Only Claude honors that automatic
bypass. Default high/critical tiers deny and moderate defers to the host.
Codex cannot force a prompt for every PreToolUse call, so a configured
failure action of ask becomes deny.

Local Codex desktop sessions use the supported hook engine. This machine has
ChatGPT with integrated Codex, 26.1007.30912 (build 20156), reported up to date
by its configured updater. Actual Codex app-server routing was tested: hook
allow removed a frontend approval request; ask reached the frontend. Actual
desktop allow/deny and PermissionRequest routing also passed in a managed
`on-request`/`auto_review` session. The ask marker executed without becoming
a session grant. Human approval/rejection also passed after switching the
same chat to Ask for approval (`approvals_reviewer = "user"`): the request
waited with no marker, approval executed, and rejection returned
`rejected by user` with no execution/Post event. Auto-review intentionally
uses a reviewer agent instead; see [Auto-review](https://learn.chatgpt.com/docs/sandboxing/auto-review). Cloud-orchestrated Work has separate managed
hook rules; local command hooks are not general cloud enforcement.

## OpenCode V2 migration

V2 requires a default `{id, setup}` definition and domain APIs. The old named
`YolonotPlugin` alone fails to load on 2.0.28. V2 uses the `shell` tool with
`{command, workdir}`, replacing the old bash/cwd assumptions.

The new shim uses `ctx.tool.transform` to wrap the final shell executor and
`ctx.permission.hook("evaluate")` for native allow/ask. Classification occurs
after execute-before middleware has finished rewriting arguments. An earlier
call-ID verdict cannot authorize different final input. Explicit host denies
remain authoritative. Successful empty hook output leaves native permissions
unchanged. PostToolUse follows successful execution only; temporary verdict
state is cleaned up.

V2 subprocesses set `YOLONOT_OPENCODE_API=2`. Moderate risk can ask; high and
critical retain their hard-deny floor. The plugin subscribes to the 2.0.28 SDK
`permission.asked` (matched by the shell call's `tool.callID`) and
`permission.replied` (`once`, `always`, `reject`) events and forwards the
human's resolution to `yolonot hook` as `PermissionReplied`, recording
`allow_once`, `ask_approved` (with session approval) or `ask_rejected` (with
session deny). Read-only diagnostics infer the marker
from the installed V2 CLI. V1 keeps its legacy named/server exports and its
older host-deferred ask behavior.

Installation writes `${XDG_CONFIG_HOME:-~/.config}/opencode/plugins/yolonot.ts`
and removes an owned old `plugin/yolonot.ts` copy to avoid double execution.
Both directory spellings work in the tested V2 loader; discovery was not the
original migration failure. Binary paths are JSON escaped, and stderr is
drained while waiting for the subprocess. Reinstall, restart OpenCode and
inspect `opencode plugin list`. [Plugin docs](https://opencode.ai/docs/plugins/).

## Antigravity and Gemini CLI

Google ended Gemini CLI access for individual free/Pro/Ultra accounts on
18 June 2026; enterprise and paid API-key access remain supported. yolonot
uses Antigravity for supported Google CLI workflows.
[Google's transition announcement](https://github.com/google-gemini/gemini-cli/discussions/27274).

Antigravity uses a named-hook map in `~/.gemini/config/hooks.json`, matches
`run_command`, and reads `toolCall.args.CommandLine/Cwd`. Allow maps to
`auto_approve`, ask to `force_ask`, and deny blocks. `force_ask` is used
deliberately instead of `ask` (`"ask"` respects Antigravity's cached `"Always
Allow"` grants in `~/.gemini/config/config.json` and
`~/.gemini/config/projects/<uuid>.json`, which would silently bypass a fresh
yolonot ask or `BypassSandbox` review; `"force_ask"` ignores cached host grants
and narrows the native prompt to a one-time Allow/Deny confirmation). Because
Antigravity's hook protocol (`hooks_go_proto`, checked through `agy` 1.4.2)
only emits `SessionStart`, `PreToolUse`, `PostToolUse`, `PreInvocation`,
`PostInvocation`, `Stop`, `OnCompaction` and `OnToolError` — with no
`PermissionReplied` event and no chosen grant-scope field (`once`, `session`,
`workspace`, `always`) on `PostToolUse` — completed native asks are logged as
`allow_once` and do not auto-widen to a session grant (use `yolonot approve` or
`yolonot suggest` to persist approvals until Antigravity exposes the user's
permission-scope selection to hooks). When yolonot is active,
`auto_approve` also satisfies Antigravity's `BypassSandbox: true` gate for
allowed commands; when a session is paused (`yolonot pause`), yolonot emits
an empty passthrough (`{}`) and Antigravity falls back to its native manual
approval prompt on `BypassSandbox: true`. Installed commands pin
the phase because payloads omit the event name. A `run_command` the adapter
cannot read (no command, or no `Cwd` in a multi-root workspace) is denied
instead of left to the host. Restart `agy` and inspect
`/hooks`. [Antigravity hooks](https://www.antigravity.google/docs/hooks/).

**yolonot has retired Gemini CLI support.** This is our support decision;
it does not mean Google's enterprise/API service has ended. New setup and
install operations reject `--harness gemini` and omit it from `--all`.
Legacy adapter code remains to read existing settings, diagnose registrations
and safely remove hooks/skills:

```bash
yolonot uninstall --harness gemini
yolonot install --harness antigravity
```

Migration does not copy account credentials or blindly translate host settings.

## Cursor

Hooks live in `~/.cursor/hooks.json`, with flat permission responses. Current
docs describe native ask; earlier installed behavior motivated the existing
passthrough default. Native ask is now an explicit opt-in:

```bash
YOLONOT_CURSOR_NATIVE_ASK=1 cursor-agent
```

Without it, asks defer to host permissions. With it, lower-tier asks emit
`permission: "ask"`; high/critical retain the deny floor unless explicitly
overridden. Native Run/Skip prompts were verified on IDE 3.24.18, including
marker absence before approval and after rejection. CLI 2026.10.14 also
showed an actual hook-requested Run once/Skip approval dialog.
CLI `--force`/`--yolo` automatically accepts native asks even with this opt-in;
use ordinary interactive mode when an actual human response is required.
An explicit deny remains enforced in force mode. Cursor CLI also sends
`afterShellExecution` for a skipped command, with the same empty output as a
successful silent command. This event therefore records neither human approval
nor a durable session grant. A later request asks again; explicit session
allow/deny decisions use the shared CLI.
`failClosed` is not blindly enabled: Cursor can treat intentional empty
passthrough as hook failure, breaking pause and host-deferred actions.
[Cursor hooks](https://cursor.com/docs/hooks).

Session stdin uses `conversation_id`; `YOLONOT_CURSOR_SESSION_ID` targets CLI
operations from an external shell. Tool-use identifiers are retained when
supplied. Install/uninstall preserve unrelated hooks and permissions and
report malformed host configuration.

## Native skills

All supported adapters install the same management skill, rendered for the host.
It covers session decisions, profiles, risk policy, judges/models, rules/hints,
learning, diagnostics and installation. Mutations require explicit user instruction;
this skill does not enforce safety itself. Hooks enforce shell decisions.
Refresh only the skill with `yolonot install --harness <host> --skill-only`.
The byte-identical legacy Claude skill is backed up on migration; customized
skills are preserved and installation refuses to overwrite them.

In Codex Desktop, select `@yolonot` from the composer or the Skills panel.
Codex CLI/IDE can use `$yolonot`. Installed skills are discovered dynamically;
restart the app if a new skill has not appeared. A running conversation may
retain its earlier skill catalog. No optional Claude mod UI is ported by this skill.

| Host | Skill directory |
|---|---|
| Claude | `~/.claude/skills/yolonot` (or configured Claude root) |
| Codex | `~/.agents/skills/yolonot` |
| OpenCode | `${XDG_CONFIG_HOME:-~/.config}/opencode/skills/yolonot` |
| Antigravity CLI | `~/.gemini/antigravity-cli/skills/yolonot` |
| Gemini (retired; cleanup only) | `~/.gemini/skills/yolonot` |
| Cursor | `~/.cursor/skills/yolonot` |

## Verification scope

Real installed Claude/Codex processes used local scripted model endpoints,
dummy credentials and isolated configurations. OpenCode V2 used its actual
server/tool/permission APIs without a model account. Harmless markers proved
allow execution, deny blocking, ask approval/rejection and host-deny
preservation. Codex app-server also checked a changed deny rule between Pre
and PermissionRequest. User settings and remote model accounts were untouched.
Google/Cursor adapter fixtures do not prove a live host prompt UI. An isolated
Antigravity/Gemini initially stopped at authentication. After the user signed in,
Antigravity 1.3.5 passed actual CLI allow/deny/headless ask and interactive
approval/rejection. Cursor IDE 3.24.18 passed allow/deny/native ask approval
and rejection plus empty-output passthrough. These follow-up tests used
temporary project hooks and existing user logins; no credentials were copied.
Cursor CLI 2026.10.14-0f9edde also passed actual allow/deny checks. Its
`--force` mode automatically permits a hook ask; explicit deny still blocks.
Interactive CLI asks show a hook-requested approval dialog. Empty/omitted
`cwd` now resolves from the primary `workspace_roots` entry, so wrappers that
change their own working directory cannot skip project rules. Explicit command
`cwd` wins, including relative paths resolved under that root.
Gemini support is retired. These are dated native checks, not certification
for every host/model/account combination. Preserve redacted per-run evidence
separately from portable source tests.

## Extended harness adapters (19 additional hosts)

The 19 additional harnesses below are registered `yolonot` adapters built on the unified `baseHarness` (`internal/yolonot/harness_base.go`), inspected against their upstream source repositories and compiled binaries on **19–20 October 2026**, and verified end-to-end in `e2e/extended_harnesses_test.go` and `e2e/auth_test.go`.

An adapter needs an enforceable pre-execution contract, a supported install path and reproducible lifecycle tests. A generic MCP connection alone does not intercept arbitrary shell commands.

### Extended harness overview matrix

| # | Harness | Installed version | Source / distribution | Primary hook config | Reads `.claude/settings.json`? | Shell tool (`input` field) | Stdin schema & `cwd` | Verified `allow` / `ask` / `deny` |
|---|---|---|---|---|---|---|---|---|
| 1 | **Crush** (`crush`) | `0.98.1` | Source-available (`FSL-1.1-MIT`, Go, [`charmbracelet/crush`](https://github.com/charmbracelet/crush)) | `~/.config/crush/crush.json`, `.crush/crush.json` | No | `bash` (`command`) | `snake_case` (`event`, `cwd`, `session_id`) | **allow + deny** (`ask` maps to `DecisionNone` passthrough) |
| 2 | **Qwen Code** (`qwen`) | `0.25.3` | Open-source (`Apache-2.0`, TS, [`QwenLM/qwen-code`](https://github.com/QwenLM/qwen-code)) | `~/.qwen/settings.json`, `.qwen/settings.json` | No | `run_shell_command`, `monitor` (`command`) | `snake_case` (`hook_event_name`, `cwd`, `session_id`) | **allow + ask + deny** (`allow` needs `PermissionRequest`; `ask`/`deny` on `PreToolUse`) |
| 3 | **Z.AI ZCode** (`zcode`) | `3.15.3-37` (`0.16.9`) | Open-source repo ([`zai-org/ZCode`](https://github.com/zai-org/ZCode)) + bundled `@zcode/cli` | `~/.zcode/cli/setting.json` (`hooks.enabled: true`, `hooks.events.*`) | CLI: No; Desktop: **Yes** | `Bash` (`command`, `dangerouslyDisableSandbox`) | Both `snake_case` & `camelCase`, has `cwd` | **allow + ask + deny** (`PreToolUse` and `PermissionRequest`) |
| 4 | **GitHub Copilot CLI** (`copilot`) | `1.0.98` | Closed-source (`@github/copilot` SEA + Rust `runtime.node`) | `~/.copilot/settings.json`, `.github/copilot/settings.json`, `.github/hooks/*.json` | No (reads `extraKnownMarketplaces` only) | `bash`, `powershell`, `local_shell` (`command`, `requestSandboxBypass`) | Both `snake_case` & `camelCase`, has `cwd` | **allow + ask + deny** (`preToolUse` and `permissionRequest`; fail-closed on hook error) |
| 5 | **Grok Build** (`grok`) | `1.0.62` | Closed-source (`@xai-official/grok` native Rust `grok-native`) | `~/.grok/config.toml`, `~/.grok/hooks/*.json`, `.grok/hooks/*.json` | **Yes (global & project by default)** | `run_terminal_command` (`command`; aliases `Bash`/`Shell`) | `camelCase` (`sessionId`, `toolName`, `toolInput`, `cwd`) + `hook_event_name` | **ask + deny** (`allow` means "not blocked" only; no `PermissionRequest` event) |
| 6 | **DeepSeek Harness** (`dsh`) | `0.2.1-rc.2` | Open-source (`MIT`, TS, [`deepseek-ai/deepseek-harness`](https://github.com/deepseek-ai/deepseek-harness)) | `$DSH_HOME/cordis.patch.yml` → `dsh-hooks-claude-code` `configPath` | Only if `configPath` points to it | `bash`, `pwsh` (`command`, `sandbox_permissions`) | `snake_case`, has `cwd` | **ask + deny** (`allow` passes to `next()` without bypassing downstream gates) |
| 7 | **Hermes** (`hermes`) | `0.9.0` (`2026.9.24`) | Open-source (`MIT`, Python, [`NousResearch/hermes-agent`](https://github.com/NousResearch/hermes-agent)) | `~/.hermes/config.yaml` (`hooks.pre_tool_call`) | No | `terminal` (`command`) | `snake_case`, has `cwd` | **ask + deny** (`action: "approve"` prompts human; `action: "block"` / exit `2` denies) |
| 8 | **Kimi Code** (`kimi`) | `2.2.0` | Open-source (`MIT`, TS, [`MoonshotAI/kimi-code`](https://github.com/MoonshotAI/kimi-code)) | `~/.kimi-code/config.toml` (`[[hooks]]`) | No | `Bash` (`command`; `Shell` in legacy v1) | `snake_case`, has `cwd` (`tool_call_id`) | **deny only** (`permissionDecision: "deny"` or exit `2`; `allow`/`ask` passthrough) |
| 9 | **Devin CLI** (`devin`) | `3000.11.92` | Closed-source (Rust binary, Cognition `devin-cli`) | `~/.config/devin/hooks.v1.json`, `.devin/hooks.v1.json` | **Yes (global & project `.claude/settings*.json` + `.windsurf/hooks.json`)** | `exec` (`command` in Claude mode, `tool_args.command` in native) | `snake_case`, has `cwd` | **allow + ask + deny** (verified in `EventHandlerMut<PreTool>::handle`) |
| 10 | **Muse Code** (`muse`) | `1.4.11` (`R6667.1`) | Closed-source (Rust binary, Meta) | `~/.config/muse/settings.json` (`schema_version: 1`) | No | `bash` (`command`; matcher `"Bash"` aliases `bash`, `shell`, `exec_command`, `execute_command`) | `snake_case`, has `cwd` | **allow + ask + deny** (`ask`/`deny` on `PreToolUse`; `allow` requires `PermissionRequest`) |
| 11 | **Goose** (`goose`) | `1.55.0` | Open-source (`Apache-2.0`, Rust, [`block/goose`](https://github.com/block/goose)) | `~/.agents/plugins/<name>/hooks/hooks.json`, `.agents/plugins/<name>/hooks/hooks.json` | No (skills only) | `shell` / `developer__shell` (`command`) | `snake_case` (`event`, `working_dir`, `tool_call_id`) | **deny only** (`PreToolUse` runs after native approval; exit `2` or `decision: "block"`) |
| 12 | **OpenHands** (`openhands`) | `1.16.0` (SDK `1.21.0`) | Open-source (`MIT`, Python, [`All-Hands-AI/OpenHands`](https://github.com/All-Hands-AI/OpenHands)) | `.openhands/hooks.json` or `~/.openhands/hooks.json` | No | `terminal` (`command`) | `snake_case` (`event_type`, `working_dir`, `session_id`) | **deny only** (`decision: "deny"`, `continue: false` or exit `2`; `ASK` is commented out as future) |
| 13 | **Kiro CLI v3** (`kiro-cli`) | `2.32.0` | Closed-source (Rust binary, AWS `kiro.dev`) | `~/.kiro/agents/<agent>.json`, `.kiro/agents/<agent>.json` | No | `shell` / `execute_bash` / `execute_cmd` (`command`) | `snake_case` keys, `hook_event_name: "preToolUse"`, has `cwd` | **deny only** (exit `2` blocks; exit `0` stdout is injected into LLM prompt) |
| 14 | **Cline** (`cline`) | `3.0.73` (`@cline/core` `0.0.29`) | Open-source (`Apache-2.0`, TS, [`cline/cline`](https://github.com/cline/cline)) | `~/.cline/hooks/PreToolUse`, `.clinerules/hooks/PreToolUse`, `.cline/hooks/PreToolUse` | No | `run_commands` (`commands: string[]`; legacy VS Code: `execute_command`) | Hybrid (`hookName: "tool_call"`, `workspaceRoots[0]`, `tool_call` + `preToolUse`) | **deny only** (`{"cancel": true}` aborts run; `review: true` is parsed but ignored in `0.0.29`) |
| 15 | **Kilo Code** (`kilo`) | `7.8.12` | Open-source (`MIT`, TS, [`Kilo-Org/kilocode`](https://github.com/Kilo-Org/kilocode)) | `~/.config/kilo/plugins/*.{ts,js}`, `.kilocode/plugins/*.{ts,js}` | No | `bash` (`command`, `workdir`; `sandbox_escalation` permission) | OpenCode V1 plugin API (`_ctx.directory` + `args.workdir`) | **allow + ask + deny** (via V1 `tool.execute.before` + `permission.asked`/`permission.replied`) |
| 16 | **OpenClaw** (`openclaw`) | `2026.10.5` | Open-source (`MIT`, TS, [`openclaw/openclaw`](https://github.com/openclaw/openclaw)) | `~/.openclaw/extensions/<id>/` (`openclaw.plugin.json` + `index.js`) | No | `exec` (`command`, `workdir`, `elevated`, `host`) | In-process `before_tool_call` (`params.workdir` or `process.cwd()`) | **allow + ask + deny** (`block: true` denies; `requireApproval` prompts user with `onResolution`) |
| 17 | **Pi** (`pi`) | `1.3.0` | Open-source (`MIT`, TS, [`badlogic/pi-mono`](https://github.com/badlogic/pi-mono)) | `~/.pi/agent/extensions/*.{ts,js}`, `.pi/extensions/*.{ts,js}` | No | `bash`, `powershell` (`command`) | In-process `tool_call` (`ctx.cwd`) | **allow + ask + deny** (`{ block: true }` denies; `ctx.ui.confirm` prompts user) |
| 18 | **Reflection Mirror** (`mirror`) | `0.1.33` | Open-source (`Apache-2.0`, Python + Rust, [`reflection-oss/mirror`](https://github.com/reflection-oss/mirror)) | `~/.mirror/extensions/<name>/extension.py`, `.mirror/extensions/<name>/extension.py` | No | `bash` (`command`) | In-process `Extension` (`context.workspace.cwd`) | **allow + ask + deny** (`SendApprovalDecision` / `DecideApproval` on `hitl_request`) |
| 19 | **Amp** (`amp`) | `0.0.1792411243-gb8cffc` | Closed-source (`@sourcegraph/amp` / `@ampcode/cli` Bun binary) | `~/.config/amp/plugins/*.ts`, `.amp/plugins/*.ts` (or `amp.permissions` `delegate`) | No | `Bash` (`cmd`, `cwd`), `shell_command` (`command`, `workdir`) | In-process `tool.call` (`ctx.system.workspaceRoot` + `input.cwd`/`workdir`) | **allow + ask + deny** (`action: 'allow'`, `action: 'reject-and-continue'`, `ctx.ui.confirm`) |

---

### Collateral `.claude/settings.json` consumers (Grok Build, Devin CLI, ZCode Desktop)

Three extended harnesses also load `~/.claude/settings.json` and `<project>/.claude/settings.json` in their compatibility layers:

1. **Grok Build (`grok 1.0.62`)**: `[compat.claude] hooks = true` is enabled by default. Grok aliases `Bash` to `run_terminal_command` and sends `sessionId`, `toolName`, `toolInput`, `toolUseId` and `permissionMode` in `camelCase` alongside `hook_event_name: "PreToolUse"`. `parseFlexibleHookPayload` (used by both `ClaudeHarness` and `GrokHarness`) normalizes both `snake_case` and `camelCase` fields, while `yolonot install --harness grok` installs a dedicated `~/.grok/hooks/yolonot.json` hook file.
2. **Devin CLI (`devin 3000.11.92`)**: `config-importers` (`Provider::Claude`) automatically imports `~/.claude/settings.json`, `.claude/settings.json` and `.claude/settings.local.json`, and uses `HookFormatKind::Claude` (`snake_case` payload with `cwd`). Because `ClaudeEventInput::from(&EventInput)` preserves Devin's tool name `"exec"` verbatim instead of translating it to `"Bash"`, `yolonot install --harness devin` registers `"matcher": "exec"` in `~/.config/devin/config.json`.
3. **ZCode Desktop**: `hooksService.ts` (`loadLegacyHooksFromLocation`) loads `~/.claude/settings.json` and `<workspace>/.claude/settings.json` (whereas standalone `zcode` CLI reads `~/.zcode/cli/setting.json` with `hooks.enabled: true` and `hooks.events.*`, handled by `yolonot install --harness zcode`).

---

### Non-hook integration matrix (`rules discover`, `audit`, `InstallSkill`, `SessionIDFromEnv`)

| # | Harness | Native rule config (`yolonot rules discover`) | Rule syntax & `.claude/settings.json` permissions | Host permission alerts (`host_permissions`) | Host sandbox alerts (`host_sandbox`) | Primary skill paths (`InstallSkill`) | Shell & hook env vars (`SessionIDFromEnv` / `ActiveHarness`) |
|---|---|---|---|---|---|---|---|
| 1 | **Crush** (`crush`) | `/etc/crush/crush.json`, `~/.config/crush/{crush.json,crushrc}`, `~/.local/share/crush/crush.json`, `.crush/crush.json`, `.crush.json`, `crush.json`, `.crushrc` | Tool-level only (`permissions.allowed_tools`, `options.disabled_tools`, `crushrc` `permissions allow/deny`); does **not** read `.claude` permissions | `permissions.allowed_tools` has `"bash"`/`"bash:execute"`; `crushrc` `permissions allow bash`; `--yolo` / `-y`; `crush run` | **No OS sandbox** (in-process `mvdan.cc/sh/v3/interp` with AST `blockFuncs`) | `~/.config/crush/skills` (also scans `~/.agents/skills`, `~/.claude/skills`; project `.agents/skills`, `.crush/skills`, `.claude/skills`, `.cursor/skills`) | Shell: `CRUSH=1`, `AGENT=crush`, `AI_AGENT=crush` (no session ID); Hook: `CRUSH_SESSION_ID` |
| 2 | **Qwen Code** (`qwen`) | `/Library/Application Support/QwenCode/settings.json` (macOS) / `/etc/qwen-code/settings.json` (Linux), `~/.qwen/settings.json`, `.qwen/settings.json` | Claude-style `permissions.{allow,ask,deny}` (`Bash(...)`, `Read(...)`, `Edit(...)`, `Write(...)`, `WebFetch(domain:...)`) + `permissions.autoMode.{environment,hints}` + legacy `tools.{allowed,exclude}`; does **not** read `.claude` permissions | `tools.approvalMode: "yolo"` (or `"auto"`), `tools.autoAccept: true`, `permissions.allow` has `"Bash"`/`"run_shell_command"`; `--yolo` / `-y` | `tools.sandbox` (`false` default; `true`/`"docker"`/`"podman"`/`"sandbox-exec"`), `tools.executionSandbox` (`bwrap`/`landlock`, `filesystem`, `network`) | `~/.qwen/skills` (also scans `~/.agents/skills`; project `.qwen/skills`, `.agents/skills`) | Shell & Hook: `QWEN_CODE_SESSION_ID`, `QWEN_CODE_CLI=1`, `QWEN_CODE_PROJECT_DIR` |
| 3 | **Z.AI ZCode** (`zcode`) | `~/.zcode/cli/{setting.json,config.json}`, `zcode.json`, `.zcode/config.json`, plus SQLite `~/.zcode/cli/db/db.sqlite` (`local_setting` `namespace='permission'`) | JSON: tool-level `permission.{allowedTools,disallowedTools}`; SQLite: `{allow,ask,deny}: [{toolName: "Bash", ruleContent: "git status:*"}]`; does **not** read `.claude` permissions | `permission.mode: "yolo"` or `"guarded"`, `permission.autoApproveHighRisk: true`, `permission.allowedTools` has `"Bash"`; `--mode yolo` | **No OS sandbox** (host sandbox removed from execution adapter; `dangerouslyDisableSandbox` field still forwarded in `tool_input`) | `~/.zcode/skills` (also scans `~/.agents/skills`; project `.zcode/skills`, `.agents/skills`) | Shell: `ZCODE_RUNTIME_ENV`, `ZCODE_APP_CLI_VERSION`; Hook: `ZCODE_SESSION_ID`, `CLAUDE_SESSION_ID` |
| 4 | **GitHub Copilot CLI** (`copilot`) | `/Library/Application Support/GitHubCopilot/managed-settings.json` (macOS), `~/.copilot/settings.json`, `~/.copilot/config.json` (`locations.*.tool_approvals`), `.github/copilot/settings(.local).json` | `managed-settings.json`: `permissions.{allow,ask,deny,limitTo}` (`Bash(...)`, `Shell(...)`, `PowerShell(...)`, `Read(...)`, `Edit(...)`, `Write(...)`, `Domain(...)`, `Mcp(...)`); `settings.json`: `allowedUrls`, `deniedUrls`; does **not** read `.claude` permissions | `defaultPermissionMode: "allow-all"`, `defaultMode: "autopilot"`, `COPILOT_ALLOW_ALL=true`, `--allow-all` / `--yolo` | MXC sandbox (`sandbox.enabled: false` default; Seatbelt on macOS, `bwrap`+netns on Linux, ProcessContainer on Windows; `sandbox.allowBypass`, `sandbox.userPolicy`) | `~/.copilot/skills` (also scans `~/.agents/skills`; project `.github/skills`, `.agents/skills`, `.claude/skills`) | Shell: `COPILOT_CLI_BINARY_VERSION`, `COPILOT_CLI_RESOLVED_DIST_DIR`; Hook: `COPILOT_PROJECT_DIR` (stdin `session_id`) |
| 5 | **Grok Build** (`grok`) | `/etc/grok/{requirements,managed_config}.toml`, `~/.grok/{requirements,managed_config,config}.toml`, `.grok/config.toml`, `~/.grok/sessions/*/permission.toml` **plus `.claude/settings*.json` & Claude `managed-settings.json`** | Native TOML `[permission]` `allow`/`ask`/`deny` (`"Bash(git *)"`) and structured `rules = [{action, tool, pattern}]`; **also reads `.claude/settings(.local).json` & Claude `managed-settings.json` `permissions`!** | `[ui] permission_mode = "always-approve"` / `"bypassPermissions"`, `--always-approve` / `--yolo` (locked via `[ui] disable_bypass_permissions_mode = true`) | `[sandbox] profile` (`"off"` default; `"workspace"`, `"devbox"`, `"read-only"`, `"strict"` via Seatbelt / Landlock+`bwrap`+seccomp; custom `sandbox.toml`) | `~/.grok/skills` (also scans `~/.agents/skills`, `~/.claude/skills`, `~/.cursor/skills` globally & per-project) | Shell: `GROK_AGENT=1`; Hook: `GROK_SESSION_ID`, `GROK_HOOK_EVENT`, `GROK_WORKSPACE_ROOT` |
| 6 | **DeepSeek Harness** (`dsh`) | None (one-shot grants only; no persistent allow/deny rule store) | No rule DSL; does **not** read `.claude` permissions | `DSH_PERMISSION_MODE=danger-full-access`; `~/.dsh/cordis.patch.yml` & `profiles/*/cordis.patch.yml`: `sandbox-policy.config.mode: danger-full-access`, `approval.config.policy: never`, `permission.config.defaultPreset: danger-full-access` | `dsh-sandbox-local` (Seatbelt on macOS, `bwrap`/`landlock` on Linux, `windows-acl` on Windows); disabled when `sandbox-policy.config.mode == "danger-full-access"` | `~/.dsh/skills` (`$DSH_HOME/skills`) and `~/.agents/skills` (project `.dsh/skills`, `.agents/skills`) | Shell: `DSH_SESSION_ID`, `DSH_SHELL=1`, `DSH_HOME`, `DSH_PROFILE` |
| 7 | **Hermes** (`hermes`) | `~/.hermes/config.yaml` (`$HERMES_HOME/config.yaml` or `profiles/<p>/config.yaml`) | `command_allowlist` (`fnmatchcase` globs / pattern keys) and `approvals.deny` (hard-floor `fnmatch` globs); does **not** read `.claude` permissions | `HERMES_YOLO_MODE=1`, `--yolo`; `config.yaml`: `approvals.mode: off` (or YAML `false`), `approvals.{cron_mode,single_query_mode,unattended_mode}: approve` | `terminal.backend`: `"local"` (**default, unsandboxed host execution**); `"docker"` with `docker_mount_cwd_to_workspace: true` or host bind mounts in `docker_volumes` | `~/.hermes/skills` (`$HERMES_HOME/skills`; project `.hermes/skills` & `.agents/skills` only when listed in `skills.trusted_project_dirs`) | Shell: `HERMES_SESSION_ID`, `HERMES_HOME`, `HERMES_SCRATCH_DIR` |
| 8 | **Kimi Code** (`kimi`) | `~/.kimi-code/config.toml` (`$KIMI_CODE_HOME/config.toml`) | `[permission]` `[[permission.rules]]` (`decision = "allow"\|"ask"\|"deny"`, `pattern = "Bash(...)"` / `"Read(...)"` / `"Write(...)"` / `"Edit(...)"`, picomatch globs); does **not** read `.claude` permissions | `~/.kimi-code/config.toml`: `default_permission_mode = "auto"` (approves all, skips dangerous guard) or `"yolo"`, `permission.dangerous_command_guard = false`, `KIMI_CODE_DANGEROUS_COMMAND_GUARD=false`; legacy `~/.kimi/config.toml`: `default_yolo = true` | **No OS sandbox** | `~/.kimi-code/skills` and `~/.agents/skills` (project `.kimi-code/skills`, `.agents/skills`; legacy v1 `~/.kimi/skills`) | Shell: none injected (`session_id` only on hook stdin JSON) |
| 9 | **Devin CLI** (`devin`) | `/Library/Application Support/Devin/system.json` (macOS) / `/etc/devin/system.json` (Linux), `~/.config/devin/config.json`, `.devin/config.json`, `.devin/config.local.json` | `permissions.{allow,ask,deny}` (`Exec(<word-prefix>)`, `Read(<glob>)`, `Write(<glob>)`, `Fetch(<url\|domain:...>)`, `exec`, `edit`, `read`, `mcp__*`); does **not** read `.claude` permissions (only hooks/skills/CLAUDE.md) | `DEVIN_PERMISSION_MODE=dangerous\|bypass\|yolo\|autonomous`, `--permission-mode`; `permissions.allow` has `"exec"` or `"Exec(*)"` | Off by default (`--sandbox` / `DEVIN_SANDBOX=1` enables Seatbelt / `bwrap`+`seccomp`); **`sandbox.excluded.allow`** runs matched `Exec(...)` commands outside the sandbox without prompting | `~/.config/devin/skills`, `~/.agents/skills` (project `.devin/skills`, `.agents/skills`, `.claude/skills`) | Hook: `DEVIN_PROJECT_DIR` + stdin `session_id`; Shell (`exec`): no `DEVIN_SESSION_ID` |
| 10 | **Muse Code** (`muse`) | `~/.config/muse/approval-policy.json`, `~/.config/muse/settings.json` (`permissions.profiles`), enterprise policy plane | `approval-policy.json`: `rules[]` (`effect: "allow"\|"deny"\|"prompt"`, `rule.kind`: `shell_command_argv_prefix`, `shell_command_exact_raw`, `tool_action`, `filesystem`, `network`, `unix_socket`); does **not** read `.claude` permissions | `settings.json`: `permissions.default_profile == ":unrestricted"`, custom profile `approval: "allow_all"`; `--yolo`, `--disable-approval`, `MUSE_PERMISSION_PROFILE_FAIL_OPEN=1`, `MUSE_DISABLE_APPROVAL_JUDGE=1` | ON by default (Seatbelt on macOS, `bwrap` on Linux); weakened by `permissions.default_profile == ":unrestricted"`, profile `filesystem: "unrestricted"` or `network: "enabled"`, `--disable-sandbox` | `~/.config/muse/skills` (`$XDG_CONFIG_HOME/muse/skills`; project `.agents/skills`; also imports `~/.claude/skills` & `~/.codex/skills`) | Shell & Hook: **`MUSE_SESSION_ID`**, `MUSE_THREAD_ID`, `MUSE_RELEASE_INFO` (also sets `CLAUDE_CODE_TOOL_USE_ID` — check `MUSE_SESSION_ID` before `CLAUDE_*`!) |
| 11 | **Goose** (`goose`) | `~/.config/goose/permission.yaml` (`$GOOSE_PATH_ROOT/config/permission.yaml`) | Tool-level only under `user.{always_allow,ask_before,never_allow}` (`shell`, `developer__shell`, `write`, `edit`); does **not** read `.claude` permissions | **`GOOSE_MODE` defaults to `"auto"` when unset** (auto-approves all tools and ignores `permission.yaml`!); `user.always_allow` containing `shell` / `developer__shell` | **No OS sandbox** (and escapes Flatpak via `flatpak-spawn --host`) | `~/.agents/skills`, `~/.config/goose/skills`, `~/.claude/skills` (project `.agents/skills`, `.goose/skills`, `.claude/skills`) | Shell: **`AGENT_SESSION_ID`** |
| 12 | **OpenHands** (`openhands`) | None (no static command/file allow/deny list in `agent_settings.json` or `cli_config.json`) | Per-conversation `confirmation_policy` (`NeverConfirm`, `ConfirmRisky`, `AlwaysConfirm`) in `~/.openhands/conversations/*/base_state.json`; does **not** read `.claude` permissions | `--always-approve` / `--yolo`, `--headless`; `base_state.json` `confirmation_policy.kind == "NeverConfirm"` (default in `ConversationState`) or `"ConfirmRisky"`; `security_policy_filename: null` | CLI uses `LocalWorkspace` (**no OS or container sandbox**; Docker sandbox is only in OpenHands App Server) | `~/.agents/skills` (#1 priority), `~/.openhands/skills` (project `.agents/skills`, `.openhands/skills`) | Hook: `OPENHANDS_SESSION_ID`, `OPENHANDS_PROJECT_DIR`; Shell (`terminal`): none |
| 13 | **Kiro CLI v3** (`kiro-cli`) | `/Library/Application Support/Kiro/managed-settings.json` (macOS) / `/etc/kiro/managed-settings.json` (Linux), `~/.kiro/settings/permissions.{yaml,json}`, `~/.kiro/workspace-roots/<hash>/permissions.{yaml,json}`, `~/.kiro/agents/*.json`, `.kiro/agents/*.json`, `.kiroignore` | V3 `rules[]` (`capability: shell\|fs_read\|fs_write\|mcp\|all`, `match: [...]`, `exclude: [...]`, `effect: allow\|ask\|deny`) + `policies[]`; V2 `allowedTools` + `toolsSettings.shell.{allowedCommands,deniedCommands}` (regex); does **not** read `.claude` permissions | `-a` / `--trust-all-tools`; `cli.json` `chat.disableTrustAllConfirmation: true`, `policyPreset: ["allow-all"]`; `permissions.yaml` `policies: ["allow-all"]` or `capability: all\|shell` `effect: allow` | `~/.kiro/settings/sandbox.json` and `.kiro/settings/sandbox.json` (Seatbelt / `bwrap` in KAS, but interactive `kiro-cli chat` runs unsandboxed in `2.32.0`) | `~/.kiro/skills` and `.kiro/skills` (does **not** scan `~/.claude/skills` or `~/.agents/skills`) | V3 Shell & Hook: **`KIRO_SESSION_ID`**, `AWS_SDK_UA_APP_ID=kiro-agent`; V2 Shell: `KIRO_CHAT_SHELL=1`, `AMAZON_Q_CHAT_SHELL=1` |
| 14 | **Cline** (`cline`) | `~/.cline/data/settings/global-settings.json`, `<workspace>/.clineignore` | Tool enablement only in `global-settings.json` (`tools.use_Bash.enabled`, `disabledTools`); gitignore-style path blocks in `.clineignore`; does **not** read `.claude` permissions | **`toolAutoApprove` defaults to `true` when unset** in `global-settings.json`; `CLINE_TOOL_APPROVAL_MODE=auto\|allow`; **`-y` / `--yolo` disables all runtime hooks**! | **No OS sandbox** (`--sandbox` / `CLINE_SANDBOX=1` only redirects `CLINE_DATA_DIR` to `/tmp/cline-sandbox`) | `~/.cline/skills`, `~/.agents/skills` (project `.clinerules/skills`, `.cline/skills`, `.claude/skills`, `.agents/skills`) | Shell: none (stdin `taskId` / `sessionContext.rootSessionId` in hooks) |
| 15 | **Kilo Code** (`kilo`) | `/Library/Application Support/kilo` (macOS) / `/etc/kilo` (Linux), `~/.config/kilo/{kilo.jsonc,kilo.json,opencode.jsonc,opencode.json,config.json}`, `~/.kilocode/*`, `.kilo/*`, `.kilocode/*`, `.kilocodeignore` | OpenCode V1 `permission` schema (`permission.bash: "allow"\|"ask"\|"deny"` or `{ "<glob>": "allow"\|"ask"\|"deny" }`, last matching key wins); does **not** read `.claude` permissions | `permission: "allow"`, `permission.bash: "allow"` (**auto-written by `migrateBashPermission()`!**), `KILO_PERMISSION`, `--auto` / `--yolo` / `--dangerously-skip-permissions` | `sandbox.enabled` (`false` default; Seatbelt on macOS, `bwrap` on Linux), `sandbox.network: "allow"\|"deny"`, `experimental.sandbox` | `~/.config/kilo/skills`, `~/.kilocode/skills`, `~/.agents/skills`, `~/.claude/skills` (project `.kilocode/skills`, `.kilo/skills`, `.agents/skills`, `.claude/skills`) | Worker env: `KILO_RUN_ID`, `KILO_PROCESS_ROLE=worker` (plugin `"shell.env"` hook receives `{cwd, sessionID, callID}`) |
| 16 | **OpenClaw** (`openclaw`) | `~/.openclaw/openclaw.json`, `~/.openclaw/exec-approvals.json`, and SQLite `~/.openclaw/state/openclaw.sqlite` (`exec_approvals_config.raw_json`) | `ExecApprovalsFile`: `defaults`/`agents.<id>` `{security, ask, allowlist: [{pattern, argPattern, source}]}`; `openclaw.json`: `tools.{allow,deny,profile}`, `tools.exec.safeBins`; does **not** read `.claude` permissions | **Built-in default is `security: "full", ask: "off"`**; `tools.exec.mode: "full"` or `"auto"`, `wizard.accessMode: "full"`, `tools.elevated.enabled: true` | `tools.exec.host: "auto"` (runs on host `"gateway"` unless sandbox enabled), `agents.defaults.sandbox.mode: "off"\|"non-main"\|"all"`, `tools.fs.workspaceOnly: false` | `~/.openclaw/skills`, `~/.agents/skills` (project `<workspace>/skills`, `<workspace>/.agents/skills`; does **not** scan `.claude/skills`) | Shell: **`OPENCLAW_CLI=1`** (`OPENCLAW_SUBAGENT_EXEC=1` in subagents; no built-in session ID env var) |
| 17 | **Pi** (`pi`) | `~/.pi/agent/settings.json` (`$PI_CODING_AGENT_DIR/settings.json`), `<cwd>/.pi/settings.json`, `~/.pi/agent/trust.json` | No rule DSL (`defaultTools: ["read", "bash", "edit", "write"]` with `+name`/`-name` deltas); does **not** read `.claude` permissions | All enabled tools (`bash`, `edit`, `write`) run **unconditionally without prompts by default** unless a `tool_call` extension blocks or prompts; `defaultProjectTrust: "always"` | **No OS sandbox** | `~/.pi/agent/skills`, `~/.agents/skills` (project `<cwd>/.pi/skills` and ancestor `.agents/skills`; does **not** scan `.claude/skills`) | Shell: **`PI_SESSION_ID`**, `PI_SESSION_FILE`, `PI_PROVIDER`, `PI_MODEL` |
| 18 | **Reflection Mirror** (`mirror`) | `~/.mirror/config.json`, `~/.mirror/tool_approvals.json` | `tool_approvals.json` `entries[]`: `kind: "argv_prefix"` (`tool: "bash"`, `argv: [...]` matched via `tree_sitter_bash` on simple literal commands, `scope` per workspace) or `kind: "exact_arguments"` (`arguments_sha256`); does **not** read `.claude` permissions | `~/.mirror/config.json` `"approval_mode": "auto"`, CLI `--approval-mode auto` (persists to `config.json`), `mirror-agent serve` | Unsandboxed on host by default (`folder`/`worktree` tabs); optional Microsandbox Linux VM via `/sandbox` (`config.json` `sandbox.{image,egress,cpus,memory_mib}`) | `~/.mirror/skills`, `~/.agents/skills`, `~/.claude/skills` (project `<dir>/.agents/skills`, `<dir>/.claude/skills` from repo root to `cwd`) | Shell: sets `CI=true`, `GIT_TERMINAL_PROMPT=0`, `GH_PROMPT_DISABLED=1` (no `MIRROR_*` or session ID env var) |
| 19 | **Amp** (`amp`) | `/Library/Application Support/ampcode/managed-settings.json` (macOS) / `/etc/ampcode/managed-settings.json` (Linux), `~/.config/amp/settings.json` (`$AMP_SETTINGS_FILE`), `<workspace>/.amp/settings.json` | `"amp.permissions"` ordered array (`{tool, action: "allow"\|"ask"\|"reject"\|"delegate", matches: {cmd/command/path: <glob or /regex/ or array>}, context, to}` — first match wins!) + `"amp.guardedFiles.allowlist"`; does **not** read `.claude` permissions | `"amp.dangerouslyAllowAll": true`, `--dangerously-allow-all`, or `"amp.permissions"` starting with `{tool: "Bash"\|"*", action: "allow"}` | Local executor (`--executor local`, default) has **no OS sandbox** (remote VM isolation only via `--executor orb`) | `~/.config/amp/skills`, `~/.config/agents/skills`, `~/.agents/skills`, `~/.claude/skills` (project `.agents/skills`, `.claude/skills`; **not** `.amp/skills`) | Shell: **`AMP_CURRENT_THREAD_ID`**, **`AGENT_THREAD_ID`**, `AI_AGENT=amp`; Delegate/Orb: `AMP_THREAD_ID`, `AGENT=amp` |

---

### Group A & dual-phase JSON hook harnesses

#### 1. Crush (`@charmland/crush` `v0.98.1`)
- **Install**: `brew install charmbracelet/tap/crush` or `npm install -g @charmland/crush`
- **Config paths**: `/etc/crush/crush.json`, `~/.config/crush/crush.json`, `~/.config/crush/crushrc`, `~/.local/share/crush/crush.json`, `<project>/crush.json`, `<project>/.crush.json`, `<project>/.crush/crush.json` (all hook lists merge additively).
- **Config schema** (`internal/config/config.go:817-826` — flat array per event, not nested `{matcher, hooks}`):
  ```json
  {
    "hooks": {
      "PreToolUse": [
        {
          "name": "yolonot",
          "matcher": "bash",
          "command": "yolonot hook --harness crush",
          "timeout": 30
        }
      ]
    }
  }
  ```
- **Events & matcher**: Only `PreToolUse` is supported (`internal/hooks/hooks.go:15`). `matcher` is an unanchored Go RE2 regex tested against `toolName` (`"bash"`).
- **Stdin payload** (`internal/hooks/input.go:23-49`):
  ```json
  {
    "event": "PreToolUse",
    "session_id": "<sessionID>",
    "cwd": "/path/to/workspace",
    "tool_name": "bash",
    "tool_input": { "command": "git status", "description": "Check git status" }
  }
  ```
  Also exports `CRUSH=1`, `CRUSH_EVENT`, `CRUSH_TOOL_NAME`, `CRUSH_SESSION_ID`, `CRUSH_CWD`, `CRUSH_PROJECT_DIR`, `CRUSH_TOOL_INPUT_COMMAND`.
- **Stdout & exit codes** (`internal/hooks/runner.go:220-264`, `internal/hooks/input.go:80-211`):
  - Accepts both `{"version": 1, "decision": "allow"|"deny", "reason": "...", "updated_input": {...}}` and Claude's `{"hookSpecificOutput": {"permissionDecision": "allow"|"deny", "permissionDecisionReason": "...", "updatedInput": {...}}}`.
  - `allow` calls `permission.WithHookApproval(ctx, call.ID)` (`internal/agent/hooked_tool.go:82-84`), bypassing Crush's interactive permission prompt.
  - `deny`: exit code `2` (stderr reason), exit code `49` (blocks and halts the entire turn), or exit `0` with `decision: "deny"` / `permissionDecision: "deny"`.
  - `ask`: **not a distinct decision**. `parseDecision` (`input.go:202-211`) maps anything other than `"allow"`/`"deny"` (including `"ask"`) to `DecisionNone` (passthrough to Crush's normal permission prompt, where built-in `safeCommands` or `--yolo` auto-allow).
- **Error / timeout & caveats**: Default timeout `30s`; fail-open on timeout, crash, invalid JSON, or exit codes other than `2`/`49`. **Subagent blind spot**: `wrapToolsWithHooks` (`internal/agent/hooked_tool.go:31-34`) skips wrapping when `isSubAgent` is true, so inner tool calls inside `agent` / `agentic_fetch` subagents never trigger hooks.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: Tool-level only (`permissions.allowed_tools: ["bash", "bash:execute"]` and `options.disabled_tools: ["bash"]` in `crush.json` / `.crush.json`, or `permissions allow bash` / `permissions deny bash` in `crushrc` / `.crushrc`, `internal/shellconfig/permissions.go:23-78`).
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag `permissions.allowed_tools` containing `"bash"` or `"bash:execute"` (`internal/permission/permission.go:194-197`), `--yolo` / `-y`, and `crush run` (non-interactive auto-approve). Crush has **no OS sandbox** (`mvdan.cc/sh/v3/interp` in-process shell with AST `blockFuncs`).
  - **Skills (`InstallSkill`)**: Global `$CRUSH_SKILLS_DIR` or `~/.config/crush/skills/<name>/SKILL.md` (also scans `~/.config/agents/skills`, `~/.agents/skills`, `~/.claude/skills`; project `.agents/skills`, `.crush/skills`, `.claude/skills`, `.cursor/skills`, `internal/config/load.go:1312-1373`). Note: `internal/skills/skills.go:118-146` validates that frontmatter `name` matches `filepath.Base(skillDir)`.
  - **Env & detection**: Child `bash` tool sets `CRUSH=1`, `AGENT=crush`, `AI_AGENT=crush` (no `CRUSH_SESSION_ID` in `bash` tool, only in hooks). Detect via `crush` on `PATH` or `~/.config/crush` / `~/.local/share/crush`.

#### 2. Qwen Code (`@qwen-code/qwen-code` `v0.25.3`)
- **Install**: `npm install -g @qwen-code/qwen-code`
- **Config paths**: `~/.qwen/settings.json` (or `$QWEN_HOME/settings.json`) and trusted `<workspace>/.qwen/settings.json` (plus system `/Library/Application Support/QwenCode/settings.json` on macOS or `/etc/qwen-code/settings.json` on Linux). Uses Claude Code's nested `{matcher, hooks: [{type: "command", command, timeout}]}` schema.
- **Events & matcher**: 22 events including `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PostToolUseFailure`, `PermissionDenied`. Shell tools are `"run_shell_command"` (with exact-matcher alias target `"Bash"`, `"Shell"`, `"ShellTool"` in `hookPlanner.ts:22-29`) and `"monitor"` (background streaming shell tool). Regex matchers test only the canonical tool name, so `"matcher": "run_shell_command|monitor"` covers both.
- **Stdin payload** (`packages/core/src/hooks/types.ts:261-278, 712-717, 812-844`):
  ```json
  {
    "session_id": "<sessionId>",
    "transcript_path": "/path/to/transcript",
    "cwd": "/path/to/workspace",
    "hook_event_name": "PreToolUse",
    "timestamp": "2026-10-19T12:00:00.000Z",
    "permission_mode": "default",
    "prompt_id": "<promptId>",
    "tool_name": "run_shell_command",
    "tool_input": { "command": "git status", "is_background": false, "description": "..." },
    "tool_use_id": "toolu_...",
    "tool_call_id": "call_...",
    "agent_id": "subagent_..."
  }
  ```
- **Stdout & dual-phase `PreToolUse` + `PermissionRequest` architecture** (`packages/core/src/core/coreToolScheduler.ts:3674-4505, 5512-5630`):
  - **`PreToolUse` `allow` does NOT bypass Qwen's confirmation prompt**: Returning `permissionDecision: "allow"` on `PreToolUse` only passes the `PreToolUse` gate into `shouldConfirmExecute` (L3–L5 permission evaluation). When confirmation is required, Qwen then fires `PermissionRequest` (`coreToolScheduler.ts:4366`).
  - **Auto-approve (`allow`)**: Requires registering on `PermissionRequest` and returning `{"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}}`.
  - **Force prompt (`ask`)**: Returning `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "..."}}` on `PreToolUse` records `this.preToolUseAsks.set(callId, reason)` (`coreToolScheduler.ts:5618-5624`), forcing an interactive prompt even in `auto_edit`/`auto`/`yolo` modes and bypassing `PermissionRequest` hooks.
  - **Block (`deny`)**: Exit code `2` (stderr reason) or exit `0` with `permissionDecision: "deny"` (on `PreToolUse`) or `decision.behavior: "deny"` (on `PermissionRequest`).
- **Error / timeout & caveats**: Default timeout `60s`; fail-open on timeout/spawn error/invalid JSON (note: non-JSON plaintext on exit code `!= 0` and `!= 1` is treated as `decision: "block"` by `createPlainTextOutput` in `hookRunner.ts:1776-1789`). In non-interactive headless runs (without `--input-format stream-json`) and background subagents, `PreToolUse` `"ask"` fails closed as a denial (`coreToolScheduler.ts:5584-5593, 5696-5705`).
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules & hints (`discover.go`)**: JSONC files at `/Library/Application Support/QwenCode/settings.json` (macOS) / `/etc/qwen-code/settings.json` (Linux) / `C:\ProgramData\qwen-code\settings.json` (Windows, or `$QWEN_CODE_SYSTEM_SETTINGS_PATH`), `~/.qwen/settings.json` (`$QWEN_HOME/settings.json`), and `<project>/.qwen/settings.json`. Uses Claude-identical `permissions.{allow,ask,deny}` (`Bash(...)`, `Shell(...)`, `run_shell_command(...)`, `Read(...)`, `Edit(...)`, `Write(...)`, `WebFetch(domain:...)`, `packages/core/src/permissions/rule-parser.ts:49-564`), plus prose classifier hints in `permissions.autoMode.{environment, hints.{allow, softDeny, hardDeny, deny}}` and legacy `tools.{allowed,exclude}` / top-level `{allowedTools,excludeTools}`.
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag `tools.approvalMode: "yolo"` (or legacy `approvalMode: "yolo"`), `tools.autoAccept: true`, or blanket `Bash`/`run_shell_command` in `permissions.allow` / `tools.allowed`. Sandbox is configured via `tools.sandbox` (`false` default; `true | "docker" | "podman" | "sandbox-exec"` or `QWEN_SANDBOX`) and Linux `tools.executionSandbox` (`{backend: "auto"|"bwrap"|"landlock", filesystem: "read-only"|"workspace-write", network: "open"|"closed"}`).
  - **Skills (`InstallSkill`)**: `~/.qwen/skills/yolonot/SKILL.md` (`$QWEN_HOME/skills`; also scans `~/.agents/skills`, `<project>/.qwen/skills`, `<project>/.agents/skills`, and `skills.directories`, `skill-manager.ts:958-986`).
  - **Env & detection**: Both `run_shell_command` and hook subprocesses receive **`QWEN_CODE_SESSION_ID`**, `QWEN_CODE_CLI=1`, and `QWEN_CODE_PROJECT_DIR` (`shellContextEnv.ts:115-240`).

#### 3. Z.AI ZCode (`zcode-app-cli` `v3.15.3-37` / `zcode-runtime` `0.16.9`)
- **Install**: `npm install -g zcode-app-cli` (or build from [`zai-org/ZCode`](https://github.com/zai-org/ZCode))
- **Config paths & schema** (`vendor/cli-config.cjs:10-23`, `vendor/zcode.cjs` offset `4188509`, `4192563`):
  - Global CLI config: `~/.zcode/cli/setting.json` (or `$ZCODE_CLI_SETTINGS_FILE`; upstream unpatched CLI uses `~/.zcode/cli/config.json`).
  - **Hooks are disabled by default** (`hooks.enabled: false`) unless a plugin registers a hook or `"enabled": true` is set, and events live under `hooks.events.<EventName>`:
    ```json
    {
      "hooks": {
        "enabled": true,
        "timeoutMs": 60000,
        "events": {
          "PreToolUse": [
            {
              "matcher": "Bash",
              "hooks": [
                {
                  "type": "command",
                  "command": "yolonot hook --harness zcode",
                  "timeout": 60
                }
              ]
            }
          ]
        }
      }
    }
    ```
  - **Standalone CLI project-hook block**: Project-level `zcode.json` and `.zcode/config.json` hooks are blocked in standalone CLI mode (`config_project_hooks_pending_trust` at `zcode.cjs` offset `4201000`) because `workspaceHookAdmission` is only supplied by the Desktop host.
- **Events & tool input**: 7 events (`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PostToolUseFailure`, `Stop`). Shell tool is `"Bash"` with input `{ command, timeout, description, run_in_background, dangerouslyDisableSandbox }`.
- **Stdin payload** (`bSn` at `zcode.cjs` offset `5172863`): Emits **both** `snake_case` (`hook_event_name`, `session_id`, `tool_name`, `tool_input`, `tool_use_id`, `permission_mode`, `transcript_path`) and `camelCase` (`hookEventName`, `sessionId`, `toolName`, `toolInput`, `toolCallId`, `mode`, `transcriptPath`) alongside `cwd`.
- **Stdout & exit codes** (`t1r` at `1373857`, `nmo` at `5108267`):
  - Strict Zod schema validation (`t1r`): extra unrecognized keys fail validation and mark the hook failed (fail-open). If `hookSpecificOutput` is present, `hookEventName` is required and must match the event. Top-level `decision` only accepts `"approve" | "block"`.
  - On `PreToolUse`, `hookSpecificOutput.permissionDecision` supports `"allow"` (upgrades default `"ask"` to `"allow"`, bypassing the interactive prompt), `"ask"` (escalates `"allow"` to `"ask"`), and `"deny"`. Exit code `2` blocks with stderr.
  - Note: `PermissionRequest` hooks race concurrently against the interactive `permissionBroker` (`racePermissionResponders` at `5119475`), so returning `"allow"` on `PreToolUse` is preferred.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: JSON configs (`~/.zcode/cli/setting.json`, `~/.zcode/cli/config.json`, `<dir>/zcode.json`, `<dir>/.zcode/config.json`) hold tool-level `permission.{allowedTools, disallowedTools}` (`string[]`). Per-command rules (`{version: 1, allow/ask/deny: [{toolName: "Bash", ruleContent: "git status:*"}]}`) are stored in SQLite `~/.zcode/cli/db/db.sqlite` (`$ZCODE_SESSION_DB_PATH`), table `local_setting` (`scope='project'`, `namespace='permission'`, `key='ruleset'`, `local-settings.ts:7-25`).
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag `permission.mode` set to `"yolo"` or `"guarded"` (`service.ts:153-155`), `permission.autoApproveHighRisk: true`, or `permission.allowedTools` containing `"Bash"`. ZCode has **no OS sandbox** (removed in `node-execution-adapter-run.ts:276-279`).
  - **Skills (`InstallSkill`)**: `~/.zcode/skills/yolonot/SKILL.md` (also scans `~/.agents/skills` and project `.zcode/skills`, `.agents/skills`, `skills/roots.ts:46-118`).
  - **Env & detection**: `Bash` tool sets `ZCODE_RUNTIME_ENV` and `ZCODE_APP_CLI_VERSION` (no session ID in `Bash` tool); hook subprocesses receive `ZCODE_SESSION_ID`, `ZCODE_PROJECT_DIR`, `CLAUDE_CODE_SESSION_ID`, and `CLAUDE_SESSION_ID` (`configured-runner-input.ts:74-98` — check `ZCODE_SESSION_ID` before `CLAUDE_*`!).

#### 4. GitHub Copilot CLI (`@github/copilot` `v1.0.98`)
- **Install**: `npm install -g @github/copilot` or `brew install copilot-cli`
- **Config paths** (`cli-main.js:1124510, 1686861, 6960073`, `runtime.node` PC `25989924..25992308`):
  - System policy: `/etc/github-copilot/policy.d/*.json` (must be root-owned, non-writable by group/others, non-symlink) and `/Library/Application Support/GitHubCopilot/managed-settings.json`.
  - Global user: `~/.copilot/settings.json` (`$COPILOT_HOME/settings.json`) and `~/.copilot/hooks/*.json` (`"version": 1` required in standalone `hooks/*.json` files).
  - Repository (requires repo trust): `.github/copilot/settings.json`, `.github/copilot/settings.local.json`, and `.github/hooks/*.json` (`"version": 1`).
- **Config schema (`~/.copilot/settings.json`)**:
  ```json
  {
    "hooks": {
      "preToolUse": [
        {
          "matcher": "bash|powershell|local_shell",
          "hooks": [
            {
              "type": "command",
              "command": "yolonot hook --harness copilot",
              "timeoutSec": 60
            }
          ]
        }
      ],
      "postToolUse": [
        {
          "matcher": "bash|powershell|local_shell",
          "hooks": [
            {
              "type": "command",
              "command": "yolonot hook --harness copilot",
              "timeoutSec": 60
            }
          ]
        }
      ]
    }
  }
  ```
- **Matcher & shell tools**: Matcher is wrapped in `^(?:<matcher>)$` (`runtime.node` offset `90667016`, PC `54180508`) and matched case-sensitively against `"bash"`, `"powershell"`, `"local_shell"`. Tool input has `command`, `description`, `timeout`, `shellId`, `async`, **`requestSandboxBypass`** (`boolean`), and **`requestSandboxPermissive`** (`boolean`).
- **Stdin payload** (`command_executor.rs` at `runtime.node` PC `23949792..23955540`): Sends **both** `snake_case` (`hook_event_name: "preToolUse"`, `session_id`, `transcript_path`, `tool_name`, `tool_input`) and `camelCase` (`eventName: "preToolUse"`, `sessionId`, `transcriptPath`, `toolName`, `toolArgs`) plus `cwd` (and `agent_id`/`agentId`, `agent_type`/`agentType` in subagents).
- **Stdout & exit codes** (`command_executor.rs` PC `23969628..23986000`, `permissions/hooks.rs` PC `18536340..18541500`):
  - Accepts both top-level `{"permissionDecision": "allow"|"ask"|"deny", "permissionDecisionReason": "...", "modifiedArgs": {...}}` and Claude's `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"|"ask"|"deny", "permissionDecisionReason": "...", "updatedInput": {...}}}`.
  - `allow` on `preToolUse` (or `permissionRequest`) produces a pre-service approval (`decidedBy: "pre_tool_use_hook"`), bypassing the user prompt (unless org policy enforces `managedApprovalRequired: true`).
  - `ask` on `preToolUse` triggers an interactive user confirmation prompt in `tool_phase.rs` (fails closed as denial in headless mode).
  - `deny`: exit code `2` (stderr reason) or exit `0` with `permissionDecision: "deny"`.
- **Error vs timeout asymmetry**:
  - **Hook error (`exit != 0 && != 2` or spawn/sandbox failure)**: **Fail-closed** on `preToolUse` and policy hooks (`'Error in preToolUse hook (fail-closed)'` at `runtime.node` offset `90826486`). Note that when Copilot's session sandbox is active, hooks execute inside the session sandbox and need write access in `sandbox.userPolicy` if writing outside allowed paths.
  - **Hook timeout**: **Fail-open** (`'preToolUse hook timed out; allowing the tool call to proceed'` at offset `90826561`).
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: Managed `/Library/Application Support/GitHubCopilot/managed-settings.json` supports `permissions.{allow,ask,deny,limitTo}` with `Bash(...)`, `Shell(...)`, `PowerShell(...)`, `Read(...)`, `Edit(...)`, `Write(...)`, `Domain(...)`, `Mcp(...)`, `CustomTool(...)` (`runtime.node` `0x567afd0`). User `~/.copilot/settings.json` and repo `.github/copilot/settings(.local).json` support `allowedUrls` and `deniedUrls`; location-scoped interactive tool approvals live in `~/.copilot/config.json` under `locations.<key>.tool_approvals`. Does **not** read `.claude/settings.json` `permissions` (`claudeRepo` governance keys at `0x4f3b581` only include `hooks`, `enabledPlugins`, `disableAllHooks`, `extraKnownMarketplaces`, `companyAnnouncements`).
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag `defaultPermissionMode: "allow-all"` or `defaultMode: "autopilot"` in `settings.json`, `permissions.defaultMode: "allow-all"` in `managed-settings.json`, `COPILOT_ALLOW_ALL=true`, and `--allow-all` / `--yolo`. Sandbox (`sandbox.enabled`, default `false`) uses Microsoft Execution Containers (Seatbelt on macOS, `bwrap`+netns on Linux, ProcessContainer on Windows); also inspect `sandbox.allowBypass` (default `true`) and `sandbox.userPolicy.{filesystem,network,seatbelt}`.
  - **Skills (`InstallSkill`)**: `~/.copilot/skills/yolonot/SKILL.md` (`$COPILOT_HOME/skills`; also scans `~/.agents/skills` when `COPILOT_HOME` is unset, plus project `.github/skills`, `.agents/skills`, `.claude/skills`, `cli-main.js:174702..178956`).
  - **Env & detection**: Child shells inherit `COPILOT_CLI_BINARY_VERSION` and `COPILOT_CLI_RESOLVED_DIST_DIR`; hooks receive `COPILOT_PROJECT_DIR` and `CLAUDE_PROJECT_DIR` (session ID is in stdin JSON).

#### 9. Devin CLI / Fusion (`devin` `v3000.11.92`)
- **Install**: `brew install --cask devin-cli` or `curl -fsSL https://cli.devin.ai/install.sh | bash`
- **Config paths** (`config-importers/src/importers/hooks.rs` at `0x29cd500..0x29f3500`):
  - Native: `~/.config/devin/config.json` (`"hooks"`), `~/.config/devin/hooks.v1.json`, `~/.config/devin/hooks.json`, `.devin/hooks.v1.json`, `.devin/hooks.json`, `.devin/config(.local).json`.
  - Automatic foreign importers: `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json` (`Provider::Claude`), plus `.windsurf/hooks.json` and `~/.codeium/windsurf/hooks.json` (`Provider::Windsurf`).
- **Events & shell tool**:
  - Claude format: `PreToolUse`, `PostToolUse`, `PermissionRequest`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `PreCompact`, `PostCompact`, `SessionStart`, `SessionEnd`, `Notification`.
  - Native `hooks.v1.json`: `pre_tool`, `post_tool`, `permission_request`, `user_prompt`, `stop`, `session_start`, `session_end`, `pre_compact`, `post_compact`.
  - Shell tool name is **`"exec"`** (`ExecInput`: `command`, `workdir`, `timeout`, `shell_id`, `tty`, `run_in_background`). Even when running hooks imported from `.claude/settings.json`, `ClaudeEventInput::from(&EventInput)` (`0x102996044`) keeps `"tool_name": "exec"` verbatim.
- **Stdin payload** (`serialize_claude_input` at `0x102993d90`):
  - In Claude format (`.claude/settings*.json` or `"format": "claude"` in `hooks.v1.json`), sends `snake_case` JSON **including `cwd`**:
    ```json
    {
      "hook_event_name": "PreToolUse",
      "session_id": "<session_id>",
      "turn_id": "<turn_id>",
      "cwd": "/path/to/workspace",
      "transcript_path": "/path/to/transcript",
      "tool_name": "exec",
      "tool_input": { "command": "git status" },
      "tool_use_id": "<tool_use_id>"
    }
    ```
  - In native `HookFormatKind::Devin` (`hooks.v1.json` without `"format": "claude"`), uses `"event": "pre_tool"` and `"tool_args": { "command": "..." }`.
- **Stdout & exit codes** (`parse_claude_command_output` at `0x1029942a8..0x102994910`, `EventHandlerMut<PreTool>::handle` at `0x1007cb3b4..0x1007cb680`):
  - Supports full **`allow`**, **`ask`**, and **`deny`** on `PreToolUse`:
    - `allow`: `hookSpecificOutput.permissionDecision: "allow"` or top-level `decision: "allow"|"approve"` **auto-approves the tool call** (`chisel/approved_by` hook, priority `0`).
    - `ask`: `hookSpecificOutput.permissionDecision: "ask"` or top-level `decision: "ask"` **forces a user permission prompt** (priority `1`).
    - `deny`: exit code `2` (stderr reason), `hookSpecificOutput.permissionDecision: "deny"|"block"`, or top-level `decision: "deny"|"block"` (priority `2`).
  - Default timeout `60s`; fail-open on timeout, invalid JSON, or exit codes other than `0`/`2`.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: Managed `/Library/Application Support/Devin/system.json` (macOS) / `/etc/devin/system.json` (Linux) / `C:\ProgramData\Devin\system.json` (Windows), user `~/.config/devin/config.json` (`%APPDATA%\devin\config.json` on Windows), and project `.devin/config.json` / `.devin/config.local.json` (JSONC with `//` and `/* */` comments). Under `"permissions": { "allow": [...], "ask": [...], "deny": [...] }`, supports `Exec(<word-boundary-prefix>)`, `Read(<glob>)`, `Write(<glob>)`, `Fetch(<url|domain:...>)`, lowercase tool names (`"exec"`, `"edit"`, `"read"`, `"grep"`, `"glob"`), and `"mcp__<server>__<tool>"` (`docs/reference/permissions.mdx:187-330`). Does **not** import `permissions` from `.claude/settings.json`.
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag `DEVIN_PERMISSION_MODE` set to `"dangerous"` / `"bypass"` / `"yolo"` / `"autonomous"`, or `permissions.allow` containing `"exec"` / `"Exec(*)"` / `"Write(/**)"`. OS sandbox (Seatbelt on macOS, `bwrap`+`seccomp` on Linux) is **off by default** unless `--sandbox` or `DEVIN_SANDBOX=1` is set; **critical**: any `Exec(...)` pattern in `sandbox.excluded.allow` in `config.json` runs **outside the OS sandbox without prompting** (`docs/sandbox.mdx:76-90`).
  - **Skills (`InstallSkill`)**: `~/.config/devin/skills/yolonot/SKILL.md` (also scans `~/.config/cognition/skills`, `~/.agents/skills`, and project `.devin/skills`, `.cognition/skills`, `.agents/skills`, `.claude/skills`, `.windsurf/skills`, `.github/skills`).
  - **Env & detection**: Hooks receive `DEVIN_PROJECT_DIR` (and `session_id` on stdin); `exec` tool subprocesses do not receive a `DEVIN_SESSION_ID` env var. Detect via `devin` on `PATH` or `~/.config/devin`.

#### 10. Muse Code (`muse` `v1.4.11-R6667.1`)
- **Install**: `curl -fsSL https://dev.meta.ai/install.sh | sh`
- **Config paths** (`crates/config/src/paths.rs:412`, `crates/config/src/settings.rs:195`, live-verified):
  - Global: `~/.config/muse/settings.json` (or `$XDG_CONFIG_HOME/muse/settings.json`, with `"schema_version": 1`).
  - Project: `<workspace>/.muse/settings.json` (only loaded when the workspace is trusted in `~/.config/muse/trust.json` or `--trust-workspace`).
  - Does **not** read `~/.claude/settings.json`.
  - **Startup hook trust gate** (`crates/tui/src/startup/hook_review.rs`, `~/.config/muse/trust.json`): Any new or modified hook definition hash prompts `"<N> new or changed hooks need your trust"` at startup before execution.
- **Events & compatibility matcher**: 20 events including `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PostToolUseFailure`. Live-verified shell tool name in `PreToolUse` is lowercase `"bash"` (`tool_input: {"command": "...", "description": "...", "workdir": "..."}`), and Muse's built-in compatibility matcher alias table (`0x10d63cd10..0x10d63ce0c`) automatically matches `"Bash"` against `["Bash", "bash", "shell", "exec_command", "execute_command"]`. **Important**: Do **not** use `"matcher": "*"`, because Muse runs background reminder subagents that call internal tool `"submit_reminder_decision"`, which would otherwise trigger the shell hook on every turn. Note: exec-form `"args"` arrays (`D99`), `if` conditions (`D66`), and `once: true` (`D96`) are rejected at config validation; `"command"` must be a shell command string.
- **Stdin payload** (live-verified on `muse exec`): `snake_case` JSON with `hook_event_name`, `session_id`, `turn_id`, `transcript_path`, `cwd`, `permission_mode`, `model`, `model_provider`, `tool_name: "bash"`, `tool_input: { "command": "...", "description": "...", "workdir": "..." }`, `tool_use_id`.
- **Stdout & dual-phase `PreToolUse` + `PermissionRequest` rules** (`crates/agent-hooks` at `0x10d617900..0x10d618550`):
  - **Strict `PreToolUse` validation traps**:
    1. Top-level `"decision"` on `PreToolUse` is **rejected** with `"unsupported legacy PreToolUse output; use hookSpecificOutput.permissionDecision"` (`0x127363b8`).
    2. Returning `"permissionDecision": "allow"` on `PreToolUse` **without `updatedInput` is rejected** with `"PreToolUse permissionDecision: allow requires updatedInput; a bare allow is rejected"` (`0x1273644e`)! To allow a command without rewriting input on `PreToolUse`, the hook **must** emit `{}` or empty stdout on exit `0`.
    3. Returning `"permissionDecision": "deny"` on `PreToolUse` **requires a non-empty `permissionDecisionReason`** (`"PreToolUse permissionDecision: deny requires a non-empty permissionDecisionReason"` at `0x12736348`), or exit code `2` with stderr.
    4. Returning `"permissionDecision": "ask"` on `PreToolUse` escalates to user approval (`permission_decision = Ask` at `0x10d61809c`).
  - **Auto-approve (`allow`) via `PermissionRequest`** (`0x10d617ad0..0x10d617c80`): Registering on `PermissionRequest` and returning `{"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}}` auto-approves the command.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: Persistent approvals live in `$XDG_CONFIG_HOME/muse/approval-policy.json` (`~/.config/muse/approval-policy.json`, `ApprovalPolicyStoreFile`) under `rules[]`, where each entry has `effect: "allow" | "deny" | "prompt"`, `durability: "session" | "local_persistent"`, and `rule` tagged by `kind`: `shell_command_argv_prefix` (`argv_prefix: string[]`), `shell_command_exact_raw` (`command: string`), `tool_action` (`tool_name`), `filesystem` (`path`, `access: "read"|"write"`), `network` (`host`, `port`, `protocol`), or `unix_socket` (`path`). User permission profiles live in `~/.config/muse/settings.json` under `permissions.{default_profile, profiles}`.
  - **Audit (`host_permissions` & `host_sandbox`)**: Both approval and OS sandbox (Seatbelt on macOS, `bwrap` on Linux) are **ON by default**. Flag `permissions.default_profile == ":unrestricted"` in `~/.config/muse/settings.json` (disables both OS sandbox and approval prompts), custom profiles with `approval: "allow_all"`, `filesystem: "unrestricted"`, or `network: "enabled"`, and env vars `MUSE_PERMISSION_PROFILE_FAIL_OPEN=1` / `MUSE_DISABLE_APPROVAL_JUDGE=1`.
  - **Skills (`InstallSkill`)**: `$XDG_CONFIG_HOME/muse/skills/yolonot/SKILL.md` or `~/.config/muse/skills/yolonot/SKILL.md` (empirically verified via `muse skills list --source user --json` and `muse skills validate`; also scans project `.agents/skills` and foreign `~/.claude/skills` / `~/.codex/skills`).
  - **Env & detection**: Both workspace shell/exec tool subprocesses and hook subprocesses receive **`MUSE_SESSION_ID`** and `MUSE_THREAD_ID` (plus `MUSE_RELEASE_INFO` from the launcher). **Critical ordering note**: Muse's shell tool also sets `CLAUDE_CODE_TOOL_USE_ID`, so `ActiveHarness()` / `SessionIDFromEnv()` must check `MUSE_SESSION_ID` before `CLAUDE_*` variables!

---

### Group B: `ask` + `deny` only (`allow` does not bypass host prompt)

#### 5. Grok Build (`@xai-official/grok` `v1.0.62`)
- **Install**: `npm install -g @xai-official/grok` or `curl -fsSL https://x.ai/cli/install.sh | bash`
- **Config paths** (`bin/grok-native` embedded `10-hooks.md` at `128260078..128290000`):
  - Native: `~/.grok/config.toml` (`[[hooks.<Event>]]`), `~/.grok/hooks/*.json`, `<project>/.grok/hooks/*.json` (project hooks require folder trust via `/hooks-trust` or `--trust`).
  - Default compatibility layers: `~/.claude/settings(.local).json`, `<project>/.claude/settings(.local).json` (`[compat.claude] hooks = true`), and `~/.cursor/hooks.json`, `<project>/.cursor/hooks.json` (`[compat.cursor] hooks = true`).
- **Events & shell tool**: 15 events (`PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PermissionDenied`, `SessionStart`, `UserPromptSubmit`, `Stop`, etc.; **no `PermissionRequest` event**). Shell tool in payload is `"run_terminal_command"` (`toolInput.command`), aliased to `"Bash"` and `"Shell"` in matchers.
- **Stdin payload** (`grok-native` offset `128290400..128292500`):
  ```json
  {
    "hookEventName": "pre_tool_use",
    "hook_event_name": "PreToolUse",
    "sessionId": "abc-123",
    "cwd": "/path/to/workspace",
    "workspaceRoot": "/path/to/workspace",
    "permissionMode": "default",
    "toolName": "run_terminal_command",
    "toolInput": { "command": "npm test" },
    "toolUseId": "call_...",
    "toolInputTruncated": false,
    "timestamp": "2026-10-19T12:00:00Z"
  }
  ```
- **Stdout & exit codes** (`grok-native` offset `128292500..128308000`):
  - Accepts both top-level `{"decision": "allow"|"ask"|"deny"|"defer", "reason": "..."}` and Claude's `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"|"ask"|"deny", "permissionDecisionReason": "..."}}`.
  - **`allow` limitation**: `"allow"` means only *"not blocked"* (`grok-native` offset `128293600`); it does not bypass Grok's user confirmation prompt, and Grok has no `PermissionRequest` hook event.
  - **`ask`**: Forces the tool call to reach the interactive user prompt, overriding `auto` mode, saved `"always allow"` grants, and safe-command fast-paths (in `dontAsk` / non-interactive mode, `"ask"` becomes a denial and fires `PermissionDenied`).
  - **`deny`**: Exit code `2` (first line of stderr) or JSON `"deny"`/`"block"` on any exit code.
- **Timeout caveat**: Default `PreToolUse` timeout is **`5` seconds** (`timeout = 5` at `128270500`, fail-open on timeout/error). Always set `"timeout": 60` on Grok/Claude hook entries so LLM judge calls do not time out at 5s.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: Scans `/etc/grok/{requirements,managed_config}.toml`, `~/.grok/{requirements,managed_config,config}.toml` (`$GROK_HOME`), `<dir>/.grok/config.toml` (from repo root to `cwd`), `~/.grok/sessions/<url-encoded-root>/permission.toml`, **and directly reads Claude's `permissions.{allow,ask,deny,defaultMode}` from `~/.claude/settings(.local).json`, `<dir>/.claude/settings(.local).json`, and Claude `managed-settings.json`** (`22-permissions-and-safety.md:184-319`). Supports both compact `[permission] allow/ask/deny = ["Bash(git *)"]` and structured `[[permission.rules]]` (`{action, tool, pattern}`).
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag `[ui] permission_mode` set to `"always-approve"` or `"bypassPermissions"` (or `"auto"` / `"dontAsk"`), and `[sandbox] profile = "off"` (the default; built-in Seatbelt / Landlock+`bwrap`+seccomp profiles are `"workspace"`, `"devbox"`, `"read-only"`, `"strict"`, plus custom `~/.grok/sandbox.toml`, `18-sandbox.md:1-342`).
  - **Skills (`InstallSkill`)**: `~/.grok/skills/yolonot/SKILL.md` (`$GROK_HOME/skills`; also scans `~/.agents/skills`, `~/.claude/skills`, `~/.cursor/skills` globally and per-project, `08-skills.md:17-68`).
  - **Env & detection**: `run_terminal_command` exports `GROK_AGENT=1` (no session ID in child shells); hooks receive `GROK_SESSION_ID`, `GROK_HOOK_EVENT`, `GROK_WORKSPACE_ROOT`, and `CLAUDE_PROJECT_DIR` (`10-hooks.md:718-746`).

#### 6. DeepSeek Harness (`@deepseek-ai/dsh` `v0.2.1-rc.2`)
- **Install**: Source checkout [`deepseek-ai/deepseek-harness`](https://github.com/deepseek-ai/deepseek-harness) (`npx @deepseek-ai/dsh`)
- **Config paths**: Cordis YAML composition in `$DSH_HOME/cordis.patch.yml` (`~/.dsh/cordis.patch.yml`) mounting `@deepseek-ai/dsh-hooks-claude-code` (`packages/experimental/hooks-claude-code`) with `configPath` pointing to a `hooks.json` or `settings.json` file.
- **Events & shell tool**: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, `SubagentStart`, `SubagentStop`. Shell tool name is lowercase **`"bash"`** (`packages/shell/tool-bash/src/index.ts:369`, or `"pwsh"` on Windows) with `tool_input: { command, description, timeoutMs, workdir, run_in_background, sandbox_permissions: "use_default" | "require_escalated" }`. Because Claude-mode matchers check exact literal equality on `[A-Za-z0-9_|]+` (`packages/experimental/hook-protocol/src/matcher.ts:40-44`), the matcher must include lowercase `bash` (e.g. `"Bash|bash|pwsh"`).
- **Stdin & stdout** (`packages/experimental/hook-protocol/src/codec.ts:59-134`, `hooks-claude-code/src/index.ts:244-250`):
  - Stdin is `snake_case` Claude JSON (`session_id`, `cwd`, `hook_event_name`, `tool_name: "bash"`, `tool_input`, `tool_use_id`).
  - Stdout requires `hookSpecificOutput.hookEventName === "PreToolUse"` with `permissionDecision: "deny" | "ask" | "allow"` (or exit code `2` / top-level `decision: "block"`).
  - `"deny"` returns `{ kind: 'deny', reason }`; `"ask"` returns `{ kind: 'ask', reason }`; `"allow"` calls `next()` (passthrough without bypassing downstream gates). `updatedInput` is parsed but logged as not yet honored (`hooks-claude-code/src/index.ts:241-243`). Default timeout `600s`, fail-open.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: DeepSeek Harness has **no persistent command/file allow or deny rule lists** (`packages/interaction/user-approval/README.md:154` — only one-shot `allowed-once` grants exist).
  - **Audit (`host_permissions` & `host_sandbox`)**: Check `DSH_PERMISSION_MODE=danger-full-access` and Cordis patch files (`~/.dsh/cordis.patch.yml`, `~/.dsh/profiles/*/cordis.patch.yml`) for `id: sandbox-policy` with `config.mode: "danger-full-access"` (disables OS Seatbelt/`bwrap`/`landlock`/`windows-acl` sandbox), `id: approval` with `config.policy: "never"`, or `id: permission` with `config.defaultPreset: "danger-full-access"`. Also note `tool_input.sandbox_permissions === "danger-full-access"` on per-command escalations (`packages/shell/tool-bash/src/index.ts:68-70`).
  - **Skills (`InstallSkill`)**: `$DSH_HOME/skills/yolonot/SKILL.md` (`~/.dsh/skills/yolonot/SKILL.md`) and `~/.agents/skills/yolonot/SKILL.md` (project `.dsh/skills`, `.agents/skills`; does **not** scan `.claude/skills`, `packages/skill/skill-filesystem/src/index.ts:48-88`).
  - **Env & detection**: Injects **`DSH_SESSION_ID`**, **`DSH_SHELL=1`**, `DSH_HOME`, and `DSH_PROFILE` into every `bash` tool subprocess (`packages/shell/shell-env/src/index.ts:72-82`).

#### 7. Hermes (`NousResearch/hermes-agent` `v0.9.0` / `2026.9.24`)
- **Install**: `curl -fsSL https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.sh | bash`
- **Config path & schema** (`agent/shell_hooks.py:270-281, 364-446`): `~/.hermes/config.yaml` (or `~/.hermes/profiles/<profile>/config.yaml`):
  ```yaml
  hooks:
    pre_tool_call:
      - matcher: "terminal"
        command: "yolonot hook --harness hermes"
        timeout: 60
        fail_closed: true
    post_tool_call:
      - matcher: "terminal"
        command: "yolonot hook --harness hermes"
        timeout: 60
  ```
- **First-use hook allowlist** (`shell_hooks.py:39, 314-325, 748-775`): Hermes requires explicit opt-in for shell hooks in `~/.hermes/shell-hooks-allowlist.json` (`hermes hooks accept`, `HERMES_ACCEPT_HOOKS=1`, or `hooks_auto_accept: true` in `config.yaml`). Note: commands are spawned via `split_command_line` with `shell=False` (`shell_hooks.py:488, 506`).
- **Events, matcher & shell tool**: `pre_tool_call` and `post_tool_call` (plus 47 other lifecycle events). `matcher` is evaluated with anchored `re.compile(matcher).fullmatch(tool_name)` (`shell_hooks.py:132`). Shell tool is `"terminal"` (`tools/terminal_tool.py:1555`) with `tool_input: { command, background, timeout, workdir, pty }`.
- **Stdin & stdout** (`shell_hooks.py:87-102, 554-683`, `hermes_cli/plugins.py:1979-2099`):
  - Stdin (`snake_case`): `hook_event_name` (`"pre_tool_call"` / `"post_tool_call"`), `tool_name: "terminal"`, `tool_input: { "command": "..." }`, `session_id`, `cwd`, `profile`, `extra: { tool_call_id, task_id, turn_id }`.
  - **`deny`**: Exit code `2` (stderr reason), `{"action": "block", "message": "..."}`, or `{"decision": "block", "reason": "..."}`.
  - **`ask`**: `{"action": "approve", "message": "..."}` escalates to Hermes's human approval prompt (`approval.request_tool_approval` at `plugins.py:2069-2088`). Note: `{"decision": "approve"}` is deliberately ignored (`shell_hooks.py:643-645`).
  - **`allow` / passthrough**: Exit `0` with empty stdout or `{}` returns `None` (proceeds without bypassing Hermes's built-in `approval.detect_dangerous_command` check).
  - **Error / timeout**: Default `60s` (max `300s`); fail-open by default, **fail-closed when `fail_closed: true` is set**.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: In `~/.hermes/config.yaml` (`$HERMES_HOME/config.yaml` or `profiles/<p>/config.yaml`), top-level `command_allowlist: [...]` holds `fnmatchcase` command globs (e.g. `"podman *"`, `"git status"`, matched only on simple commands without shell metacharacters, `tools/approval_floors.py:182-205`) or dangerous-pattern keys (`"recursive delete"`, `"git_force_push"`, `"chmod_777"`), and `approvals.deny: [...]` holds hard-floor `fnmatch` deny globs evaluated even before `--yolo` (`tools/approval.py:1058-1066`).
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag `HERMES_YOLO_MODE=1`, `approvals.mode: off` (or YAML `false`, which Python parses as `False` and `normalize_approval_mode` normalizes to `"off"`, `tools/approval_context.py:269`!), and `approvals.{cron_mode,single_query_mode,unattended_mode}: approve`. For `host_sandbox`, `terminal.backend` defaults to `"local"` (**unsandboxed host execution**); when set to `"docker"`, flag `terminal.docker_mount_cwd_to_workspace: true` or host bind mounts in `terminal.docker_volumes`.
  - **Skills (`InstallSkill`)**: `$HERMES_HOME/skills/yolonot/SKILL.md` (`~/.hermes/skills/yolonot/SKILL.md`). Does **not** scan `~/.claude/skills` or `~/.agents/skills` globally unless listed in `skills.external_dirs`, and project `.hermes/skills` / `.agents/skills` are only scanned when the project path is in `skills.trusted_project_dirs` (`agent/skill_utils.py:553-574`).
  - **Env & detection**: Bridges **`HERMES_SESSION_ID`** and `HERMES_HOME` into every child shell environment (`tools/environments/local.py:276-288`).

---

### Group C: `deny` only (`ask` and `allow` defer to host)

#### 8. Kimi Code (`@moonshot-ai/kimi-code` `v2.2.0`)
- **Install**: `npm install -g @moonshot-ai/kimi-code` or `brew install kimi-code` (replaces archived Python `kimi-cli` v1.52.0)
- **Config path & schema** (`packages/agent-core-v2/src/features/externalHooks/configSection.ts:8-22`): `~/.kimi-code/config.toml` (or `$KIMI_CODE_HOME/config.toml`):
  ```toml
  [[hooks]]
  event = "PreToolUse"
  matcher = "Bash"
  command = "yolonot hook --harness kimi"
  timeout = 60
  ```
- **Events & shell tool**: 20 events, of which **only `PreToolUse`, `UserPromptSubmit`, and `Stop` are blockable** (`PostToolUse` and `PermissionRequest` are fire-and-forget observation events in `internal/types.ts:3-24`). Shell tool is `"Bash"` (`tool_input.command`; legacy Python `kimi-cli` v1.52 used `"Shell"` in `~/.kimi/config.toml`).
- **Stdin & stdout** (`matchHooks.ts:124-134`, `runHook.ts:32-41, 140-206`):
  - Stdin (`snake_case`): `hook_event_name: "PreToolUse"`, `session_id`, `cwd`, `client_type: "kimi_code_cli"`, `tool_name: "Bash"`, `tool_input: { "command": "..." }`, `tool_call_id` (note `tool_call_id` instead of `tool_use_id`).
  - **`deny`**: Exit code `2` (stderr reason) or exit `0` with `{"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": "..."}}` (top-level `decision: "block"` is not parsed by `HookJsonOutputSchema`).
  - **`allow` / `ask` / passthrough**: Exit `0` with empty stdout, `{}` or `permissionDecision: "allow"|"ask"` all return `action: 'allow'` (passthrough). Default timeout `30s`, strictly fail-open.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: In `~/.kimi-code/config.toml` (`$KIMI_CODE_HOME/config.toml`), `[permission]` supports `[[permission.rules]]` with `decision = "allow" | "ask" | "deny"`, `scope = "user" | "project"`, and `pattern = "Bash(<picomatch-glob>)"` / `"Read(<glob>)"` / `"Write(<glob>)"` / `"Edit(<glob>)"` / `"FetchURL(<glob>)"` (plus shorthand `[[permission.allow]]`, `[[permission.deny]]`, `[[permission.ask]]`, `packages/agent-core-v2/src/agent/permissionRules/configSection.ts:19-150`).
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag top-level `default_permission_mode = "auto"` (**"Never Ask" — approves all tool calls and skips `dangerous-command-ask`**, `dangerous-command-ask.ts:131`) or `"yolo"`, `[permission] dangerous_command_guard = false`, or env var `KIMI_CODE_DANGEROUS_COMMAND_GUARD=false` (and `default_yolo = true` in legacy `~/.kimi/config.toml`). Kimi Code has **no OS sandbox**.
  - **Skills (`InstallSkill`)**: `~/.kimi-code/skills/yolonot/SKILL.md` (`$KIMI_CODE_HOME/skills`; also scans `~/.agents/skills`, `<project>/.kimi-code/skills`, `<project>/.agents/skills`, `skillRoots.ts:8-39`; legacy v1 uses `~/.kimi/skills`).
  - **Env & detection**: Does not inject a session ID env var into `Bash` tool subprocesses (`session_id` is passed on hook stdin JSON). Detect via `kimi` on `PATH` or `~/.kimi-code` (`$KIMI_CODE_HOME`).

#### 11. Goose (`block/goose` `v1.55.0`)
- **Install**: `brew install block-goose-cli`
- **Config paths & schema** (`crates/goose/src/hooks/mod.rs:423-456`, `crates/goose/src/plugins/discovery.rs:48-102`):
  - Implements the Open Plugins hooks specification. Hooks live inside enabled plugin directories at `~/.agents/plugins/<plugin-name>/hooks/hooks.json` (global) or `<project>/.agents/plugins/<plugin-name>/hooks/hooks.json` (project):
    ```json
    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "shell|developer__shell",
            "hooks": [
              {
                "type": "command",
                "command": "yolonot hook --harness goose",
                "timeout": 60,
                "on_failure": "block"
              }
            ]
          }
        ]
      }
    }
    ```
- **Events & shell tool**: `PreToolUse` and `Stop` are blocking (`BeforeShellExecution` and `PostToolUse` are non-blocking observation events, `ops_toolcalling.rs:177-180, 423-430`). Note that `PreToolUse` runs *after* Goose's native `ToolApprovalOperation`. Shell tool is `"shell"` (or `"developer__shell"`, with `tool_input.command`).
- **Stdin & stdout** (`crates/goose/src/hooks/mod.rs:224-258, 897-947`):
  - Stdin: `{"event": "PreToolUse", "session_id": "...", "matcher_context": "shell", "tool_call_id": "...", "tool_name": "shell", "tool_input": {"command": "..."}, "working_dir": "/path/to/workspace"}` (note `"event"` and `"working_dir"`).
  - **`deny`**: Exit code `2` (stderr reason) or stdout JSON `{"decision": "block", "reason": "..."}`.
  - **`allow` / passthrough**: Exit code `0` with **empty stdout** or `{"decision": "allow"}`. **Critical quirk**: If a hook exits `0` with non-empty JSON that lacks `"decision": "allow"|"block"` (such as `{}` or `{"hookSpecificOutput": ...}`), Goose treats it as `HookVerdict::HookFailure` (`mod.rs:942`)!
  - **Error / timeout**: Default `30s`; fail-open by default (`"on_failure": "allow"`), **fail-closed when `"on_failure": "block"` is set**.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: `~/.config/goose/permission.yaml` (`$GOOSE_PATH_ROOT/config/permission.yaml` or `%APPDATA%\Block\goose\config\permission.yaml` on Windows) holds tool-level lists under `user.{always_allow, ask_before, never_allow}` (`crates/goose/src/config/permission.rs:13-60`; ignore the internal `smart_approve` cache section).
  - **Audit (`host_permissions` & `host_sandbox`)**: **Critical default**: `Config::get_goose_mode()` (`crates/goose/src/config/base.rs:1282`) defaults `GOOSE_MODE` to **`GooseMode::Auto`**, which approves all tool calls and **completely skips `permission.yaml` (`user.never_allow` / `user.ask_before`)** (`permission_inspector.rs:159-162`)! Flag when `GOOSE_MODE` is `"auto"` or unset in `/etc/goose/config.yaml` / `~/.config/goose/config.yaml`, or when `shell` / `developer__shell` is in `user.always_allow`. Goose has **no OS sandbox** (and escapes Flatpak via `flatpak-spawn --host`, `shell.rs:24-51`).
  - **Skills (`InstallSkill`)**: Scans `~/.agents/skills`, `~/.config/goose/skills`, `~/.claude/skills`, and `~/.config/agents/skills` globally, plus `<project>/.agents/skills`, `<project>/.goose/skills`, and `<project>/.claude/skills` (`crates/goose/src/skills/mod.rs:317-389`).
  - **Env & detection**: Sets **`AGENT_SESSION_ID=<session_id>`** on every child shell command (`shell.rs:612-630`).

#### 12. OpenHands (`openhands` `v1.16.0` / SDK `v1.21.0`)
- **Install**: `uv tool install openhands`
- **Config paths** (`openhands/sdk/hooks/config.py:219-252`): `<working_dir>/.openhands/hooks.json` or `~/.openhands/hooks.json`. **Precedence quirk**: `HookConfig.load()` stops at the first existing file (`config.py:232-240`), so if `<working_dir>/.openhands/hooks.json` exists, `~/.openhands/hooks.json` is ignored rather than merged.
- **Events & shell tool**: `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `SessionStart`, `SessionEnd`, `Stop`. `matcher` uses `re.fullmatch` when regex characters are present (`config.py:59-103`). Shell tool is `"terminal"` (`openhands/tools/terminal/definition.py:303`) with `tool_input: { command, is_input, timeout, reset }`.
- **Stdin & stdout** (`openhands/sdk/hooks/types.py:20-50`, `executor.py:234-272`):
  - Stdin: `{"event_type": "PreToolUse", "tool_name": "terminal", "tool_input": {"command": "..."}, "session_id": "...", "working_dir": "/path/to/workspace", "metadata": {}}` (also exports `OPENHANDS_PROJECT_DIR`, `OPENHANDS_SESSION_ID`, `OPENHANDS_EVENT_TYPE`, `OPENHANDS_TOOL_NAME`).
  - **`deny`**: Exit code `2` (stderr or JSON `"reason"`) or stdout JSON `{"decision": "deny", "reason": "..."}` or `{"continue": false, "reason": "..."}` (note: `"decision": "block"` is not recognized; only `"deny"`).
  - **`allow` / passthrough**: Exit `0` with empty stdout, `{}` or `{"decision": "allow"}`. `HookDecision.ASK` is commented out as `# Future` (`types.py:39`).
  - **Error / timeout**: Default `60s`; strictly **fail-open** on timeouts, exceptions, and non-zero exit codes other than `2`.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: No static command/file rule config exists in `~/.openhands/agent_settings.json` or `cli_config.json`.
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag `--always-approve` / `--yolo`, `--headless`, or per-conversation `~/.openhands/conversations/<id>/base_state.json` with `confirmation_policy.kind == "NeverConfirm"` (`state.py:121`), and `security_policy_filename` set to `""`/`null` in `~/.openhands/agent_settings.json`. OpenHands CLI uses `LocalWorkspace` (**no OS or container sandbox**).
  - **Skills (`InstallSkill`)**: `~/.agents/skills/yolonot/SKILL.md` (#1 priority) and `~/.openhands/skills/yolonot/SKILL.md` (project `<root>/.agents/skills`, `<root>/.openhands/skills`; does **not** scan `.claude/skills`, `openhands/sdk/skills/skill.py:721-910`).
  - **Env & detection**: Hook executor sets `OPENHANDS_SESSION_ID`, `OPENHANDS_PROJECT_DIR`, `OPENHANDS_EVENT_TYPE`, `OPENHANDS_TOOL_NAME` (`executor.py:160-165`), whereas interactive `terminal` tool subprocesses do not receive `OPENHANDS_SESSION_ID`.

#### 13. Kiro CLI v3 (`kiro-cli` `v2.32.0`)
- **Install**: `curl -fsSL https://cli.kiro.dev/install | bash`
- **Config paths & schema** (`autodocs/docs/features/agent-configuration.md`, `crates/agent/src/agent/agent_config/load.rs`): Per-agent JSON files at `<workspace>/.kiro/agents/<agent-name>.json` and `~/.kiro/agents/<agent-name>.json`:
  ```json
  {
    "name": "default",
    "hooks": {
      "preToolUse": [
        {
          "matcher": "shell",
          "command": "yolonot hook --harness kiro",
          "timeout_ms": 30000
        }
      ]
    }
  }
  ```
- **Events & shell tool**: `agentSpawn`, `userPromptSubmit`, `preToolUse` (`PreToolUse`), `postToolUse` (`PostToolUse`), `stop`. Shell tool is `"shell"` (aliased with `"execute_bash"` and `"execute_cmd"`) with `tool_input: { command, working_dir }`.
- **Stdin & exit-code-only stdout contract** (`autodocs/docs/features/hooks.md`, `crates/agent/src/agent/mod.rs` @ offset `89244409`):
  - Stdin: `{"hook_event_name": "preToolUse", "cwd": "/path/to/workspace", "tool_name": "shell", "tool_input": {"command": "git status", "working_dir": "/path/to/workspace"}}` (note camelCase `"preToolUse"`).
  - **`deny`**: Exit code `2` blocks the tool call (and skips sibling tool calls in the same batch), returning `stderr` to the LLM.
  - **`allow` / passthrough**: Exit code `0` **with empty stdout**. **Critical quirk**: Kiro does not parse JSON decisions from stdout; any non-empty stdout on exit `0` is injected verbatim into the LLM prompt as hook context!
  - **Error / timeout**: Default `30,000ms`; any exit code other than `0` or `2` (or timeout) shows a stderr warning and **allows** execution (fail-open).
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: Two config surfaces exist in `2.32.0`:
    1. **V3 standalone policy files** (`acp-server.js:15700-15755, 16928-16929`): Managed `/Library/Application Support/Kiro/managed-settings.json` (macOS) / `/etc/kiro/managed-settings.json` (Linux) / `C:\ProgramData\Kiro\managed-settings.json` (Windows, `deny`-only), user `~/.kiro/settings/permissions.{yaml,json}` (`allow`/`ask`/`deny`), workspace `~/.kiro/workspace-roots/<sha256_prefix_16>/permissions.{yaml,json}` (`ask`/`deny`), and `<workspace>/.kiroignore`. Uses `policies: ["read-only-shell", ...]` and `rules: [{capability: "shell"|"fs_read"|"fs_write"|"filesystem"|"mcp"|"all", match: [...], exclude: [...], effect: "allow"|"ask"|"deny"}]`.
    2. **Custom agent configs** (`~/.kiro/agents/*.json`, `<workspace>/.kiro/agents/*.json`, `$KIRO_AGENT_CONFIG_DIR/*.json`): Supports both V3 `permissions.{rules,policies}` and V2 `allowedTools` + `toolsSettings.{shell|execute_bash}.{allowedCommands,deniedCommands}` (regexes) and `toolsSettings.{read|fs_read, write|fs_write}.{allowedPaths,deniedPaths}`.
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag `-a` / `--trust-all-tools`, `~/.kiro/settings/cli.json` (or `.kiro/settings/cli.json`) with `"chat.disableTrustAllConfirmation": true` or `"policyPreset": ["allow-all"]`, V3 `policies` containing `"allow-all"`, or blanket `shell`/`all` `allow` rules. Sandbox config lives in `~/.kiro/settings/sandbox.json` and `<workspace>/.kiro/settings/sandbox.json`, but interactive `kiro-cli chat` runs unsandboxed in `2.32.0`.
  - **Skills (`InstallSkill`)**: `~/.kiro/skills/yolonot/SKILL.md` and `<workspace>/.kiro/skills/yolonot/SKILL.md` (does **not** scan `~/.claude/skills` or `~/.agents/skills`, `acp-server.js:17156`).
  - **Env & detection**: V3 sets **`KIRO_SESSION_ID`** and `AWS_SDK_UA_APP_ID=kiro-agent` in every child shell and hook (`acp-server.js:1656, 5004, 11035`); V2 sets `KIRO_CHAT_SHELL=1` and `AMAZON_Q_CHAT_SHELL=1`.

#### 14. Cline (`cline` `v3.0.73` / `@cline/core` `v0.0.29`)
- **Install**: `npm install -g cline`
- **Config paths** (`sdk/packages/core/src/hooks/hook-file-config.ts:154-201`): Directory-based executable scripts named `PreToolUse` / `PostToolUse` (with optional `.sh`, `.js`, `.ts`, `.py`, `.ps1` extension) in `~/Documents/Cline/Hooks`, `~/.cline/hooks` (`$CLINE_DIR/hooks`), `<workspace>/.clinerules/hooks`, `<workspace>/.cline/hooks`, or `--hooks-dir <dir>`.
- **Shell tool & multi-command array** (`sdk/packages/core/src/extensions/tools/schemas.ts:127-172`):
  - In Cline CLI (`@cline/core`), the shell tool is **`"run_commands"`** and its canonical input is an **array of command strings** `{"commands": ["git status", "npm test"]}` (legacy VS Code extension uses `"execute_command"` with `{"command": "..."}`).
- **Stdin & stdout** (`sdk/packages/core/src/hooks/hook-file-hooks.ts:191-223, 577-662`, `subprocess-runner.ts:243-258`):
  - Stdin includes both `tool_call: { id, name: "run_commands", input: { commands: [...] } }` and legacy `preToolUse: { toolName: "run_commands", parameters: { commands: "[...]" } }`, plus `workspaceRoots: ["/path/to/workspace"]` and `taskId`.
  - **Exit code is ignored** by `runSubprocessEvent` (`subprocess-runner.ts:243-258`); only stdout JSON (or `HOOK_CONTROL\t{...}`) is inspected.
  - **`deny`**: `{"cancel": true, "errorMessage": "..."}`. Note: in `@cline/core` `0.0.29`, `beforeToolResultFromControl` (`hook-file-hooks.ts:591-595`) maps `cancel: true` to `{ stop: true }`, which throws `ControlledStopError` and aborts the current agent turn.
  - **`ask` (`review`) bug in `@cline/core` `0.0.29`**: Although `parseHookControl` (`hook-file-hooks.ts:210`) parses `"review": true`, `beforeToolResultFromControl` (`lines 577-606`) never forwards `control.review` to the policy engine, making `"review": true` a no-op.
  - **`allow` / passthrough**: Empty stdout or `{"cancel": false}`. Default timeout `120s`, fail-open on error/timeout/invalid JSON.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: No command glob allow/deny rules exist in `~/.cline/data/settings/global-settings.json` (`$CLINE_GLOBAL_SETTINGS_PATH`, only tool enablement `tools.use_Bash.enabled` / `disabledTools`); `<workspace>/.clineignore` defines gitignore-style path blocks (`ClineIgnoreController.ts:73-120`).
  - **Audit (`host_permissions` & `host_sandbox`)**: **Critical CLI default**: In Cline CLI v3, `--auto-approve` defaults to `"true"` and `resolveStartupToolAutoApprove` (`apps/cli/src/utils/startup-settings.ts:21-31`) defaults `toolAutoApprove` to **`true`** when unset in `~/.cline/data/settings/global-settings.json`! Even worse, passing **`-y` / `--yolo` completely disables all runtime hooks** (`createRuntimeHooks` in `apps/cli/src/utils/hooks.ts:176-181`: `if (options.yolo === true) return { hooks: undefined }`). Also flag `CLINE_TOOL_APPROVAL_MODE=auto|allow`. Cline has **no OS sandbox** (`--sandbox` / `CLINE_SANDBOX=1` only redirects `CLINE_DATA_DIR` to `/tmp/cline-sandbox`).
  - **Skills (`InstallSkill`)**: Global `~/.cline/skills/yolonot/SKILL.md` and `~/.agents/skills/yolonot/SKILL.md` (project `.clinerules/skills`, `.cline/skills`, `.claude/skills`, `.agents/skills`; note `~/.claude/skills` is not scanned globally, `sdk/packages/shared/src/storage/paths.ts:468-523`).
  - **Env & detection**: Does not inject `CLINE_SESSION_ID` into child shells (`taskId` and `sessionContext.rootSessionId` are passed on hook stdin JSON).

---

### Group D: In-process plugin / shim harnesses (OpenCode model)

#### 15. Kilo Code (`@kilocode/cli` `v7.8.12`)
- **Install**: `npm install -g @kilocode/cli`
- **Plugin discovery** (`packages/opencode/src/config/paths.ts:23-41`, `plugin.ts:18-30`): Auto-loads `{plugin,plugins}/*.{ts,js}` from `~/.config/kilo` (`$KILO_CONFIG_DIR`), `~/.kilocode`, `~/.kilo`, and project `.kilocode`/`.kilo`.
- **V1 vs V2 architecture in `7.8.12`**: Unlike upstream OpenCode `2.0.28`, Kilo Code `7.8.12` has **not** implemented V2 `ctx.tool.transform` or `ctx.permission.hook("evaluate")` yet (`packages/plugin/src/v2/effect/PLAN.md:5, 37-42`). All tool calls run through the V1 `packages/opencode` pipeline (`SessionTools.resolve` in `packages/opencode/src/session/tools.ts:186-225`) with tool name `"bash"` and args `{ command, timeout, workdir, description }`.
- **Full `allow` / `ask` / `deny` contract**:
  - Export `export const YolonotPlugin = async (ctx) => ({ "tool.execute.before": ..., "tool.execute.after": ..., event: ... })` (or default `{ id: "yolonot", server: async (ctx) => ({ ... }) }`).
  - `deny`: throw `new Error("yolonot: ...")` in `"tool.execute.before"`.
  - `allow`: record approved `callID` in `"tool.execute.before"`, then on `event` (`permission.asked` with `event.properties.tool?.callID === callID`), auto-reply via `ctx.client.postSessionIdPermissionsPermissionId({ path: { id: sessionID, permissionID: event.properties.id }, body: { response: "once" } })` (note: `Permission.reply` at `permission/index.ts:295-304` requires interactive confirmation when `metadata.sandboxEscalation === true` or `metadata.skillShell === true`).
  - `ask` & human resolution: do not auto-reply to `permission.asked` so Kilo's TUI prompts the user, and capture the user's choice (`"once" | "always" | "reject"`) on `permission.replied`.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: Identical schema to OpenCode (`permission` in JSONC, where last matching wildcard key wins, plus legacy `.kilocodeignore`), loaded from:
    - Managed: `/Library/Application Support/kilo` (macOS), `/etc/kilo` (Linux), `C:\ProgramData\kilo` (Windows) reading `{kilo,opencode}.{jsonc,json}` (`packages/opencode/src/config/managed.ts:8-63`).
    - User: `$KILO_CONFIG_DIR` or `~/.config/kilo/{config.json,kilo.json,kilo.jsonc,opencode.json,opencode.jsonc}`, `~/.kilocode/{kilo,opencode}.{jsonc,json}`, `~/.kilo/{kilo,opencode}.{jsonc,json}`, `$KILO_CONFIG`, and `~/.kilocode/.kilocodeignore`.
    - Project: `<dir>/{kilo,opencode}.{jsonc,json}`, `<dir>/.kilo/{kilo,opencode}.{jsonc,json}`, `<dir>/.kilocode/{kilo,opencode}.{jsonc,json}`, and `<dir>/.kilocodeignore` (note: Kilo ignores `.opencode/`).
  - **Audit (`host_permissions` & `host_sandbox`)**: **Critical quirk**: `KilocodeConfig.migrateBashPermission()` (`kilocode/config/config.ts:473-558`) automatically writes `"permission": { "bash": "allow" }` into the user's global config once and creates `~/.config/kilo/.bash-permission-migrated`! Also flag `permission: "allow"`, `KILO_PERMISSION`, and `--auto` / `--yolo` / `--dangerously-skip-permissions`. For `host_sandbox`, `sandbox.enabled` defaults to `false` (`@kilocode/sandbox` uses Seatbelt on macOS and `bwrap` on Linux when enabled, with `sandbox.network: "allow"|"deny"`).
  - **Skills (`InstallSkill`)**: `~/.config/kilo/skills/yolonot/SKILL.md` (`$KILO_CONFIG_DIR/skills`; also scans `~/.kilocode/skills`, `~/.kilo/skills`, `~/.agents/skills`, `~/.claude/skills` globally and `.kilocode/skills`, `.kilo/skills`, `.agents/skills`, `.claude/skills` per-project, `skill/index.ts:202-306`).
  - **Env & detection**: TUI worker sets `KILO_RUN_ID` and `KILO_PROCESS_ROLE=worker`, and the plugin `"shell.env"` hook receives `{ cwd, sessionID, callID }` (`tool/shell.ts:537-544`), allowing the plugin to inject `KILO_SESSION_ID` into every child shell.

#### 16. OpenClaw (`openclaw` `v2026.10.5`)
- **Install**: `npm install -g openclaw@latest`
- **Plugin discovery** (`src/plugins/roots.ts:20-30`, `src/plugins/manifest.ts:36, 154-205`): Global plugins in `~/.openclaw/extensions/<id>/` with `openclaw.plugin.json` (`{"id": "yolonot", "configSchema": {"type": "object", "additionalProperties": false}, "activation": {"onStartup": true, "onCapabilities": ["hook"]}}`) and `index.js` are enabled by default without editing `~/.openclaw/openclaw.json`.
- **Hook API & shell tool** (`src/plugins/hook-types.ts:545-600`, `src/agents/bash-tools.exec-run.ts:191`):
  - Register `api.on("before_tool_call", handler, { priority: 100 })` and `api.on("after_tool_call", afterHandler)`. Default `before_tool_call` timeout is `15s` and **fails closed** on timeout/exception (`src/plugins/hook-types.ts:141`).
  - Shell tool is `"exec"` with `event.params`: `{ command, workdir, env, timeoutSeconds, background, pty, elevated: boolean, host: "auto"|"sandbox"|"gateway"|"node" }`. (`cwd` is `event.params.workdir || process.cwd()`; sandbox bypass is `event.params.elevated === true` or `event.params.host === "gateway"|"node"`).
- **Full `allow` / `ask` / `deny` contract** (`src/agents/agent-tools.before-tool-call.policy.ts:300-393`, `approval.ts:210-560`):
  - `deny`: return `{ block: true, blockReason: "yolonot: ..." }`.
  - `ask`: return `{ requireApproval: { title: "Allow command?", description: command, severity: "warning", allowedDecisions: ["allow-once", "allow-always", "deny"], onResolution: (decision) => { ... } } }` (routes through OpenClaw's native embedded TUI or gateway approval broker and reports `"allow-once" | "allow-always" | "deny" | "timeout" | "cancelled"` to `onResolution`).
  - `allow` / `passthrough`: return `undefined` (or `{}`).
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: State dir is `$OPENCLAW_STATE_DIR` or `~/.openclaw`. Rules live in:
    1. `~/.openclaw/state/openclaw.sqlite` (table `exec_approvals_config`, `config_key = 'current'`, column `raw_json`) and legacy fallback `~/.openclaw/exec-approvals.json` (`src/infra/exec-approvals-config.ts:22-134`): `defaults` and `agents.<id>` with `allowlist: [{pattern, argPattern, source}]` and `mcpTools: [{server, tool, action}]`.
    2. `~/.openclaw/openclaw.json` (`$OPENCLAW_CONFIG_PATH`, JSON5): `tools.{allow,alsoAllow,deny,profile}`, `tools.exec.{safeBins,safeBinTrustedDirs}`, and `tools.fs.workspaceOnly`.
  - **Audit (`host_permissions` & `host_sandbox`)**: **Built-in default is `DEFAULT_SECURITY = "full"`, `DEFAULT_ASK = "off"`** (`exec-approvals-config.ts:95-96`)! Flag `tools.exec.mode: "full"` (or `"auto"`), `security: "full"` with `ask: "off"`, `wizard.accessMode: "full"`, `tools.elevated.enabled: true` (default `true`), `agents.defaults.sandbox.mode: "off" | "non-main"`, and `tools.fs.workspaceOnly: false` (default).
  - **Skills (`InstallSkill`)**: `~/.openclaw/skills/yolonot/SKILL.md` (`$OPENCLAW_STATE_DIR/skills`) and `~/.agents/skills/yolonot/SKILL.md` (workspace `<workspace>/skills` and `<workspace>/.agents/skills`; does **not** scan `.claude/skills`, `workspace-skill-sources.ts:94-181`).
  - **Env & detection**: Sets **`OPENCLAW_CLI="1"`** (and `OPENCLAW_SUBAGENT_EXEC="1"` in subagents) on all spawned child processes (`src/infra/openclaw-exec-env.ts:1-43`).

#### 17. Pi (`@earendil-works/pi-coding-agent` `v1.3.0`)
- **Install**: `npm install -g --ignore-scripts @earendil-works/pi-coding-agent`
- **Extension discovery** (`packages/coding-agent/src/core/extensions/loader.ts:781-876`): Auto-loads `~/.pi/agent/extensions/*.{ts,js}` (`$PI_CODING_AGENT_DIR/extensions`) and `<cwd>/.pi/extensions/*.{ts,js}` via `jiti`.
- **Hook API & shell tool** (`src/core/extensions/types.ts:1193-1365`, `src/core/tools/bash.ts:40-43, 418`):
  - Shell tool is `"bash"` (`"powershell"` on Windows) with `event.input: { command: string, timeout?: number }` and `ctx.cwd: string`.
  - Register `pi.on("tool_call", async (event, ctx) => ...)` and `pi.on("tool_result", async (event, ctx) => ...)`.
  - `deny`: return `{ block: true, reason: "yolonot: ..." }` (throwing an error also blocks fail-closed).
  - `ask`: Pi has no built-in permission prompt; the extension checks `if (!ctx.hasUI) return { block: true, reason: "..." }` and calls `await ctx.ui.confirm(title, message)` (or `await ctx.ui.select(title, ["Allow once", "Allow session", "Deny"])`).
  - `allow` / `passthrough`: return `undefined`.
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: `~/.pi/agent/settings.json` (`$PI_CODING_AGENT_DIR/settings.json`) and trusted `<cwd>/.pi/settings.json` have no command/file rule DSL (only `defaultTools: ["read", "bash", "edit", "write"]` with `+name`/`-name` delta modifiers, `settings-manager.ts:84-147`).
  - **Audit (`host_permissions` & `host_sandbox`)**: By design, Pi runs all enabled built-in tools (`bash`, `edit`, `write`, `read`) **without confirmation prompts and without an OS sandbox** unless an extension intercepts `"tool_call"`. Also check `defaultProjectTrust: "always"` in `~/.pi/agent/settings.json`.
  - **Skills (`InstallSkill`)**: `~/.pi/agent/skills/yolonot/SKILL.md` (`$PI_CODING_AGENT_DIR/skills`) and `~/.agents/skills/yolonot/SKILL.md` (project `<cwd>/.pi/skills` and ancestor `.agents/skills`; does **not** scan `.claude/skills`, `package-manager.ts:2452-2568`).
  - **Env & detection**: Sets **`PI_SESSION_ID`**, `PI_SESSION_FILE`, `PI_PROVIDER`, `PI_MODEL`, and `PI_REASONING_LEVEL` on every `bash` tool execution (`packages/coding-agent/src/core/tools/bash.ts:186-212`).

#### 18. Reflection Mirror (`reflection-mirror` `v0.1.33`)
- **Install**: `uv tool install reflection-mirror`
- **Extension discovery** (`mirror-cli/src/mirror/cli/user_extensions.py:72-95`, `extension.py:165-376`): Loads `~/.mirror/extensions/<name>/extension.py` and `<project>/.mirror/extensions/<name>/extension.py` subclassing `mirror.cli.extension.Extension` (requires `"extensions": {"yolonot": {"enabled": true}}` and the resolved path in `"consented_extensions"` in `~/.mirror/config.json`).
- **Interception contract** (`mirror-agent/src/react_agent_service.rs:1297-1349`, `mirror-cli/src/mirror/cli/cli.py:2274, 2326-2383`, `reducer.py:872-916`):
  - Shell tool is `"bash"` with `{"command": "..."}` and workspace `cwd` in `context.workspace.cwd` / `global_state.workspace`.
  - In `APPROVAL_MODE_HITL` (`'approve'`, default), `mirror-agent` pauses before running `bash` and emits `SessionMessage(hitl_request=HITLRequest(call=...))` followed by `actions.ApprovalRequested`.
  - `allow`: emit `effects.SendApprovalDecision(call_id=call_id, approved=True, source=agent_pb2.APPROVAL_SOURCE_AUTOMATIC)` (or dispatch `actions.DecideApproval(approved=True, remember=False, call_id=call_id)`).
  - `deny`: emit `effects.SendApprovalDecision(call_id=call_id, approved=False, source=agent_pb2.APPROVAL_SOURCE_AUTOMATIC)` during `handle_message` (pre-empting `~/.mirror/tool_approvals.json`).
  - `ask` / `passthrough`: return `(ext_state, ())` on `ApprovalRequested` so Mirror's TUI approval modal prompts the user, and observe the resolution on `agent_message.tool_approval` (`outcome` + `source`).
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: `~/.mirror/tool_approvals.json` (`tool_approvals.py:13-181`, `bash_approvals.py:14-94`) stores workspace-scoped (`scope: "[\"local-v1\", \"/abs/workspace\", null]"`) entries with `kind: "argv_prefix"` (`tool: "bash"`, `argv: ["git", "status"]` matched via `tree_sitter_bash` on simple literal commands without pipes/redirects/expansions) or `kind: "exact_arguments"` (`arguments_sha256`).
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag `"approval_mode": "auto"` in `~/.mirror/config.json` (note: running `mirror --approval-mode auto` persists `"approval_mode": "auto"` into `~/.mirror/config.json`, `main.py:384-388`!). By default, Mirror workspaces run **unsandboxed on the host** (Microsandbox Linux VM isolation is opt-in via `/sandbox`).
  - **Skills (`InstallSkill`)**: Scans `~/.mirror/skills`, `~/.agents/skills`, and `~/.claude/skills` globally (and `<dir>/.agents/skills`, `<dir>/.claude/skills` from repo root to `cwd`, `mirror-agent/src/system_prompt/skill.rs:49-152`).
  - **Env & detection**: `bash` tool sets `CI=true`, `GIT_TERMINAL_PROMPT=0`, `GH_PROMPT_DISABLED=1` and strips `GIT_DIR`/`GIT_WORK_TREE` (`bash_tool.rs:64-83`), without setting a `MIRROR_*` or session ID env var.

#### 19. Amp (`@sourcegraph/amp` / `@ampcode/cli` `v0.0.1792411243-gb8cffc`)
- **Install**: `npm install -g @sourcegraph/amp` or `curl -fsSL https://ampcode.com/install.sh | bash`
- **Plugin discovery** (`amp plugins show-docs` lines 133–155, `bin/amp` offset `88500850`): Auto-loads `~/.config/amp/plugins/*.ts` (or `.js`) and `<workspace>/.amp/plugins/*.ts` inside a `bun` plugin runtime subprocess (requires header comment `// @i-know-the-amp-plugin-api-is-wip-and-very-experimental-right-now`). Also supports native `amp.permissions` `{ "tool": "Bash", "action": "delegate", "to": "<program>" }` in `~/.config/amp/settings.json`.
- **Hook API & shell tools** (`amp plugins show-docs` lines 1868–1932, 2208–2250; `bin/amp` offset `88455950, 88458200`):
  - Shell tools are `"Bash"` (`event.input.cmd`, `event.input.cwd`), `"shell_command"` (`event.input.command`, `event.input.workdir`), and `"async_shell_command"` (`event.input.command`, `event.input.workdir`). Built-in helper `amp.helpers.shellCommandFromToolCall(event)` normalizes `{ command, dir }`, and workspace root is `amp.helpers.filePathFromURI(ctx.system.workspaceRoot)`.
  - Register `amp.on('tool.call', async (event, ctx) => ...)` and `amp.on('tool.result', async (event, ctx) => ...)`:
    - `allow` / `passthrough`: return `{ action: 'allow' }`.
    - `deny`: return `{ action: 'reject-and-continue', message: 'yolonot: ...' }`.
    - `ask`: call `await ctx.ui.confirm({ title: 'Allow command?', message: '...', requireHuman: true })` (catching `amp.helpers.isPluginUINotAvailableError(err)` in headless `-x` mode to fail closed as `reject-and-continue`).
- **Rule discovery, audit, skills & env (`discover.go` / `audit` / `InstallSkill` / `SessionIDFromEnv`)**:
  - **Rules (`discover.go`)**: Managed `/Library/Application Support/ampcode/managed-settings.json` (macOS) / `/etc/ampcode/managed-settings.json` (Linux) / `C:\ProgramData\ampcode\managed-settings.json` (Windows), user `~/.config/amp/settings.json` (`$AMP_SETTINGS_FILE`), and workspace `<workspace>/.amp/settings.json`. Under `"amp.permissions"` (evaluated **in order, first matching rule wins**), each rule has `tool` (`"Bash"`, `"shell_command"`, `"async_shell_command"`, `"Read"`, `"edit_file"`, `"create_file"`, `"delete_file"`, `"*"`), `action: "allow" | "ask" | "reject" | "delegate"` (note `"reject"`, not `"deny"`!), `matches: { cmd/command/path: "<glob>" | "/<regex>/" | [...] }`, optional `context: "thread" | "subagent"`, and `to` (for `delegate`). Also inspect `"amp.guardedFiles.allowlist"` (`string[]` of globs overriding Amp's guarded files denylist).
  - **Audit (`host_permissions` & `host_sandbox`)**: Flag `"amp.dangerouslyAllowAll": true` (`--dangerously-allow-all`), `"amp.permissions"` starting with `{ "tool": "Bash" | "*", "action": "allow" }`, or broad `"amp.guardedFiles.allowlist"` globs (`"**"`, `"/**"`). Local execution (`--executor local`, default) has **no OS sandbox** (remote VM isolation is only used with `--executor orb`).
  - **Skills (`InstallSkill`)**: `~/.config/amp/skills/yolonot/SKILL.md` (also scans `~/.config/agents/skills`, `~/.agents/skills`, `~/.claude/skills` globally and `<workspace>/.agents/skills`, `<workspace>/.claude/skills` per-workspace; note `<workspace>/.amp/skills` is **not** scanned).
  - **Env & detection**: Shell tool subprocesses receive **`AMP_CURRENT_THREAD_ID`**, **`AGENT_THREAD_ID`**, and **`AI_AGENT=amp`** (`bin/amp` `@ 0x551f698`); `delegate` permission helpers receive `AMP_THREAD_ID`, `AGENT=amp`, `AGENT_TOOL_NAME`, and `AGENT_TOOL_USE_ID`.

