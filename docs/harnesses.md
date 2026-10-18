# Harness compatibility

yolonot shares a shell-command policy across five supported adapters. Native prompts,
hook trust and sandbox enforcement remain host-specific. Versions below were
checked on **14 October 2026**; installed and upstream versions are separate.

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

## Other harness candidates

These are researched candidates, not installed yolonot adapters:

| Candidate | Enforcement surface | Suggested priority |
|---|---|---|
| [GitHub Copilot CLI](https://docs.github.com/en/copilot/reference/hooks-reference) | preToolUse permission decisions | Next: fits the approval model |
| [Kiro](https://kiro.dev/docs/hooks/actions/) | PreToolUse shell hooks can block | After Copilot; verify V3 configuration |
| [Cline](https://github.com/cline/cline/blob/main/.clinerules/hooks/README.md) | PreToolUse cancellation | Useful for VS Code users |
| [Windsurf / Devin Desktop](https://docs.devin.ai/desktop/cascade/hooks) | pre_run_command blocking | Track current product/schema first |

An adapter needs an enforceable pre-execution contract, a supported install
path and reproducible lifecycle tests. A generic MCP connection alone does
not intercept arbitrary shell commands.
