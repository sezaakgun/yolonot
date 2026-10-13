# AI harnesses

yolonot was built for Claude Code but also ships adapters for other bash-capable AI coding tools. Pick one explicitly with `--harness` (or `YOLONOT_HARNESS=<name>`); otherwise yolonot auto-detects.

| Harness | `ask` prompt support | Notes |
|---------|----------------------|-------|
| **Claude Code** (default) | full 3-state (allow/ask/deny) | Native hook protocol. |
| **Cursor** | deny only | Schema accepts `ask` but Cursor does not enforce it — no TUI prompt, and asked-not-approved pins the command as session_deny. Moderate-risk commands fall through to Cursor's own permission UI; high/critical still hard-deny. Same hooks.json covers the `cursor-agent` CLI. |
| **Codex CLI** | deny only | Upstream hook API has no user-prompt primitive. Moderate-risk commands fall through to Codex's own permission engine (yolonot goes transparent); high/critical still hard-deny. |
| **OpenCode** | deny only | Plugin hook `tool.execute.before` is throw-to-block or return-to-allow. yolonot maps moderate-risk to allow since empty stdout is treated as allow; high/critical still hard-deny. |
| **Gemini CLI** | full 3-state — **with caveat** (see below) | Needs `--yolo` for `allow` to take effect. |

## Install

```bash
yolonot install --harness claude      # Claude Code only
yolonot install --harness codex       # Codex CLI only
yolonot install --harness opencode    # OpenCode only
yolonot install --harness gemini      # Gemini CLI only
yolonot install --harness cursor      # Cursor only
yolonot install --all                 # every registered adapter
```

When neither flag is passed, `yolonot install` targets every **detected** harness (i.e. whichever CLIs you have installed). `yolonot setup` runs install + rules + model pick in one go and accepts the same flags.

Uninstall mirrors this: `yolonot uninstall --harness <name>` or `--all`. Without a flag, `uninstall` defaults to every *currently installed* adapter.

Restart the host CLI after install so it re-reads hooks.

## Claude Code mod

Claude Code 2.1.296+ loads plugin *function hooks* (mods): a TypeScript module that can gate tool calls, draw in the transcript and above the prompt. `yolonot install --mod` writes one to `~/.yolonot/mod/` and names it in `~/.claude/settings.json` under `env.CLAUDE_CODE_PLUGIN_DIRS`. Restart Claude Code to load it; `yolonot uninstall` (or `yolonot mod uninstall`) removes it. Older builds ignore the module and keep the classic hook.

With the mod loaded:

- **Verdict line.** Under every shell command the transcript folds ("Ran 1 shell command") a dim line shows the deciding layer, the time, and the command: `● yolonot fast_allow · 21 ms · echo hi`. Asks and denies carry the reason. The allow banner is not printed twice.
- **Four-way ask.** Instead of Claude's yes/no prompt, a yolonot dialog offers *Allow once*, *Allow this session*, *Explain* and *Deny*. Explain asks the chat model for a three-line note (`yolonot explain`) and re-asks. Allow once runs the command without remembering it; Allow this session is the usual session approval; Deny records a session rejection.
- **No wrapped retries.** A command the user denied is refused again when the model retries it through `bash -c`, `sh -c` or a heredoc, with a note telling the model to ask you instead of rewording the call.
- **Nothing else.** No status row, no buttons: `yolonot pause` / `resume` and rule suggestions (`yolonot suggest`) stay on the command line; the mod never proposes a rule.

How it works: the mod runs `yolonot hook` itself for every Bash call (before Claude's permission path) and records the verdict per `tool_use_id` in `~/.yolonot/sessions/<session>.mod`; the classic PreToolUse hook then replays that record instead of judging twice. Headless (`claude -p`) sessions load the mod but have no dialog: an ask there is refused. Once installed, every later `yolonot install` refreshes the mod too.

Two differences from the classic hook alone:

- The mod does not see Claude's permission mode, so it judges under `--dangerously-skip-permissions` as well, where the classic hook stays silent. Pause yolonot for the session if that is not what you want.
- On a machine with managed settings, Claude's `sec-default` module skips user-tier `classic.*` hooks and `prompt.context`; the mod uses neither, which is why it runs the hook itself. The mod was developed and tested on such a machine, Claude Code 2.1.296; unmanaged machines should behave the same but were not tested.

## Runtime pinning

The hook binary is installed with `--harness <name>` baked into the host's hook command, so it routes to the right adapter automatically. To force-pin from your shell (e.g. for `yolonot check` against a specific harness):

```bash
YOLONOT_HARNESS=claude claude
YOLONOT_HARNESS=codex codex
YOLONOT_HARNESS=opencode opencode
YOLONOT_HARNESS=gemini gemini --yolo
YOLONOT_HARNESS=cursor cursor-agent
```

Resolution order:

1. `YOLONOT_HARNESS` env var (explicit override).
2. `--harness` flag on the CLI invocation.
3. Auto-detect based on which host is calling the hook.

## Codex CLI

Codex's hook API has no `ask` primitive — only `deny` is supported; `allow`/`ask` fail open. `CodexHarness` translates `ask → deny` on purpose. Tune the tradeoff with the [risk map](risk-tiers.md):

```bash
yolonot risk codex                    # show current map
yolonot risk codex moderate deny      # turn moderate into hard deny
yolonot risk codex moderate passthrough   # let Codex's own permission engine decide
```

## OpenCode

Plugin API has no `ask` primitive either. `tool.execute.before` is throw-to-block or return-to-allow. The plugin shim throws on `ask` (same pattern as Codex). Upstream blocker.

The OpenCode adapter also installs a small TypeScript shim (`harness_opencode_plugin.ts`) into your OpenCode plugins directory. `yolonot install --harness opencode` handles this automatically.

## Gemini CLI — run with `--yolo`

Gemini's hook protocol has a genuine `ask` primitive (it fires the native TUI confirmation prompt with yolonot's reason), but its scheduler **silently ignores hook `allow` decisions unless YOLO mode is on**. The policy engine runs unconditionally, so without YOLO you'll still see Gemini's own "Allow once / Allow for this session / No" prompts even after yolonot has allowed a command.

```bash
# recommended: yolonot is the sole approval gate
gemini --yolo
```

Or persist it in `~/.gemini/settings.json`:

```json
{ "general": { "defaultApprovalMode": "yolo" } }
```

**Without `--yolo`, yolonot still runs as an extra security layer** — `ask` and `deny` decisions are fully honored, so yolonot can force prompts and hard-block dangerous commands that Gemini would otherwise run without asking. It just can't suppress Gemini's own prompts for commands it auto-allows.

## Cursor

Cursor (1.7+) installs into `~/.cursor/hooks.json` under `beforeShellExecution` / `afterShellExecution`. The same file is read by the `cursor-agent` CLI, so no separate install step.

Cursor's hook schema documents three decisions (`allow`/`ask`/`deny`) but only `deny` is enforced today ("ask is accepted by the schema but not enforced" per Cursor's docs). Live testing confirmed Cursor does not surface a TUI prompt on `ask`, and the hook is re-invoked before the user can respond — which pins the command as `session_deny` via yolonot's asked-not-approved heuristic. We therefore treat Cursor as **deny-only**, same class as Codex / OpenCode:

- `allow` — empty stdout, command runs.
- `ask` — empty stdout (passthrough). Cursor's own permission UI decides. Tune with the [risk map](risk-tiers.md).
- `deny` — flat `{"permission":"deny","user_message":…,"agent_message":…}`. Banner shown to both user and agent so the model can self-correct.

```bash
yolonot risk cursor                    # show current map
yolonot risk cursor moderate deny      # turn moderate into hard deny
yolonot risk cursor moderate passthrough   # let Cursor's own permission engine decide (default)
```

Restart Cursor (or start a new chat) after `yolonot install --harness cursor` so the agent re-reads the file.

Session id arrives on stdin as `conversation_id`. Cursor does not export a session env var, so set `YOLONOT_CURSOR_SESSION_ID` if you need CLI commands (`yolonot pause`, `status`, etc.) to target a specific Cursor session from a shell.

## Escalation per harness

The [escalation model](models.md#escalation-second-opinion-model) triggers on the chain's *raw* uncertainty (`decision: ask`, any non-critical tier) or on a resolved ask, and only when a rescue or harden could change the outcome (a resolved deny is policy, never uncertainty), so it fires consistently across harnesses — but what a rescue or harden buys you differs:

| Harness | What escalation changes |
|---------|------------------------|
| Claude Code / Gemini | A rescue removes the ask prompt entirely (no interruption); a harden can turn an ask into a deny under a `critical → deny` risk map. |
| Codex / Cursor | The classifier's uncertain verdicts land in passthrough/deny cells. A rescue converts a wobbly passthrough into a definitive allow (with session memory); a harden can convert it into a deny instead of deferring to the host. |
| OpenCode | Default map resolves moderate rather permissively — hardening is the main value: a big-model `high`/`critical` verdict flips it to deny. |

Escalation improves *verdicts*; it cannot create enforcement on harnesses whose hook APIs don't enforce (see the per-harness notes above). For unattended runs on any harness, `"unresolved": "deny"` converts a post-escalation residual ask into a reasoned deny instead of a stall.
