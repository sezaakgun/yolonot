# AI harnesses

yolonot was built for Claude Code but also ships adapters for other bash-capable AI coding tools. Pick one explicitly with `--harness` (or `YOLONOT_HARNESS=<name>`); otherwise yolonot auto-detects.

| Harness | `ask` prompt support | Notes |
|---------|----------------------|-------|
| **Claude Code** (default) | full 3-state (allow/ask/deny) | Native hook protocol. |
| **Codex CLI** | deny only | Upstream hook API has no user-prompt primitive. Moderate-risk commands fall through to Codex's own permission engine (yolonot goes transparent); high/critical still hard-deny. |
| **OpenCode** | deny only | Plugin hook `tool.execute.before` is throw-to-block or return-to-allow. yolonot maps moderate-risk to allow since empty stdout is treated as allow; high/critical still hard-deny. |
| **Gemini CLI** | full 3-state — **with caveat** (see below) | Needs `--yolo` for `allow` to take effect. |

## Install

```bash
yolonot install --harness claude      # Claude Code only
yolonot install --harness codex       # Codex CLI only
yolonot install --harness opencode    # OpenCode only
yolonot install --harness gemini      # Gemini CLI only
yolonot install --all                 # every registered adapter
```

When neither flag is passed, `yolonot install` targets every **detected** harness (i.e. whichever CLIs you have installed). `yolonot setup` runs install + rules + provider pick in one go and accepts the same flags.

Uninstall mirrors this: `yolonot uninstall --harness <name>` or `--all`. Without a flag, `uninstall` defaults to every *currently installed* adapter.

Restart the host CLI after install so it re-reads hooks.

## Runtime pinning

The hook binary is installed with `--harness <name>` baked into the host's hook command, so it routes to the right adapter automatically. To force-pin from your shell (e.g. for `yolonot check` against a specific harness):

```bash
YOLONOT_HARNESS=claude claude
YOLONOT_HARNESS=codex codex
YOLONOT_HARNESS=opencode opencode
YOLONOT_HARNESS=gemini gemini --yolo
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
