# Commands

## CLI

```
  Inspect & Diagnose:
yolonot              Status overview + session summary + update check (opens the settings screen on a terminal)
yolonot status       Show session state (--all includes resolved effective policy; --json; --harness <name>)
yolonot doctor       Check health, installation, config validity, models, judge chain, escalation latency
yolonot audit        Audit broad allow-cmd rules, policy risks, paused sessions, and host permissions/sandbox
yolonot log [n]      Show the last n decisions with model timing (default 20; `-n <n>`; `--session <id|current>`)
yolonot stats        Show impact summary, blocked/hardened incidents, and analytics (--session <id|current>, --since today|24h|7d, --project <name>)
yolonot check [--cwd <dir>] <cmd>  Preview rules/judges without command execution; prints which scripts the judge saw
yolonot explain <cmd> Up to three lines from the first chat judge (stdin JSON {command, reason} also works)

  Session Control:
yolonot approve '<cmd>' Approve an exact command for this session/project (--session-id <id>)
yolonot deny '<cmd>'   Reject an exact command for this session/project
                       (quote the command as one argument; split words are rejected)
yolonot reset        Clear this project's session decisions; preserve logs
yolonot pause        Disable yolonot for current session (total bypass; requires --confirm-bypass)
yolonot resume       Re-enable yolonot for current session

  Policy & Rules:
yolonot config       Settings screen: judges, models, policy, prompt (`config quiet [on|off]` toggles allow banners)
yolonot profile      Manage risk profiles and per-harness tier maps (`profile <harness> [<tier> <action|reset>]`)
yolonot rules        Show active rules, hints + sensitive patterns (`--trace` includes sources; `defaults|config|review|verify` inspect/verify prompt customization)
yolonot suggest      Analyze history and human ask resolutions to suggest rules/hints (`--list` | `--json` | `--basic`)

  Setup & Models:
yolonot setup        First-run wizard (install + rules + models + chain)
yolonot install      Install hooks + native skill (--skill-only skips hooks; --mod adds the Claude mod)
yolonot uninstall    Remove hooks + managed native skill; preserve yolonot data
yolonot models       Model catalog: list | add [typed] | remove <name> | test <name>
yolonot judges       Judge chain & escalation: list | add <entry> | remove <n|entry> | move <n|entry> up|down | escalation [on|off|setup|test]
                     (entry = fast_allow, exec:<path to hook>, or a model name)
yolonot migrate      Rewrite a 0.x config.json in the 1.x format (--dry-run | --undo)
yolonot upgrade      Update to latest release
yolonot version      Show version
```

Consolidated in 1.0:
- `effective` → `yolonot status --all` (or `yolonot status --json`)
- `validate` / `config validate` → `yolonot doctor`
- `prompt` / `classifier` → `yolonot rules [defaults|config|review|verify]`
- `risk` → `yolonot profile [<harness> [<tier> <action|reset>]]`
- `escalation` → `yolonot judges [escalation [on|off|setup|test]]`
- `quiet` → `yolonot config quiet [on|off]`
- `learning` / `log --human` / `evolve` → `yolonot suggest [--list | --json]`

### Verbose mode

Add `-v` (or `--verbose`) to any command — before or after the subcommand — to print extra detail on stderr (paths written, bytes, hook entries touched). Useful for debugging install/init/config issues without parsing decision logs. Verbose output goes to stderr so it never corrupts the `yolonot hook` JSON protocol on stdout.

### Harness targeting

`install`, `uninstall`, and `setup` accept:

```bash
yolonot install --harness codex    # one harness
yolonot install --all              # every supported adapter
```

Without a flag, install/setup target **detected** harnesses and uninstall
targets **installed** adapters. A targeted operation changes only that
harness, including its optional mod. See [harnesses.md](harnesses.md).

`yolonot install --mod` also writes the Claude Code mod (a function-hooks module) to `~/.yolonot/mod/` and names it in `~/.claude/settings.json` under `env.CLAUDE_CODE_PLUGIN_DIRS`; `yolonot uninstall` removes both. `yolonot mod install|uninstall` does only that part. See [harnesses.md](harnesses.md#claude-code-mod).

### Saving settings

`yolonot config` stages changes until Save, including global and project
rule-file edits made in `$EDITOR`. Discard leaves the active files unchanged.
Save creates a config backup and reports write errors; a failed config save
rolls back rule-file writes and keeps the draft available for retry.

### Quiet mode

By default yolonot emits a short banner for every decision (`yolonot: 🧑‍🚀 <reason>`). To only surface ask/deny banners:

```bash
yolonot config quiet          # show current state
yolonot config quiet on       # silence allow banners
yolonot config quiet off      # restore default
```

Quiet mode only affects the user-facing `systemMessage`. The underlying `permissionDecision` + `permissionDecisionReason` still flow to the host CLI, and the decision log (`yolonot log`) is unchanged.

### Session identity and pause

Use `--session-id <id>` for the intended conversation. `--current` means the
latest recorded session, which may be a different chat. `status` also falls
back to the latest session when its host session variable is absent.

Pause is a session-wide (or global) bypass, including explicit deny rules, and
requires an explicit opt-in (`--global` is hard-denied if invoked by an agent):

```bash
yolonot pause --session-id <id> --confirm-bypass
yolonot resume --session-id <id>
yolonot pause --global --confirm-bypass
yolonot resume --global
```

For one command, prefer project-scoped `approve` rather than pausing.
`check` excludes session memory/cache and skips exec judges; it cannot verify
a native approval dialog. See [configuration.md](configuration.md).

### Rules and prompt customization

Inspect active rules, LLM hints, and the chat model's prompt customization. Full reference: [prompt.md](prompt.md).

```bash
yolonot rules              # Active rules, hints (allow-hint/ask-hint/context) and sensitive patterns
yolonot rules --trace      # Every loaded rule and hint with source file, line number and shadowing
yolonot rules defaults     # Built-in base prompt + the built-in hint lists behind `$defaults`, as JSON
yolonot rules config       # Effective prompt actually sent (config + walk-up, $defaults expanded)
yolonot rules review       # The chat model audits your custom hints for ambiguity/redundancy/over-reach
yolonot rules verify       # Prove a custom system_prompt still yields parseable verdicts
```

Customize via `~/.yolonot/config.json` (`prompt.{context,allow_hints,ask_hints,system_prompt}`), the PROMPT section of `yolonot config` (each list opens in `$EDITOR`, one entry per line), or per-project `.yolonot` directives (`context`/`allow-hint`/`ask-hint`/`system-prompt`). `system_prompt` fully replaces the built-in base; hints still append. **Run `yolonot rules verify` after setting a `system_prompt`** — it static-checks the JSON verdict contract and round-trips real probes through your chat model, exiting non-zero if the override wouldn't function.

### Suggesting rules and hints from your answers (`yolonot suggest`)

Human ask resolutions (`ask_approved`, `allow_once`, `ask_rejected`) are recorded in `~/.yolonot/decisions.jsonl` and feed directly into `yolonot suggest`:

- **Interactive terminal (`yolonot suggest`)**: Groups repeated asks, unseen scripts, escalation timeouts, and low-confidence allows alongside your human resolution counts (`approved`, `once`, `rejected`), asks your configured LLM for a tailored rule/hint recommendation, and lets you apply rules or hints to `.yolonot` or `~/.yolonot/rules`.
- **Non-interactive / Skill mode (`yolonot suggest --list` or `--json`)**: Emits all findings, smart recommendations, and exact repeated-ask candidates (`Asked at least twice and allowed each time`) without opening an interactive TUI. Your coding agent's `/yolonot` skill uses `yolonot suggest --list` to propose high-precision `allow-hint`, `ask-hint`, `allow-cmd`, or `allow-path` rules for your approval.

## Skill (`/yolonot`)

Every supported host receives the same management workflows through its native
skill. Claude uses `/yolonot`, Codex Desktop uses `@yolonot` and Codex CLI/IDE
uses `$yolonot`; other hosts expose their own skill picker. The menu below uses
Claude syntax; the actions and shared CLI are portable:

```
/yolonot             Session summary + command menu
/yolonot status      Session decisions + effective policy (--all, --json)
/yolonot doctor      Health, hooks, config, escalation latency
/yolonot audit       Security, broad rules, policy & host permission audit
/yolonot approve X   Move command to approved
/yolonot deny X      Move command to denied
/yolonot reset       Clear session state
/yolonot log         Recent decisions
/yolonot rules       Show rules, hints, and prompt customization (--trace, config, review, verify)
/yolonot suggest     Suggest permanent rules and hints from history (--list, --json)
/yolonot check X     Dry-run: test pipeline for a command
/yolonot stats       Show decision analytics and impact summary
/yolonot profile     Manage risk profiles and per-harness tier maps
/yolonot judges      The judge chain and second-opinion escalation
/yolonot models      Model catalog
/yolonot config      Settings screen and quiet banner toggle (config quiet on|off)
/yolonot pause       Disable yolonot for current session
/yolonot resume      Re-enable yolonot for current session
```

`approve`, `deny` and `reset` are native CLI verbs on all adapters. They
preserve project scope and script snapshots; use them instead of manually
editing session files. Skills require explicit user authorization for
mutations. See [configuration.md](configuration.md) for flags and examples.
