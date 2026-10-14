# Commands

## CLI

```
yolonot              Status overview + session summary + update check (opens the settings screen on a terminal)
yolonot setup        First-run wizard (install + rules + models + chain)
yolonot config       Settings screen: judges, models, policy (profiles, harness overrides, rules), prompt
yolonot install      Install hooks + native skill (--skill-only skips hooks; --mod adds the Claude mod)
yolonot explain <cmd> Up to three lines from the first chat judge (stdin JSON {command, reason} also works)
yolonot models       Model catalog: list | add [typed] | remove <name> | test <name>
yolonot judges       Judge chain: list | add <entry> | remove <n|entry> | move <n|entry> up|down
                     (entry = fast_allow, exec:<path to hook>, or a model name)
yolonot rules        Show active rules + sensitive patterns (--trace includes sources)
yolonot status       Show session state (approved/asked/denied)
yolonot log [n]      Show the last n decisions with model timing (default 20; `-n <n>` also works; `--human` lists your answers to asks in this project)
yolonot suggest      Analyze history, suggest permanent rules
yolonot stats        Show analytics from decision history
yolonot check <cmd>  Preview rules/judges without command execution; may call models
yolonot config validate [file] Validate config without rewriting it
yolonot doctor       Check config, hook registration, host version and model/exec readiness
yolonot effective    Show consolidated resolved policy (--harness <name>, --json)
yolonot approve <cmd> Approve an exact command for this session/project (--session-id <id>)
yolonot deny <cmd>   Reject an exact command for this session/project
yolonot reset        Clear this project's session decisions; preserve logs and learning
yolonot learning     status|list|on|off|retention|limit|forget|clear|prune
yolonot risk         Show/set per-harness risk tier → action policy
yolonot profile      Pick a named risk policy (fast/balanced/strict/paranoid + custom)
yolonot prompt       Inspect/validate the chat-model prompt customization (defaults|config|review|verify)
yolonot escalation   Second-opinion model consulted before surfacing an ask (on|off|setup|test)
yolonot quiet        Silence banners for allow decisions (only show ask/deny)
yolonot migrate      Rewrite a 0.x config.json in the 1.x format (--dry-run | --undo)
yolonot pause        Disable yolonot for current session (total bypass)
yolonot resume       Re-enable yolonot for current session
yolonot uninstall    Remove hooks + managed native skill; preserve yolonot data
yolonot upgrade      Update to latest release
yolonot version      Show version
```

Removed in 1.0: `provider`, `decision` (use `models add`), `pre-check` (use `judges`), `classifier` (renamed `prompt`), `local-allow`, `threshold`. Each prints the replacement and exits 2.

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
yolonot quiet          # show current state
yolonot quiet on       # silence allow banners
yolonot quiet off      # restore default
```

Quiet mode only affects the user-facing `systemMessage`. The underlying `permissionDecision` + `permissionDecisionReason` still flow to the host CLI, and the decision log (`yolonot log`) is unchanged.

### Session identity and pause

Use `--session-id <id>` for the intended conversation. `--current` means the
latest recorded session, which may be a different chat. `status` also falls
back to the latest session when its host session variable is absent.

Pause is a session-wide bypass, including explicit deny rules, and requires
an explicit opt-in:

```bash
yolonot pause --session-id <id> --confirm-bypass
yolonot resume --session-id <id>
```

For one command, prefer project-scoped `approve` rather than pausing.
`check` excludes session memory/cache and skips exec judges; it cannot verify
a native approval dialog. See [configuration.md](configuration.md).

### Prompt customization

Read-only inspectors for the chat model's prompt. Full reference: [prompt.md](prompt.md).

```bash
yolonot prompt defaults    # Built-in base prompt + the built-in hint lists behind `$defaults`, as JSON
yolonot prompt config      # Effective prompt actually sent (config + walk-up, $defaults expanded)
yolonot prompt review      # The chat model audits your custom hints for ambiguity/redundancy/over-reach
yolonot prompt verify      # Prove a custom system_prompt still yields parseable verdicts
yolonot prompt             # Shorthand for `config`
```

Customize via `~/.yolonot/config.json` (`prompt.{context,allow_hints,ask_hints,system_prompt}`), the PROMPT section of `yolonot config` (each list opens in `$EDITOR`, one entry per line), or per-project `.yolonot` directives (`context`/`allow-hint`/`ask-hint`/`system-prompt`). `system_prompt` fully replaces the built-in base; hints still append. **Run `verify` after setting a `system_prompt`** — it static-checks the JSON verdict contract and round-trips real probes through your chat model, exiting non-zero if the override wouldn't function.

### Learning from your answers

Explicit remembered answers (mod Allow this session/Deny or CLI approve/deny)
can become **precedents** when learning is enabled, subject to retention and
caps. They are stored in `~/.yolonot/precedents.jsonl`, initially reconstructed
from eligible decision logs if missing. Native one-time approvals, unanswered
asks and answers recorded with learning disabled do not become precedents.
Two things use this history:

- **Model judge calls when learning is enabled.** Nearby precedents from the same project are supplied as historical hints. They do not grant current authorization. `learning off`, retention/caps, forget and clear control this behavior; allow-once answers are excluded.
- **`/yolonot learn`.** The harness's own model reads `yolonot log --human` (this repository's answers, latest per command) and proposes a handful of `allow-hint` / `ask-hint` sentences with their evidence; the ones you accept go into the project `.yolonot`. Sentences, not globs: they reach chat and typed models alike and generalise to variants an `allow-cmd` pattern would miss. yolonot itself makes no model call for this; the skill does the distilling, so the quality is that of the model you are already talking to.

## Skill (`/yolonot`)

Every supported host receives the same management workflows through its native
skill. Claude uses `/yolonot`, Codex Desktop uses `@yolonot` and Codex CLI/IDE
uses `$yolonot`; other hosts expose their own skill picker. The menu below uses
Claude syntax; the actions and shared CLI are portable:

```
/yolonot             Session summary + command menu
/yolonot status      Full approved/asked/denied lists
/yolonot approve X   Move command to approved
/yolonot deny X      Move command to denied
/yolonot reset       Clear session state
/yolonot log         Recent decisions
/yolonot rules       Show rules
/yolonot suggest     Suggest permanent rules from history
/yolonot learn       Turn your answers to asks into classifier hints
/yolonot check X     Dry-run: test pipeline for a command
/yolonot stats       Show decision analytics
/yolonot profile     Pick a named risk policy
/yolonot risk        Show/set per-harness risk tier → action policy
/yolonot judges      The judge chain
/yolonot models      Model catalog
/yolonot prompt      Prompt customization (defaults|config|review|verify)
/yolonot escalation  Second-opinion model status
/yolonot quiet       Silence allow banners
/yolonot pause       Disable yolonot for current session
/yolonot resume      Re-enable yolonot for current session
```

`approve`, `deny` and `reset` are native CLI verbs on all adapters. They
preserve project scope and script snapshots; use them instead of manually
editing session files. Skills require explicit user authorization for
mutations. See [configuration.md](configuration.md) for flags and examples.
