# Commands

## CLI

```
yolonot              Status overview + session summary + update check (opens the settings screen on a terminal)
yolonot setup        First-run wizard (install + rules + models + chain)
yolonot config       Settings screen: judges, models, policy (profiles, harness overrides, rules), prompt
yolonot install      Install hooks only (see --harness flags; --mod adds the Claude Code mod)
yolonot explain <cmd> One chat-model paragraph on why a command was flagged (stdin JSON {command, reason} also works)
yolonot models       Model catalog: list | add [typed] | remove <name> | test <name>
yolonot judges       Judge chain: list | add <entry> | remove <n|entry> | move <n|entry> up|down
                     (entry = fast_allow, exec:<path to hook>, or a model name)
yolonot rules        Show active rules + sensitive patterns
yolonot status       Show session state (approved/asked/denied)
yolonot log [n]      Show the last n decisions with model timing (default 20; `-n <n>` also works; `--human` lists your answers to asks in this project)
yolonot suggest      Analyze history, suggest permanent rules
yolonot stats        Show analytics from decision history
yolonot check <cmd>  Dry-run: what would the pipeline decide?
yolonot risk         Show/set per-harness risk tier → action policy
yolonot profile      Pick a named risk policy (fast/balanced/strict/paranoid + custom)
yolonot prompt       Inspect/validate the chat-model prompt customization (defaults|config|review|verify)
yolonot escalation   Second-opinion model consulted before surfacing an ask (on|off|setup|test)
yolonot quiet        Silence banners for allow decisions (only show ask/deny)
yolonot migrate      Rewrite a 0.x config.json in the 1.x format (--dry-run | --undo)
yolonot pause        Disable yolonot for current session (total bypass)
yolonot resume       Re-enable yolonot for current session
yolonot uninstall    Remove hooks from the active harness(es)
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
yolonot install --all              # every registered adapter
```

When neither flag is passed, yolonot operates on **detected** harnesses (hosts you actually have installed). See [harnesses.md](harnesses.md).

`yolonot install --mod` also writes the Claude Code mod (a function-hooks module) to `~/.yolonot/mod/` and names it in `~/.claude/settings.json` under `env.CLAUDE_CODE_PLUGIN_DIRS`; `yolonot uninstall` removes both. `yolonot mod install|uninstall` does only that part. See [harnesses.md](harnesses.md#claude-code-mod).

### Quiet mode

By default yolonot emits a short banner for every decision (`yolonot: 🧑‍🚀 <reason>`). To only surface ask/deny banners:

```bash
yolonot quiet          # show current state
yolonot quiet on       # silence allow banners
yolonot quiet off      # restore default
```

Quiet mode only affects the user-facing `systemMessage`. The underlying `permissionDecision` + `permissionDecisionReason` still flow to the host CLI, and the decision log (`yolonot log`) is unchanged.

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

Every ask you answer (allow this session, deny) is a **precedent**, kept in `~/.yolonot/precedents.jsonl` (built once from the decision log if missing). Two things use them:

- **Every judge call.** Before a chat or typed model sees a command, the closest precedents from the same repository (git root) are added to its hints: an allowed precedent as an "Allow when" line, a rejected one as an "Ask when" line. No configuration; "allow once" answers are never used.
- **`/yolonot learn`.** The harness's own model reads `yolonot log --human` (this repository's answers, latest per command) and proposes a handful of `allow-hint` / `ask-hint` sentences with their evidence; the ones you accept go into the project `.yolonot`. Sentences, not globs: they reach chat and typed models alike and generalise to variants an `allow-cmd` pattern would miss. yolonot itself makes no model call for this; the skill does the distilling, so the quality is that of the model you are already talking to.

## Skill (`/yolonot`)

After install, `/yolonot` is available as a Claude Code skill:

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

`approve`, `deny` and `reset` are skill-only: there is no `yolonot approve` verb. The skill edits the session files under `~/.yolonot/sessions/` after you confirm. Mutating verbs are printed for you to run, not executed by the assistant.
