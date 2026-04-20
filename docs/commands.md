# Commands

## CLI

```
yolonot              Status overview + session summary + update check
yolonot setup        First-run wizard (install + rules + provider)
yolonot install      Install hooks only (see --harness flags)
yolonot provider     Change LLM provider (interactive TUI)
yolonot rules        Show active rules + sensitive patterns
yolonot status       Show session state (approved/asked/denied)
yolonot log          Show recent decisions with LLM timing
yolonot suggest      Analyze history, suggest permanent rules
yolonot stats        Show analytics from decision history
yolonot check <cmd>  Dry-run: what would the pipeline decide?
yolonot risk         Show/set per-harness risk tier → action policy
yolonot pre-check    Manage pre-checkers (fast-allow + external hooks)
yolonot quiet        Silence banners for allow decisions (only show ask/deny)
yolonot pause        Disable yolonot for current session (total bypass)
yolonot resume       Re-enable yolonot for current session
yolonot uninstall    Remove hooks from the active harness(es)
yolonot upgrade      Update to latest release
yolonot version      Show version
```

### Verbose mode

Add `-v` (or `--verbose`) to any command — before or after the subcommand — to print extra detail on stderr (paths written, bytes, hook entries touched). Useful for debugging install/init/config issues without parsing decision logs. Verbose output goes to stderr so it never corrupts the `yolonot hook` JSON protocol on stdout.

### Harness targeting

`install`, `uninstall`, and `setup` accept:

```bash
yolonot install --harness codex    # one harness
yolonot install --all              # every registered adapter
```

When neither flag is passed, yolonot operates on **detected** harnesses (hosts you actually have installed). See [harnesses.md](harnesses.md).

### Quiet mode

By default yolonot emits a short banner for every decision (`yolonot: 🧑‍🚀 <reason>`). To only surface ask/deny banners:

```bash
yolonot quiet          # show current state
yolonot quiet on       # silence allow banners
yolonot quiet off      # restore default
```

Quiet mode only affects the user-facing `systemMessage`. The underlying `permissionDecision` + `permissionDecisionReason` still flow to the host CLI, and the decision log (`yolonot log`) is unchanged.

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
/yolonot check X     Dry-run: test pipeline for a command
/yolonot stats       Show decision analytics
/yolonot risk        Show/set per-harness risk tier → action policy
/yolonot pause       Disable yolonot for current session
/yolonot resume      Re-enable yolonot for current session
```
