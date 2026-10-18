---
name: yolonot
description: Manage yolonot command safety policy, session approvals, decision history, rule suggestions, security audits, judges and model configuration. Use for yolonot troubleshooting and explicit yolonot management requests.
---

<!-- yolonot-managed-skill -->

# Yolonot manager

Use the shared `yolonot` CLI for {{HARNESS}}. The same management workflows
apply in Claude, Codex, OpenCode, Cursor and Antigravity. This skill guides
management; installed hooks enforce shell decisions independently of skills.
Claude's optional mod dialog is a separate Claude-only integration.

## Scope and authorization

Run diagnostics for the requested project. Explain proposed policy/history
changes and their scope. An explicit user request authorizes that change;
otherwise propose it before making it. Interactive commands need the user's
terminal: provide the exact command when no interactive terminal is available.
Never approve your own blocked command, pause protection, change a judge or
relax rules to evade a rejection. A user-approved command still cannot override
an explicit deny rule or the host's own permissions.

Use CLI commands for session state; do not edit session files directly. Quote
exact command arguments safely, preserving newlines and shell metacharacters.
Do not execute the command being classified. Logs and arguments may contain
credentials: summarize relevant evidence without exposing secrets or tool
response bodies.

## Session identity

Use the current host's actual session/conversation ID, preferably supplied by
the host or explicitly by the user. Environment sources understood by yolonot:

| Host | Session environment |
|---|---|
| Claude | `CLAUDE_SESSION_ID` |
| Codex | `YOLONOT_CODEX_SESSION_ID` |
| OpenCode | `YOLONOT_OPENCODE_SESSION_ID` or `OPENCODE_SESSION_ID` |
| Cursor | `YOLONOT_CURSOR_SESSION_ID` |
| Antigravity | `YOLONOT_ANTIGRAVITY_SESSION_ID` |

Most hosts supply the ID to hooks without exporting it to shell tools. Do not
invent it or infer it from the newest file. `--current` means the most recently
recorded session, which may belong to another conversation; use it only when
that is what the user requests. `status` also falls back to the latest session:
when the current ID is known, set the appropriate environment above for this
invocation. Otherwise label its output as the latest recorded session, not this
chat. Pass `--session-id <id>` explicitly to mutations and session profile pins.

## Diagnostics and inspection

- No arguments: show `yolonot status` (or `yolonot status --all` for session +
  effective policy in one call, or `yolonot status --json --harness {{HARNESS}}`
  for structured output) with the identity caveat above, then a short menu of
  the workflows below.
- `yolonot doctor --harness {{HARNESS}}`: check installation, `config.json`
  validity, host versions, configured models, judge chain and escalation
  latency, plus a 1-line summary pointer when security/policy warnings exist.
  `--probe-models` additionally makes real provider requests; may incur charges.
- `yolonot audit --harness {{HARNESS}}`: audit security, broad `allow-cmd`
  rules in `.yolonot`, policy risk warnings (`attach_outside_root`,
  `force_allow`, `high=allow`), paused sessions and host permission/sandbox
  settings (`Bash(*)`, `bypassPermissions`, `approval_policy = "never"`,
  `sandbox_mode = "danger-full-access"`, `command(*)`, `Shell(*)`).
- `yolonot check [--cwd <dir>] '<exact command>'`: classify without executing
  it and print which scripts were attached or withheld. This can contact
  configured models. It excludes session memory and skips exec judges; it does
  not reproduce an entire live host approval flow.
- `yolonot log [n]`: recent decisions; `yolonot log --session <id|current>`:
  one session's decisions.
- `yolonot stats`: aggregate decision and latency analytics, starting with an
  `Impact` summary (`Auto-approved`, `Speed saved`, `Threats stopped` and top
  blocked/hardened incidents); `--session <id|current>`, `--since today|24h|7d`,
  `--project <name>`.
- Too many asks: run `yolonot stats --session <id>` (or `--since today` when
  the session is unknown; the unfiltered output ranks sessions by asks), then
  `yolonot suggest --list` to see repeated-ask buckets, human resolution counts
  (`approved`, `once`, `rejected`), unseen scripts and exact repeated-ask
  candidates, and `yolonot doctor` for escalation latency. Do not parse
  `decisions.jsonl` by hand.
- `yolonot rules`: active static rules and LLM hints (`allow-hint`, `ask-hint`,
  `context`) per file; `yolonot rules --trace`: every loaded rule and hint with
  source path and line; `yolonot rules config|defaults|review|verify`: inspect
  merged prompt JSON or review/verify custom hints with the active LLM.
- `yolonot profile`: active profile and 5-tier risk map for {{HARNESS}};
  `profile list`, `profile show <name>`, `profile {{HARNESS}}`: inspect profiles
  and per-harness tier mappings.
- `yolonot judges`, `yolonot models`: inspect judge chain, escalation status
  and model catalog.
- `yolonot models test <name>`: live provider request, not an offline check.
- `yolonot judges escalation [test]`: inspect or live-test second-opinion
  escalation.
- `yolonot config quiet`: inspect banner state.
- `yolonot migrate --dry-run`: preview legacy configuration migration.

Use the installed binary's command menu and command usage errors for flags.
Retired verbs (`provider`, `decision`, `pre-check`, `classifier`,
`local-allow`, `threshold`, `learning`, `effective`, `validate`, `prompt`,
`risk`, `escalation`, `quiet`, `evolve`) are not current commands.

## Session decisions

For explicit user requests, run from the intended project:

```sh
yolonot approve '<exact command>' --session-id <id>
yolonot deny '<exact command>' --session-id <id>
yolonot reset --session-id <id>
```

When you run these yourself, the hook asks the user to confirm each one; on
hosts without an ask (Codex) it is denied, so print the command for the user
to run instead. Pass the command as one quoted argument.

Approval is scoped to the project, session and current script contents. Calls
that request host sandbox bypass (`[unsandboxed]` in `status` / `log`) skip
`allow-cmd`/`fast_allow` and use an isolated session bucket
(`approved_unsandboxed`) so a sandboxed approval never authorizes an
unsandboxed replay. Deny removes equivalent approvals. Reset clears this
project's session decisions and replay records; logs, pause and profile pins
remain. Native host Allow once does not create a durable session approval. A
host's allow does not imply permission to persist an approval.

Pause is a total bypass of yolonot, session-wide rather than project-scoped.
Only use on an explicit request to pause protection:
`yolonot pause --session-id <id> --confirm-bypass`.
Restore with `yolonot resume --session-id <id>`.
Global pause (`yolonot pause --global --confirm-bypass` / `yolonot resume --global`)
is hard-blocked by the hook for agents and must never be executed from this
skill; if the user explicitly asks to pause or resume globally, print the
command for the user to run in their own terminal.

## Policy, judges and models

State whether the requested change is global, per harness or per session.
Do not silently make a persistent global change for a temporary request.

- Profile: `yolonot profile use <name> --session-id <id>` for a session pin;
  omit the session flag for a persistent default, or use `--harness={{HARNESS}}`
  for a host pin. `profile reset` supports the same scope flags.
  `profile create <name> --base=<existing>` and `profile delete <name>` manage
  custom profiles.
- Risk overrides: `yolonot profile {{HARNESS}} <tier> <allow|force_allow|ask|deny|passthrough>`
  (`allow` is escalate-only and preserves a model's `ask`; `force_allow`
  overrides a model's `ask` to `allow` on non-critical tiers; `critical` never
  allows `allow` or `force_allow`); undo a cell with
  `yolonot profile {{HARNESS}} reset <tier>` (or `<tier> reset`).
- Judges: `yolonot judges add <model|fast_allow|exec:/absolute/path>`,
  `judges remove <n|entry>`, `judges move <n|entry> up|down`.
- Escalation: `yolonot judges escalation on|off|setup|test` manages the
  second-opinion model when the primary judge returns `ask`.
- Models: `yolonot models add`, `models add typed`, `models remove <name>`.
  Addition is interactive. Removing a referenced model is refused.
- Quiet banners: `yolonot config quiet on|off` controls allow banners only;
  enforcement is unchanged.
- `yolonot config`: interactive editor for policy, failures, time budget,
  models, judges and prompts.

Judges run in order after rules and session memory. Model risk is translated
through the selected harness/profile policy. Failures follow configured failure
policy; they do not universally fall through to host permissions. Unsupported
native asks cannot be assumed to display a dialog. Inspect `yolonot status --all`
first.

## Rules, hints and suggest

`yolonot init` creates missing example rule files. `yolonot suggest` analyzes
`decisions.jsonl` — combining judge verdicts, unseen scripts, escalation
timeouts and human ask resolutions (`approved`, `once`, `rejected`) — to
recommend project/global rules or hints.
- In an interactive user terminal, `yolonot suggest` opens a TUI picker.
- From this skill or a non-interactive shell, run `yolonot suggest --list` (or
  `yolonot suggest --json` / `--basic`) to inspect all findings, LLM
  recommendations and repeated-ask candidates without blocking on a TTY.
- Propose specific `.yolonot` `allow-hint`, `ask-hint`, `allow-cmd` or
  `allow-path` entries backed by repeated consistent human approvals, and apply
  only the rules or hints the user authorizes.

Rule files are project `.yolonot` files and global `~/.yolonot/rules`.
`allow-cmd`, `ask-cmd`, `deny-cmd` match command patterns; `allow-path`,
`ask-path`, `deny-path` match executable/script paths. Rules may include a
trailing quoted explanation. `allow-redirect` permits literal redirect targets
for the fast allow judge. Use `yolonot rules --trace` to inspect discovered
sources.

`context`, `allow-hint`, `ask-hint` are model context, not deterministic rules.
A script the judge could not see (`SCRIPT NOT SHOWN` in `suggest` / `stats`) is
a case for an `allow-path` or `allow-hint` describing the script, since
`allow-cmd` rules never match chained commands. Do not generalize a wrapper or
command prefix into unrestricted approval. Omit secrets and contradictory
examples. Confirm project/global scope if unclear.

## Installation and upgrades

`yolonot install --harness {{HARNESS}} --skill-only` refreshes this skill without
changing hooks. Full `install --harness {{HARNESS}}` installs enforcement too;
`uninstall --harness {{HARNESS}}` removes that integration. `setup`, `upgrade`,
`migrate` and `migrate --undo` can change installed files or configuration.
Do not install unrelated harnesses or modify another host's settings implicitly.
Gemini is retired; use the Antigravity adapter for new installations.
