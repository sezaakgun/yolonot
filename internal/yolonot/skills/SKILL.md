---
name: yolonot
description: Manage yolonot command safety policy, session approvals, decision history, learning, judges and model configuration. Use for yolonot troubleshooting and explicit yolonot management requests.
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

- No arguments: show `yolonot status` with the identity caveat above, then a
  short menu of the workflows below.
- `yolonot doctor --harness {{HARNESS}}`: check installation and configuration.
  `--probe-models` additionally makes real provider requests; may incur charges.
- `yolonot effective --harness {{HARNESS}}`: resolved policy and controls.
- `yolonot config validate`: validate configuration without changing it.
- `yolonot check '<exact command>'`: classify without executing it. This can
  contact configured models. It excludes session memory and skips exec judges;
  it does not reproduce an entire live host approval flow.
- `yolonot log [n]`: recent decisions; `yolonot log --human`: durable human
  answers in this project, excluding allow-once answers.
- `yolonot stats`: aggregate decision and latency analytics.
- `yolonot rules --trace`: active rules with their sources.
- `yolonot profile`, `profile list`, `profile show <name>`: inspect profiles.
- `yolonot risk {{HARNESS}}`: inspect tier-to-action mapping.
- `yolonot judges`, `yolonot models`: inspect chain and model catalog.
- `yolonot models test <name>`: live provider request, not an offline check.
- `yolonot prompt config|defaults|review|verify`: inspect merged hints/defaults
  or review their quality; review/verify may call configured models.
- `yolonot quiet`, `yolonot escalation`: inspect banner and second-opinion state.
- `yolonot escalation test`: live second-opinion provider test.
- `yolonot learning status`, `yolonot learning list`: inspect retained hints.
- `yolonot migrate --dry-run`: preview legacy configuration migration.

Use the installed binary’s command menu and command usage errors for flags. Removed
verbs (`provider`, `decision`, `pre-check`, `classifier`, `local-allow`,
`threshold`) are not current commands.

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

Approval is scoped to the project, session and current script contents. Deny
removes equivalent approvals. Reset clears this project's session decisions
and replay records; logs, learned history, pause and profile pins remain.
Native host Allow once does not create a durable session approval or learning
record. A host's allow does not imply permission to persist an approval.

Pause is a total bypass of yolonot, session-wide rather than project-scoped.
Only use on an explicit request to pause protection:
`yolonot pause --session-id <id> --confirm-bypass`.
Restore with `yolonot resume --session-id <id>`.

## Policy, judges and models

State whether the requested change is global, per harness or per session.
Do not silently make a persistent global change for a temporary request.

- Profile: `yolonot profile use <name> --session-id <id>` for a session pin;
  omit the session flag for a persistent default, or use `--harness={{HARNESS}}`
  for a host pin. `profile reset` supports the same scope flags.
  `profile create <name> --base=<existing>` and `profile delete <name>` manage
  custom profiles.
- Risk: `yolonot risk {{HARNESS}} <tier> <allow|ask|deny|passthrough>`;
  undo a cell with `yolonot risk {{HARNESS}} reset <tier>`.
- Judges: `yolonot judges add <model|fast_allow|exec:/absolute/path>`,
  `judges remove <n|entry>`, `judges move <n|entry> up|down`.
- Models: `yolonot models add`, `models add typed`, `models remove <name>`.
  Addition is interactive. Removing a referenced model is refused.
- `yolonot escalation on|off|setup`: second-opinion controls.
- `yolonot quiet on|off`: allow banners only; enforcement is unchanged.
- `yolonot config`: interactive editor for policy, failures, time budget,
  learning, models, judges and prompts. Validate hand-edited JSON before use.

Judges run in order after rules and session memory. Model risk is translated
through the selected harness/profile policy. Failures follow configured failure
policy; they do not universally fall through to host permissions. Unsupported
native asks cannot be assumed to display a dialog. Inspect `effective` first.

## Rules, hints and learning

`yolonot init` creates missing example rule files. `yolonot suggest` is an
interactive review of history that can write rules; it needs the user's terminal.
Rule files are project `.yolonot` files and global `~/.yolonot/rules`.
`allow-cmd`, `ask-cmd`, `deny-cmd` match command patterns; `allow-path`,
`ask-path`, `deny-path` match executable/script paths. Rules may include a
trailing quoted explanation. `allow-redirect` permits literal redirect targets
for the fast allow judge. Use `rules --trace` to inspect discovered sources.

`context`, `allow-hint`, `ask-hint` are model context, not deterministic rules.
For a learn request, inspect `log --human` and existing project hints, propose
specific patterns backed by repeated consistent answers, and apply only the
hints the user authorizes. Do not generalize a wrapper or command prefix into
unrestricted approval. Omit secrets and contradictory examples. Do not treat
allow-once answers as training evidence. Confirm project/global scope if unclear.

`yolonot learning on|off`, `learning retention <days>`, `learning limit <n>`,
`learning forget '<exact command>'`, `learning clear`, `learning prune` manage
stored precedent. Explain deletion scope before a requested destructive change;
clearing precedent does not remove session decisions or explicit rules.

## Installation and upgrades

`yolonot install --harness {{HARNESS}} --skill-only` refreshes this skill without
changing hooks. Full `install --harness {{HARNESS}}` installs enforcement too;
`uninstall --harness {{HARNESS}}` removes that integration. `setup`, `upgrade`,
`migrate` and `migrate --undo` can change installed files or configuration.
Do not install unrelated harnesses or modify another host's settings implicitly.
Gemini is retired; use the Antigravity adapter for new installations.
