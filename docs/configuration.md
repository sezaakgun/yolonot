# Configuration and diagnostics

Global configuration lives at `~/.yolonot/config.json`. Project `.yolonot`
files contain rules and prompt hints. Both are trusted policy: inspect a
checkout's policy before using it. CLI writers report persistence errors;
settings edits stay drafts until Save.

```bash
yolonot status --all                    # session state + effective policy in one view
yolonot status --harness opencode --json
yolonot doctor --harness codex          # health, installation, config & escalation latency
yolonot doctor --all --json
yolonot doctor --harness claude --probe-models
yolonot audit --harness codex           # security, broad rules, policy & host permission audit
yolonot audit --all --json
```

`doctor` checks configuration validity, hook registration, local CLI version,
required key variables, exec paths, and escalation latency, and prints a 1-line
summary pointer when security/policy warnings exist. `--probe-models`
explicitly makes model connection requests. Registration checks do not prove
that a running host loaded or trusted the hooks. See [harness verification](harnesses.md).

`audit` checks overly broad rules (`/*` suffix globs and broad `allow-cmd`
patterns on shell interpreters or mutating multiplex tools like `git *` or
`bash *`), policy risk settings (`attach_outside_root`, `force_allow` /
`high=allow` overrides), active paused sessions, and read-only host
permission/sandbox settings across Claude (`.claude/settings*.json`), Codex
(`config.toml`), Antigravity (`~/.gemini/config/config.json`) and Cursor
(`cli-config.json`).

`status --all` (and `status --json`) combines session decisions, resolved risk
tiers, profile, models, protocols, judges, rule sources, pause state, failure
actions, the deadline and active audit `Warnings`. JSON output exposes key
presence and variable names, never key values.

The [JSON schema](config.schema.json) supports editor completion. Runnable
examples are in [examples/](../examples/): local parser only, local typed
classification and a strict failure policy. `doctor` additionally checks
references, profiles, model names and protocols.

## Credentials in desktop hosts

Model `env_key` values are resolved in the yolonot process environment.
Interactive shell startup files such as `.zshrc` are not loaded by yolonot;
a key available in a terminal may therefore be absent in a desktop host's
mod or hook subprocess. Provide required variables to the host process and
restart it. Checking a Bash tool's environment alone does not prove that the
mod subprocess has the same variables.

A declared but missing key fails before any provider request and names the
missing variable without showing its value. Provider HTTP 401/403 responses
report an authentication/access error separately. Anonymous endpoints remain
supported when no `env_key` is declared. This applies to chat and typed judges
as well as Explain; the configured failure policy still decides the hook's
response to a model failure. Rule-only tests do not test provider connectivity.

Claude Desktop provides a native option: the prompt's environment dropdown →
Local → gear opens the local environment editor. Its documentation says those
variables are stored encrypted and applied to new local sessions on supported
platforms. This is preferable to adding a yolonot-specific credential store
solely for Desktop. The same documentation clarifies that macOS Desktop imports
only PATH and a fixed set of Claude variables from shell profiles, not arbitrary
exports. Add the model's required variables and start a fresh session, then
verify Explain and a live judge separately. The user verified that adding the
key here fixed Explain in the tested Desktop mod session; subsequent logs also
showed successful Jev classification. This does not certify every provider.
See [Claude Desktop environment configuration](https://code.claude.com/docs/en/desktop#local-sessions).

There is currently no built-in OS credential store. API keys are not persisted
by config writers. Explain continues to call the local binary; changing its
caller does not supply a missing credential.

## Failure policy

```json
{
  "failure": {
    "unavailable": "deny",
    "parse": "deny",
    "invalid_config": "deny",
    "oversize": "deny",
    "timeout": "deny"
  },
  "hook_timeout": 45
}
```

Each action can be `deny`, `ask` or `passthrough`. `ask` becomes deny when
the runtime adapter cannot reliably create a prompt. `passthrough` leaves
the decision to the host, including its unattended permission mode.

Defaults preserve provider outage/parse fallback to the host; malformed
configuration defaults to deny. Oversize and deadline defaults use the
profile's abstain policy, with deny on adapters without native ask. A
malformed JSON file cannot supply its own override, so it always denies.
Empty judge chains remain an intentional passthrough after rules/session
policy. Failure policy applies when the chain has no adopted verdict;
escalation errors keep the primary verdict and its unresolved policy.

`hook_timeout` is the shared model/exec budget, 1–55 seconds. Omitted or 0
uses 55. Individual model timeouts and the 3-second exec limit may end a
stage sooner. The maximum reserves teardown time within installed 60-second
hooks. This does not forcibly interrupt synchronous filesystem or stdin I/O.

These fields are also editable under POLICY in `yolonot config`.

## Explicit model protocols

Each catalog entry can set `protocol` independently of its URL:

| Protocol | Request/response contract |
|---|---|
| `chat` | OpenAI-compatible chat completions |
| `anthropic` | Anthropic Messages |
| `claude-cli` | Local `claude -p`; URL must be `claude-cli` |
| `systemone` | System One typed questions/answers |
| `decisions` | OpenAI Decisions questions/predicates |
| `workers-ai` | Typed answers within a Workers AI envelope |

Omission retains legacy URL inference. Set an explicit protocol for custom
typed endpoints whose path does not identify the API. Model settings expose
a Protocol chooser; new model additions persist the inferred protocol.

## Suggesting rules and hints from human resolutions

```bash
yolonot suggest               # interactive TUI picker
yolonot suggest --list        # non-interactive findings + candidate rules/hints
yolonot suggest --json        # structured JSON for tooling/skills
```

Human ask resolutions (`ask_approved`, `allow_once`, `ask_rejected`) are
recorded in `~/.yolonot/decisions.jsonl`. Rather than silently injecting raw
past commands into live judge prompts, `yolonot suggest` aggregates your human
resolutions alongside repeated asks, unseen scripts and escalation timeouts so
you (or your agent's `/yolonot` skill) can promote vetted `.yolonot` rules or
`allow-hint` / `ask-hint` directives. Native `PostToolUse` does not identify
the host's approval choice, so a completed pending native ask is recorded as
`allow_once` and surfaced as a repeated-ask candidate after 2+ occurrences
without creating an automatic session grant. Use `yolonot approve` or the
Claude mod's explicit session choice for a remembered session approval.

## Manual session decisions

```bash
yolonot approve 'exact command' --session-id <id>
yolonot deny 'exact command' --session-id <id>
yolonot reset --session-id <id>
```

Use the host's current session ID, `--current` for the most recently recorded
session, or its documented environment override. `--cwd <directory>` targets
that project's scope; the default is the current directory. Paths are
canonicalized so symlink spellings refer to one project. Old approvals keyed
through another spelling may require one fresh judgment after upgrading.

Approvals pin current script contents and supported direct native executable
snapshots; they never override explicit deny rules.
Deny removes equivalent approvals; reset clears this project's decisions and
replay records while preserving logs, learning history, pause and profile
pins. Multiline commands are stored as single encoded records. Use the CLI
instead of editing internal session files.

`--current` selects the latest recorded session, which may belong to another
chat. Prefer an explicit ID when several hosts or conversations are running.
Unanswered asks are pending state, not human rejections. Native hosts that do
not expose a rejection event cannot persist that answer through yolonot;
use explicit CLI deny or the Claude mod Deny choice when persistence is wanted.

## Decision-cache validity

New cache entries include a fingerprint of the model catalog, judge chain,
resolved prompts/hints, policy, learning configuration, script boundary and
project root. Changes invalidate prior entries. Legacy entries without a
fingerprint are re-judged. The fingerprint and script digest come from the
same snapshot that produced the verdict; later file/config edits cannot be
labelled as previously judged inputs. Risk mapping still applies on replay.
