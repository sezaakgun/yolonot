# Security, privacy and failure behavior

yolonot gates shell tool calls exposed by supported coding harnesses. It
does not sandbox a process, mediate every file read or edit, or authorize
arbitrary MCP tools. Keep the host's own sandbox and permissions in place.

## Trusted configuration

Explicit deny rules run before session approvals, model judges and Claude
mod replay. Replay is bound to the tool ID, command, working directory and
inspected script contents; completion closes that call's replay. Supported
direct native executables have a separate local content/target/mode snapshot
that is never sent to the model. Changed inspected files must be judged again.
Commands whose script contents are withheld cannot reuse a mod verdict.

Global configuration and project `.yolonot` files are trusted policy.
Malformed global configuration defaults to deny and CLI validation reports
errors rather than activating a partial policy.
Inspect project policy before using an unfamiliar checkout. A process
running as your user can edit your policy and session files; yolonot is not
a privilege boundary against that process. External `exec:` judges also
execute with your user privileges, so install only hooks you trust.

Models can misclassify commands or follow adversarial instructions in
inputs. Use explicit deny rules for commands that must be blocked. A model
verdict is a judgment about the inspected inputs, not proof that a command
has no side effects.

## Model requests and local data

Model judges receive the command and any scripts the attachment rules can
identify safely. The attachment boundary is the project root by default;
`attach_outside_root` explicitly widens it. Sensitive home directories are
always withheld. Script credential redaction is best effort; commands may
themselves contain secrets. See [script attachment](how-it-works.md#script-attachment).

Prompt hints and nearby human precedents in the same project also reach the
configured model judges. Precedents persist across sessions: an ordinary
approval can influence a future judgment as a hint, without creating a
permanent allow rule. `Allow once` answers are excluded. Native prompt approvals with no exposed
persistence choice are conservatively one-time: they do not become yolonot
session grants or learned precedents. Explicit `yolonot approve` and the
Claude mod session option provide remembered human grants. When an agent runs
`yolonot approve`, `deny`, `reset`, `learning`, `pause`, `resume` or
`uninstall` itself, or changes `profile`, `risk`, `judges`, `models`,
`escalation` or `quiet`, the hook always asks (deny on hosts without ask),
whatever the rules or judges say, also through global flags or `sh -c`, so an
agent cannot grant itself approval. Inspect the stored
answers with `yolonot log --human`. Disable recording/use with `learning off`;
configure retention/caps and remove entries with forget/clear/prune. Answers
recorded while disabled are excluded from later log-based reconstruction.

An unanswered ask is not a user rejection. Cancelled or unavailable mod
dialogs block the current call without creating a human Deny or session deny.
Classic hosts without explicit rejection events cannot persist a Deny answer
from missing completion alone.

Decision logs and session state are local under `~/.yolonot/`. They can contain
command arguments, paths and model reasoning. The model provider's own data
handling applies to requests you send it. API keys are resolved from the
configured environment variable and are not persisted by config saves.

## Failure behavior

| Condition | Behavior |
|---|---|
| Explicit deny rule | Block before the judge chain and mod replay. |
| Missing configured model API-key variable | Fail before a provider request; follow unavailable failure policy if no other judge decides. A terminal export may be absent in Desktop hooks/mods. |
| Invalid global configuration | Deny by default; no partial JSON policy is activated. |
| Invalid typed answer | Treat as a parse failure; try the next judge, then apply failure policy if none decides. |
| Non-2xx model response | Treat that judge as unavailable; try the next judge. |
| All models fail or return unparseable decisions | Defer to the host's native permission policy, with a warning where the adapter can display it. |
| Empty judge chain | Defer to the host; explicit rules and session policy still apply. |
| Classifier prompt exceeds the size limit | Use the profile's abstain action: deny if the critical cell denies, otherwise ask. |
| Shared hook deadline expires before a judge produces a verdict | Stop model/exec work; deny if policy requires it, otherwise ask on adapters with native ask and deny on adapters without native ask. No new approval is cached. |
| Escalation fails | Keep the primary verdict; do not cache a transient failed escalation. |
| OpenCode shim process fails or emits malformed JSON | Block. Successful empty stdout is intentional passthrough. |
| Pause or `YOLONOT_DISABLED=1` | Bypass yolonot; host permissions remain responsible. |

These are defaults. `failure` actions configure unavailable/parse/config/
oversize/timeout outcomes; unsupported native ask becomes deny. An empty
chain is still intentional passthrough. [Configuration reference](configuration.md).

Similarity, all judges and escalation share a configurable decision deadline
(default 55 seconds, maximum 55),
leaving time to emit a result before the installed 60-second host hook limit.
Individual provider timeouts and the 3-second exec timeout may end a stage
earlier; they never restart the overall budget.

New decision-cache entries include the judging model/prompt/hint/policy
fingerprint and script snapshot; legacy entries without that metadata are
re-judged. Native host failure enforcement still differs: current Claude
installation blocks hook failures via `onFailure`, OpenCode shim errors block,
and Codex requires trusted hooks. See [harness behavior](harnesses.md).

Host capabilities differ. In particular, passthrough can still prompt or
allow according to the host's policy. Check [harness behavior](harnesses.md)
and `yolonot risk <harness>` before relying on an unattended workflow.
