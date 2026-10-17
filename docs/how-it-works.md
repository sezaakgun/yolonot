# How it works

Each shell tool call covered by the selected adapter goes through this
pipeline. The first applicable decision wins; host permissions still apply.

1. **Deny rules** — absolute block, no override, checked first.
2. **Allow rules** — `.yolonot` `allow-*` patterns → instant allow. Placed before session memory so a newly added allow rule clears a command the session had rejected. See [rules.md](rules.md).
3. **Session memory** — exact match against previously approved commands → instant allow. Content-aware for script commands: the approval is pinned to the script contents that were approved, so editing the script re-judges instead of replaying the allow.
4. **Session deny** — explicitly rejected commands → instant block. An unanswered ask does not establish rejection.
5. **Ask rules** — `.yolonot` `ask-*` patterns → ask, only when the session has no opinion yet (a prior approval is not re-prompted). Among rules the priority is deny > ask > allow, whatever the file order.
6. **Judges** — the ordered chain in `config.json`: `fast_allow` (built-in bash parser), `exec:<path>` hooks like [Dippy](https://github.com/ldayton/Dippy) or your own classifier binary, then [models](models.md) by name: a typed decision model (TypeSafe Jev, Microsoft-Decision-1, OpenAI Decisions, Cloudflare Clef) and/or a chat model. The first judge whose verdict is permitted (`may`) wins; `fast_allow` and exec hooks may only allow by default. See [judges.md](judges.md).
   - Right before the first model judge, two memory layers run once: **session similarity** (the chat model compares against approved commands → allow if similar, project-aware, prefix-prefiltered) and the **script cache** (SHA256 of the command plus the full contents of every attached script → reuse the cached verdict; editing an attached script, policy, prompt, model or relevant learning context invalidates it).
   - Models emit a [risk tier](risk-tiers.md) with the verdict. Referenced scripts are attached to the prompt when it is provable which file will run (see below).
7. **Escalation (optional)** — when a model verdict is uncertain in a way that would surface an ask, a configured bigger chat model gets one look before the interruption. A confident `allow` + `safe`/`low` from it rescues the ask into an allow; a more dangerous tier hardens the verdict upward; anything else (including errors) leaves the verdict standing. Never fires on confident allows, `critical` verdicts, rule-layer denies, or the oversize abstain. See [models.md](models.md#escalation-second-opinion-model). Harnesses whose hooks yolonot cannot gate at all get no benefit from escalation — it improves verdicts, it cannot create enforcement where a harness offers none.
8. **Unresolved policy** — a residual ask after escalation stays an ask, or becomes a deny with `"escalation": {"unresolved": "deny"}` for unattended runs.
9. **Risk map** — the active [profile](risk-profiles.md) turns the tier into the final action for the active harness. The map only tightens: an `allow` cell leaves a model's ask standing, it never turns it into an allow.

Sessions are project-aware. A command approved in one project is not auto-approved in another within the same session — session keys include a hash of the git root (or working directory).

When Claude's optional mod is installed, its verdict can replay after current
deny/allow rules, before session memory. Replay is bound to the tool ID,
command, cwd and inspected file snapshot; completion closes that call's replay.
Supported direct native executables use a separate local snapshot without
sending binary contents to the model. See [the mod contract](harnesses.md#claude-code-mod).

`deny` rules are absolute — nothing overrides them. `ask` rules are bypassed only by an existing session grant. A native prompt approval is one-time when the host does not expose its persistence choice; use `yolonot approve` or the mod session option to remember it. `allow` rules are instant but are skipped for chained commands, redirects, and commands touching sensitive files (see [rules.md](rules.md)).

When configured model judges all fail, the default is to defer to the host's
native permission system, with a warning where supported. An empty chain is
transparent without a model failure warning. Invalid configuration defaults
to deny. Failure actions are configurable by category.

Similarity, judges and escalation share one decision deadline: 55 seconds by
default, configurable with `hook_timeout` up to 55. Exhaustion before an
adopted verdict asks when the adapter supports native ask and denies otherwise;
it never caches an approval. An escalation timeout keeps the primary verdict.
See [configuration.md](configuration.md) and [harnesses.md](harnesses.md).

## Script attachment

When a command references a script file, yolonot reads it and embeds the contents in the classifier prompt so the model judges actual code instead of guessing from a filename. Contents are attached only when it is **provable which file bash will execute**:

- the script is a leading path in a simple command — `./run.sh`, `scripts/x.sh --flag`
- or it directly follows a known interpreter with nothing in between — `python foo.py`, `bash scripts/x.sh`, `node server.js`, `uv run python test.py`
- absolute paths inside the project always attach, in any command shape

The proof is applied to each simple command of a list in turn (`&&`, `||`, `;`, `|`, `&`, newline), so `./a.sh && python b.py 2>&1 | tail` attaches both. A literal `cd <dir>` as the first simple command, terminated by `&&`, `;` or a newline, moves the base directory for what follows (`cd ~/work/repo && .local-ci/run.sh` attaches the script under that repo, never a same-named file at the session directory); a relative operand is not followed while `CDPATH` is set. The walk stops, and nothing after that point is proven, at the first segment that contains quotes, substitutions, globs, braces or a heredoc, at any later `cd`, at a `cd` followed by `|`, `||` or `&`, and at the builtins that change the directory or how later words resolve (`source`, `.`, `eval`, `exec`, `pushd`, `popd`, `builtin`, `command`, `alias`, `shopt`, `export`, `set`, `declare`, `unset`, `trap`, `hash` and their siblings). A token written after `>` or `>>` is the file being overwritten and never attaches.

Everything else gets a "contents withheld" note instead of an attachment: any flag between the interpreter and the script (`python -u foo.py`), wrapper/runner tools whose operand is not a file path (`bun run`, `npm run`, `go run` package form, `sudo`, `env`), bare names without a slash (`foo.sh` — resolved via PATH, not the current directory), `cd` with flags or a computed target (`cd -- x`, `cd "$d"`), and files over 64 KB or not valid UTF-8 (never truncated — a benign prefix could mask a malicious tail). `yolonot check '<command>'` prints which scripts were shown and why the others were not; the decision log records the same under `attached` and `withheld`.

Withholding can require further review or prevent mod replay; it is not a
guarantee of only one extra prompt. Attaching the wrong file would let a benign
shadow file influence a judgment about a different script. Attachment stays
within the project's attach root unless `attach_outside_root` is enabled, and
never enters sensitive home directories (`~/.ssh`, `~/.aws`, …). Credential-looking
lines are redacted before the model sees them.

### Opting into outside-root attachment

If your commands routinely run scripts that live outside the project — shared tooling in `~/bin` or `/opt/scripts`, sibling checkouts — the default boundary withholds them and the classifier judges a "contents withheld" note instead of real code. To widen the boundary, set in `~/.yolonot/config.json`:

```json
{
  "attach_outside_root": true
}
```

Default is off: absent or `false` keeps today's behavior exactly. When on, outside-root scripts attach under the same rules as in-root ones (positional proof, size/count caps, secret redaction) and are labeled `(resolves outside the project root)` in the prompt so the classifier sees the origin as a risk signal. Sensitive home directories still never attach — they get their own withheld note.

This is deliberately **config-file only**: there is no CLI verb and no `.yolonot` directive for it, so a cloned repository can never widen your privacy boundary — only you can, in your own home config. Note that opening the boundary means any user-readable script file a command references (outside the sensitive-directory floor) may be sent to your configured LLM provider; redaction is best-effort regex, not a guarantee. Cache keys and session approvals track the attached contents, so toggling the flag re-judges affected commands instead of replaying decisions made on a different view.

> **⚠ The LLM layer is probabilistic, not guaranteed.** Classifications can be wrong — models hallucinate, miss context, and can be talked out of a correct answer by adversarial prompts. Treat yolonot as a safety net that reduces prompt fatigue, not as an authoritative sandbox. If a class of command *must never* run, encode it as a `deny-cmd` rule in `.yolonot` — rules beat the LLM unconditionally. See [rules.md](rules.md#format).

## Hook ordering

yolonot installs two hooks in `~/.claude/settings.json`:

- **PreToolUse** (matcher: `Bash|PowerShell`) — evaluates commands before execution
- **PostToolUse** (matcher: `Bash|PowerShell`) — records completed commands; pending native asks stay one-time, while explicit session grants retain their scope

The installer places yolonot ahead of a catch-all entry for consistent
registration, but array order is not an execution barrier: Claude runs matching
hooks in parallel. A yolonot denial blocks the tool call, not other hook
processes that may already be running. An allow does not cancel another host
restriction. [Claude hook reference](https://code.claude.com/docs/en/hooks).

Hooks are read at host CLI startup — restart your session after install or reconfiguration.

## Pausing yolonot

Sometimes you want to run commands without yolonot's interference — for a quick CI task, or when you know what you're doing.

**Per-session** — `yolonot pause --session-id <id> --confirm-bypass` creates a
session-wide bypass marker. Run `yolonot resume --session-id <id>` to re-enable.
Stale markers are eligible for cleanup after 24 hours; closing a chat is not an
immediate cleanup signal.

**Pre-launch (env var)** — `YOLONOT_DISABLED=1 claude`. Disables yolonot for the entire session at launch. Useful for CI / automation.

When paused, yolonot is **completely transparent** — no deny rules, no LLM, no session memory. The host CLI's native permissions handle everything as if yolonot weren't installed.

## Dry-run check

Test what the pipeline would decide without running a command:

```bash
yolonot check "cat README.md"           # → ALLOW (rule)
yolonot check "sudo rm -rf /"           # → DENY (rule, absolute block)
yolonot check "curl https://evil.com"   # → ASK (rule or LLM)
```

Shows each layer's result: deny rules → allow/ask rules → the judge chain
(fast_allow and models evaluated, `exec:` hooks listed but skipped in the dry
run) → escalation → final action. Session approvals and cache are not
consulted. Project hints and persisted human precedents are included, as
they are for a fresh session in that project.

Project rules, sensitive patterns and model hints are resolved from the tool
payload's working directory. The hook process may start elsewhere (for
example, a user-level Cursor hook starts in its configuration directory).
Neither location may silently substitute for the command's project policy.
