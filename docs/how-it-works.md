# How it works

Every Bash command goes through this pipeline in order. The first layer that produces a decision wins.

1. **Deny rules** — absolute block, no override, checked first.
2. **Session memory** — exact match against previously approved commands → instant allow. Content-aware for script commands: the approval is pinned to the script contents that were approved, so editing the script re-judges instead of replaying the allow.
3. **Session deny** — previously rejected commands → instant block.
4. **Allow / ask rules** — `.yolonot` patterns → instant decision. See [rules.md](rules.md).
5. **Judges** — the ordered chain in `config.json`: `fast_allow` (built-in bash parser), `exec:<path>` hooks like [Dippy](https://github.com/ldayton/Dippy), then [models](models.md) by name: a typed decision model (TypeSafe Jev, Microsoft-Decision-1, OpenAI Decisions) and/or a chat model. The first judge whose verdict is permitted (`may`) wins. See [judges.md](judges.md).
   - Right before the first model judge, two memory layers run once: **session similarity** (the chat model compares against approved commands → allow if similar, project-aware, prefix-prefiltered) and the **script cache** (SHA256 of the command plus the full contents of every attached script → reuse the cached verdict; editing an attached script invalidates it).
   - Models emit a [risk tier](risk-tiers.md) with the verdict. Referenced scripts are attached to the prompt when it is provable which file will run (see below).
6. **Escalation (optional)** — when a model verdict is uncertain in a way that would surface an ask, a configured bigger chat model gets one look before the interruption. A confident `allow` + `safe`/`low` from it rescues the ask into an allow; a more dangerous tier hardens the verdict upward; anything else (including errors) leaves the verdict standing. Never fires on confident allows, `critical` verdicts, rule-layer denies, or the oversize abstain. See [models.md](models.md#escalation-second-opinion-model). Harnesses whose hooks yolonot cannot gate at all get no benefit from escalation — it improves verdicts, it cannot create enforcement where a harness offers none.
7. **Unresolved policy** — a residual ask after escalation stays an ask, or becomes a deny with `"unresolved": "deny"` for unattended runs.
8. **Risk map** — the active [profile](risk-profiles.md) turns the tier into the final action for the active harness.

Sessions are project-aware. A command approved in one project is not auto-approved in another within the same session — session keys include a hash of the git root (or working directory).

`deny` rules are absolute — nothing overrides them. `ask` rules prompt once, then session memory takes over. `allow` rules are instant but are skipped for chained commands, redirects, and commands touching sensitive files (see [rules.md](rules.md)).

When no judge can decide (model unreachable, unparseable reply, empty chain), yolonot emits a warning (`LLM unreachable, falling back to host permissions`) and goes transparent — the host's native permission system handles it. yolonot never silently allows on a model failure.

## Script attachment

When a command references a script file, yolonot reads it and embeds the contents in the classifier prompt so the model judges actual code instead of guessing from a filename. Contents are attached only when it is **provable which file bash will execute**:

- the script is a leading path in a plain command — `./run.sh`, `scripts/x.sh --flag`
- or it directly follows a known interpreter with nothing in between — `python foo.py`, `bash scripts/x.sh`, `node server.js`, `uv run python test.py`
- absolute paths inside the project always attach, in any command shape

Everything else gets a "contents withheld" note instead of an attachment: compound commands (`cd x && python foo.py`), any flag between the interpreter and the script (`python -u foo.py`), wrapper/runner tools whose operand is not a file path (`bun run`, `npm run`, `go run` package form, `sudo`, `env`), bare names without a slash (`foo.sh` — resolved via PATH, not the current directory), and files over 64 KB or not valid UTF-8 (never truncated — a benign prefix could mask a malicious tail).

The asymmetry is deliberate: withholding costs at most one extra ask prompt, while attaching the *wrong* file would let a benign shadow file get a malicious script auto-allowed. Attachment never crosses the project's attach root (the git repo root of the session cwd, else the cwd itself) unless you opt in with `attach_outside_root` (below), and never enters sensitive home directories (`~/.ssh`, `~/.aws`, …) — that floor holds even when the boundary is opened. Credential-looking lines are redacted before the model sees them either way.

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

- **PreToolUse** (matcher: `Bash`) — evaluates commands before execution
- **PostToolUse** (matcher: `Bash`) — saves approved commands to session memory

`yolonot setup` places the PreToolUse hook **before** any catch-all (`.*`) hooks so yolonot evaluates and can block a command before other hooks (audit loggers, etc.) see it. If you reorder hooks manually, keep yolonot's PreToolUse entry above other Bash hooks. PostToolUse order doesn't matter.

When yolonot returns `deny`, the command is blocked and no subsequent hooks run. When it returns `allow`, the command proceeds through remaining hooks normally.

Hooks are read at host CLI startup — restart your session after install or reconfiguration.

## Pausing yolonot

Sometimes you want to run commands without yolonot's interference — for a quick CI task, or when you know what you're doing.

**Per-session (interactive)** — `yolonot pause` or `/yolonot pause`. Creates a pause marker for the current session. Run `yolonot resume` to re-enable. Marker auto-cleans after 24h.

**Pre-launch (env var)** — `YOLONOT_DISABLED=1 claude`. Disables yolonot for the entire session at launch. Useful for CI / automation.

When paused, yolonot is **completely transparent** — no deny rules, no LLM, no session memory. The host CLI's native permissions handle everything as if yolonot weren't installed.

## Dry-run check

Test what the pipeline would decide without running a command:

```bash
yolonot check "cat README.md"           # → ALLOW (rule)
yolonot check "sudo rm -rf /"           # → DENY (rule, absolute block)
yolonot check "curl https://evil.com"   # → ASK (rule or LLM)
```

Shows each layer's result: deny rules → session memory → allow/ask rules → the judge chain (fast_allow and models evaluated, exec: hooks listed) → escalation → final action.
