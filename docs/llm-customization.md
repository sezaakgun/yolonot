# Classifier customization

yolonot ships with a one-size-fits-most safety classifier prompt. It works
out of the box, but it doesn't know about *your* infrastructure — the
GitHub orgs you push to, the buckets you write to, the staging namespaces
you treat as disposable. When the classifier lacks that context, it tends
to ask on routine internal commands ("is `kubectl get pods -n prod-eu-1`
really safe?") and to miss environment-specific risks the defaults can't
predict.

The `classifier` config block lets you inject prose hints into the
classifier's system prompt so it sees the world the way your team does. It
mirrors Claude Code's [auto mode](https://code.claude.com/docs/en/auto-mode-config)
config shape so the mental model is portable; differences from Claude are
called out below.

## When to use it

Reach for a hint when:

- A safe-but-unfamiliar command pattern keeps getting flagged (false ask).
- A risky pattern only your team has would slip past the defaults.
- You want the LLM to treat one of your domains, repos, or namespaces as
  trusted (not "external").

Don't use hints for:

- **Hard blocks.** Use a `.yolonot` `deny-cmd` rule instead. Hints are
  read by an LLM and can be overridden by user intent in the conversation;
  rules can't.
- **Static command lists.** Use `.yolonot` `allow-cmd` / `ask-cmd` —
  pattern matching is faster, free, and deterministic.
- **Per-harness behavior.** Use [risk profiles](risk-profiles.md) and
  per-cell overrides — those translate the LLM's tier into an action and
  can differ per host.

## The three fields

| Field | Tells the classifier |
|---|---|
| `context` | What's trusted in your environment — repos, buckets, domains, services. The classifier uses this to decide what counts as "external". |
| `allow_hints` | Routine patterns the defaults flag too aggressively. Lean toward `allow` when these clearly apply. |
| `ask_hints` | Environment-specific risks the defaults miss. Lean toward `ask` regardless of how routine the command looks. |

There is no `deny_hints` field by design. yolonot's LLM never emits
`deny` directly (deny is rule-origin only), so a `deny_hints` field would
be misleading. For hard blocks, write a `deny-cmd` rule.

## Where to put it

Two surfaces, layered:

| Surface | Scope | Use for |
|---|---|---|
| `~/.yolonot/config.json` `classifier.*` | Personal / global | Hints that apply to everything you do. Survives across projects. |
| `.yolonot` walk-up files (`context "..."`, `allow-hint "..."`, `ask-hint "..."`) | Per-project / per-team | Hints that ride with the repo. Closer-to-cwd files are listed first. |

Both surfaces stack — the LLM sees the union, with config entries first,
then walk-up entries closest-to-cwd-first. Hints aren't first-match; the
model reads them all.

### Personal config (`~/.yolonot/config.json`)

```json
{
  "classifier": {
    "impl": "llm",
    "context": [
      "$defaults",
      "Source control: github.com/yourorg/* and all repos under it",
      "Trusted buckets: s3://yourorg-builds, s3://yourorg-scratch",
      "Trusted internal domains: *.example.com, *.corp.example.com",
      "Key internal services: Jenkins at ci.example.com, Artifactory at artifacts.example.com"
    ],
    "allow_hints": [
      "$defaults",
      "kubectl get/describe/logs against prod-* namespaces is read-only and routine",
      "Writing to s3://yourorg-scratch/ is allowed: ephemeral bucket with a 7-day lifecycle"
    ],
    "ask_hints": [
      "$defaults",
      "Never run schema migrations against the billing database",
      "Modifying files under infra/terraform/prod/ goes through the review workflow"
    ]
  }
}
```

The `"impl": "llm"` field is the existing classifier-backend selector and
is optional. yolonot ships only the `llm` backend today.

### Per-project (`.yolonot` walk-up)

The same file you put `allow-cmd` / `deny-cmd` rules in also accepts
hints. yolonot collects every `.yolonot` from cwd up to the enclosing
git repo root (same trust boundary as rules):

```
# ./yourproject/.yolonot
context     "this repo deploys to ECS cluster yourorg-services in eu-west-1"
allow-hint  "Writing to ./build/ and ./dist/ is part of every test run"
ask-hint    "Never modify files under infra/k8s/prod/ without confirmation"
```

Hints stack with rules in the same file — there's no need for separate
files.

## The `$defaults` sentinel

Each list accepts the literal string `"$defaults"`, which is replaced
with yolonot's built-in entries at the position you wrote it:

```json
"context": ["my entry before", "$defaults", "my entry after"]
```

yolonot ships a small set of generic defaults — trust framing, scoping
hints for IAM and cloud-storage verbs, the pre-existing-vs-generated
distinction for destructive ops, and a few other patterns the base
prompt doesn't already cover. They are deliberately org-agnostic: no
domains, repo orgs, or path prefixes. Print them with:

```bash
yolonot classifier defaults
```

> **Footgun:** omitting `"$defaults"` from a list takes full ownership
> of that list — the built-ins are dropped, and you also stop inheriting
> any new defaults yolonot ships in future releases. Keep `"$defaults"`
> unless you have a deliberate reason to fully replace the built-in
> behavior. Same contract as Claude Code's `autoMode`.

## Inspecting your configuration

Three subcommands, all read-only:

```bash
yolonot classifier defaults    # Built-in system prompt + (empty) default hint lists, as JSON
yolonot classifier config      # Effective merged config — config + walk-up, $defaults expanded
yolonot classifier review      # Ask the active LLM provider to flag ambiguous or redundant hints
yolonot classifier             # Shorthand for `config`
```

`yolonot classifier config` prints the actual `system_prompt` that will
be sent on the next LLM call — the most useful single field for debugging
why a command got an unexpected decision. Pipe through `jq` to extract
just one part:

```bash
yolonot classifier config | jq -r .system_prompt
yolonot classifier config | jq .context
```

`yolonot classifier review` calls your configured LLM provider with a
meta-prompt that audits each hint for ambiguity, redundancy, over-broad
matching, and over-permissive language. Run it after editing your
hints — a 30-second sanity check before the new entries start steering
real decisions.

## Precedence inside the prompt

Within the assembled system prompt the layering is:

```
[base SystemPrompt — yolonot's shipped safety rules]
  ↓
Project context:    (from cfg.context + walkup.context)
  ↓
Project allow hints: (from cfg.allow_hints + walkup.allow_hints)
  ↓
Project ask hints:   (from cfg.ask_hints + walkup.ask_hints)
  ↓
[explicit user-intent override clause]
  ↓
[user message: "Command: ..."]
```

Within each section, **config entries appear before walk-up entries**, and
within walk-up the closest-to-cwd file is listed first. The model is
told that `ask_hints` win over `allow_hints` *unless* the user has
explicitly and specifically asked for the action — same precedence as
Claude's autoMode.

## Backward compatibility

This feature is purely additive:

- **Legacy config:** `"classifier": "llm"` (string form, every prior
  release) still loads. It maps to `Impl: "llm"` with empty hint slices,
  so default behavior is unchanged.
- **Round-trip:** a legacy string config that you load and save is
  re-serialized as a string — yolonot does **not** silently rewrite it
  into the new object form. The shape only changes when you opt in by
  adding hints.
- **Default prompt:** if you set no hints anywhere, the system prompt
  sent to the model is **byte-equal** to the previous release's
  `SystemPrompt` const. No change to existing classification behavior.
- **Existing CLI/env vars:** `yolonot risk`, `profile`, `pre-check`,
  `check`, `rules`, `setup`, `provider`, `log`, `stats`, every
  `YOLONOT_*` env var — unchanged. `classifier` is a new sibling
  subcommand.
- **Existing `.yolonot` directives:** `allow-cmd`, `deny-cmd`,
  `ask-cmd`, `allow-redirect`, `sensitive`, `not-sensitive` — unchanged.
  The new directives (`context`, `allow-hint`, `ask-hint`) are additive.

If you upgrade and don't touch any config, nothing changes.

## Security notes

- **Hint injection from cloned repos.** A `.yolonot` file in an untrusted
  repository can ship `allow-hint` text that nudges the classifier in a
  bad direction. yolonot's walk-up trust boundary is the enclosing git
  repo root (same as for rules), so the exposure is no worse than it
  already was for `allow-cmd` rules — but unlike Claude Code (which
  ignores shared `.claude/settings.json` precisely for this reason),
  yolonot does load `.yolonot` from the repo. Review `.yolonot` files in
  unfamiliar clones before you run anything in them.
- **Hard blocks beat hints.** A `deny-cmd` rule fires before the LLM is
  consulted at all, so it cannot be talked out of by a hint or by the
  user's message. Use `deny-cmd` for anything you truly never want run.

## Limitations and out-of-scope (today)

- No managed/enterprise scope — yolonot has no concept of managed
  settings, so you can't distribute a hint set across an org from a
  central file. Workaround: ship a per-repo `.yolonot` in your
  scaffolding.
- No mutator subcommands — `yolonot classifier defaults | config |
  review` are read-only. Edit `~/.yolonot/config.json` and `.yolonot`
  files by hand to author hints.
- Hints are global to the LLM call — there's no per-harness hint set.
  yolonot's LLM call is shared across harnesses anyway, so this is by
  design.
