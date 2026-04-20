# Pre-check hooks

The pre-check list is yolonot's fast-path layer — an ordered sequence of deterministic checkers that run **after** deny rules but **before** session memory, allow/ask rules, cache, and LLM. The first entry that returns `allow` short-circuits the pipeline.

Two kinds of entries share the list:

- **`fast-allow`** — reserved sentinel. Dispatches to yolonot's built-in Go bash parser (see below). No fork/exec. Added by default during `yolonot setup`.
- **Any other entry** — treated as an external hook binary (e.g. [Dippy](https://github.com/ldayton/Dippy)). Receives the standard Claude Code PreToolUse JSON on stdin, must return a standard hook response on stdout.

## Managing the list

```bash
yolonot pre-check                                # list configured entries in order
yolonot pre-check add fast-allow                 # built-in Go bash parser (default at setup)
yolonot pre-check add /opt/homebrew/bin/dippy    # external hook binary
yolonot pre-check remove 1                       # remove by 1-based index
yolonot pre-check remove fast-allow              # remove by exact entry
yolonot pre-check clear                          # disable all
```

**Order matters.** Put cheap/narrow checkers first. The typical layout is `fast-allow` first (strict, no subprocess), then Dippy (broader bash coverage, Python subprocess) — that way obvious cases never touch Dippy.

## Contract

The first entry to return `permissionDecision: "allow"` wins. Anything else — `ask`, `deny`, empty, `{}`, nonzero exit, or a 3s timeout for external hooks — falls through to the next entry and ultimately to yolonot's rules + LLM. yolonot deny rules always beat a pre-check allow (Step 0 runs first).

## Observability

- `yolonot check "<cmd>"` walks the list; `fast-allow` is evaluated inline (pure, no side effects). External hooks are listed but not invoked.
- Decisions show up as `fast_allow` or `pre_check` in `yolonot log` and `yolonot stats`.

## Caveats

- Only `allow` short-circuits. If a pre-check denies, the rest of the pipeline still runs and may allow — by design, so a conservative external tool can't accidentally block commands yolonot knows are fine. Use `deny-cmd` rules for hard blocks.
- If a pre-check allows something you wanted yolonot to scrutinize, tighten that checker's own config — yolonot never sees the command once it's allowed.
- Legacy configs with `"pre_check": "/path/to/hook"` (single string) keep working; they are parsed as a one-element list. Legacy `"local_allow": true` is auto-migrated to `fast-allow` at the head of the list on next load.

## Security

External pre-check binaries execute with *your* user privileges on every Bash tool invocation. Only add binaries you trust — a malicious or compromised pre-check hook can auto-approve anything by returning `permissionDecision: "allow"`, bypassing yolonot's LLM + rules entirely (deny rules still run first).

yolonot sanitizes untrusted passthrough fields (strips ANSI / C0 controls, caps 512 chars) before embedding them in banners, but that only blocks terminal spoofing — it does not prevent a rogue hook from approving commands. `fast-allow` runs in-process, so it has no such exposure.

## `fast-allow` — the built-in bash parser

`fast-allow` uses [mvdan/sh](https://github.com/mvdan/sh) to parse each command and only short-circuits when the AST proves safety:

- Single simple command, or a pipeline of only allowlisted commands.
- Head command (`ls`, `cat`, `git status`, `docker ps`, `kubectl get`, …) is in the built-in allowlist.
- For multiplex tools (`git`, `go`, `docker`, `kubectl`, `npm`, `brew`, …) the subcommand must be a known read-only one — `git push`, `docker run`, `npm install` all fall through.
- No command substitution (`$(...)`, backticks), no process substitution (`<(...)`, `>(...)`), no arithmetic expansion.
- No redirect except to `/dev/null` or targets covered by [`allow-redirect`](rules.md#allow-redirect--pre-approved-write-targets) rules — `cat foo > /tmp/out` falls through unless declared.
- No chaining (`&&`, `||`, `;`), no subshells, no brace blocks, no background, no negation.
- No prefix assignment (`FOO=bar ls`), no unknown parameter expansion operators (`${x:=bad}`, `${!x}`).

Anything even slightly ambiguous returns to the normal pipeline — session memory, rules, cache, and finally the LLM. **The LLM is still the safety net**; `fast-allow` just skips it for commands where no human would want to review.

### Dippy comparison

If you want broader fast-path coverage, layer [Dippy](https://github.com/ldayton/Dippy) after `fast-allow`. Dippy's [Parable](https://github.com/ldayton/Parable) parser is more thorough on exotic bash but adds a Python subprocess per hook invocation. `fast-allow` is deliberately conservative — it falls through to the LLM whenever in doubt, so false positives go to a smarter layer rather than being rubber-stamped.

```bash
brew tap ldayton/dippy && brew install dippy
yolonot pre-check add /opt/homebrew/bin/dippy
```

Allowlist ported with attribution from Dippy (MIT).
