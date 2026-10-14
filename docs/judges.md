# Judges

A judge looks at a command and returns a verdict. The chain is an ordered
list in `~/.yolonot/config.json`; the first judge whose verdict is permitted
wins. Rules and session memory run before the chain, escalation and the risk
map run once after it. See [how-it-works.md](how-it-works.md).

```json
"judges": ["fast_allow", "exec:/opt/homebrew/bin/dippy", "jev", "gemini"]
```

| Entry | What it is | May decide by default |
|-------|------------|-----------------------|
| `fast_allow` | Built-in bash parser (below). In-process, no network. | allow |
| `exec:<path>` | Any binary fed the Claude PreToolUse JSON on stdin: [Dippy](https://github.com/ldayton/Dippy), an ML gate, your own script. 3s timeout; counts only when it prints `permissionDecision: "allow"`. The path may carry arguments (`exec:/usr/local/bin/gate --strict`). | allow |
| a model name | A [catalog model](models.md): typed (TypeSafe Jev, Microsoft-Decision-1, OpenAI Decisions, Cloudflare Clef) or chat. | allow, ask |

Unknown catalog references and malformed judge entries are configuration
errors; `config validate` and CLI writers reject them. Malformed global
configuration follows the invalid-config failure policy rather than silently
skipping a misspelled safety stage.

An entry can be an object to narrow what the judge may decide:

```json
"judges": ["fast_allow", {"use": "jev", "may": ["allow"]}, "gemini"]
```

A verdict outside `may` is dropped and the next judge runs. `"may": ["allow"]`
on a typed model lets it clear the obvious cases and hand everything else to
the chat model.

## Managing the chain

```bash
yolonot judges                          # list in order, with kind and may
yolonot judges list                     # explicit list alias
yolonot judges add fast_allow           # append
yolonot judges add exec:/opt/homebrew/bin/dippy
yolonot judges add gemini               # a model from `yolonot models`
yolonot judges move 3 up                # by 1-based index or exact entry
yolonot judges remove exec:/opt/homebrew/bin/dippy
yolonot config                          # the same, interactively
```

`judges add` appends and refuses duplicates; `remove` keeps at least one
judge. In `yolonot config` the JUDGES section has one row per judge (move,
remove, change what it may decide), "Add judge" and "Reset chain" presets
built from the catalog (chat only, typed only, typed first, or edit the
list as JSON in `$EDITOR`). Exec hooks also appear under MODELS, like the
models they sit next to: Test runs the binary on a sample `ls -la` payload,
Replace path edits it, Remove drops it from the chain; "Add model" offers
"Exec hook" as a third kind. The chain is the only place an exec hook lives,
so adding it there appends it to JUDGES.

Settings changes, including rule-file edits, remain drafts until Save.
Discard leaves the active configuration and rules unchanged. On small
terminals the list scrolls while the header and save controls stay visible.

**Order matters.** Put cheap and narrow judges first: `fast_allow`, then an
external hook, then the typed model, then the chat model. Obvious cases never
reach a network call. With an empty chain every command passes through to the
host's own permission prompt; `yolonot` says so on its status line.

Similarity, the whole chain and escalation share one hook deadline (55 seconds by default; configurable with `hook_timeout`).
Provider timeouts and the 3-second exec limit can shorten individual stages;
falling through to another judge does not restart the deadline. Exhaustion
before an adopted verdict asks on adapters with native ask or denies otherwise, without caching an approval. An escalation timeout keeps the
primary verdict. See [configurable failure behavior](configuration.md).

## Observability

- `yolonot check "<cmd>"` walks the chain. `fast_allow` and models are
  evaluated for real; `exec:` judges are listed but not invoked.
- The deciding judge is the `layer` in `yolonot log`, `yolonot stats` and the
  banner: `fast_allow`, `exec:dippy` (the binary's base name), or the model
  name (`jev`, `gemini`, `gemini+esc` when escalation refined it).
- Right before the first model judge the hook consults session similarity
  and the script cache once (layers `session_llm`, `cache`); `fast_allow`
  and exec hooks run before that and cost nothing.

## Caveats

- `fast_allow` and `exec:` judges only short-circuit on `allow`. A hook that
  says `deny` falls through and a later judge may allow; use `deny-cmd` rules
  for hard blocks.
- If a judge allows something you wanted scrutinised, tighten that judge
  (its `may`, or the hook's own config). Later judges never see the command.

## Security

External binaries execute with *your* user privileges on every Bash tool
invocation. Only add binaries you trust — a malicious or compromised hook can
auto-approve anything by returning `permissionDecision: "allow"` (deny rules
still run first). yolonot sanitises untrusted passthrough fields (strips ANSI
and C0 controls, caps 512 chars) before embedding them in banners, which
blocks terminal spoofing but not a rogue allow. `fast_allow` runs in-process
and has no such exposure.

## `fast_allow` — the built-in bash parser

`fast_allow` uses [mvdan/sh](https://github.com/mvdan/sh) to parse each
command and only short-circuits when the AST proves safety:

- Single simple command, or a pipeline of only allowlisted commands.
- Head command (`ls`, `cat`, `git status`, `docker ps`, `kubectl get`, …) is in the built-in allowlist.
- For multiplex tools (`git`, `go`, `docker`, `kubectl`, `npm`, `brew`, …) the subcommand must be a known read-only one — `git push`, `docker run`, `npm install` all fall through.
- No command substitution (`$(...)`, backticks), no process substitution (`<(...)`, `>(...)`), no arithmetic expansion.
- No redirect except to `/dev/null` or targets covered by [`allow-redirect`](rules.md#allow-redirect--pre-approved-write-targets) rules — `cat foo > /tmp/out` falls through unless declared.
- No chaining (`&&`, `||`, `;`), no subshells, no brace blocks, no background, no negation.
- No prefix assignment (`FOO=bar ls`), no unknown parameter expansion operators (`${x:=bad}`, `${!x}`).

Anything even slightly ambiguous goes on to the next judge. The models are
still the safety net; `fast_allow` just skips them for commands no human would
want to review.

### Dippy comparison

For broader fast-path coverage, add [Dippy](https://github.com/ldayton/Dippy)
after `fast_allow`. Dippy's [Parable](https://github.com/ldayton/Parable)
parser is more thorough on exotic bash but adds a Python subprocess per hook
invocation. `fast_allow` is deliberately conservative — it falls through
whenever in doubt, so false positives go to a smarter judge rather than being
rubber-stamped.

```bash
brew tap ldayton/dippy && brew install dippy
yolonot judges add exec:/opt/homebrew/bin/dippy
```

Allowlist ported with attribution from Dippy (MIT).
