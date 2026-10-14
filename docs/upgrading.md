# Upgrading from 0.x

yolonot 1.0 changes the shape of `~/.yolonot/config.json` and a few CLI
verbs. A 0.x file is folded into the new shape in memory without being
rewritten. Explicit timeout and policy values are preserved. The disk
rewrite is yours to trigger. Env-only model configuration is removed;
move those endpoints into the catalog before upgrading.

## What changed

| 0.x | 1.x |
|-----|-----|
| `provider`, `decision`, `escalation.provider` | one `models` catalog; `judges` and `escalation.model` refer to entries by name |
| `pre_check`, `local_allow` | `judges` entries `fast_allow` and `exec:<path>` |
| `classifier.{context,allow_hints,ask_hints,system_prompt}` | `prompt.*` (`impl` dropped) |
| `profile`, `custom_profiles` | `policy.profile`, `policy.profiles` |
| `profile_override`, `risk_maps` | `policy.harness.<name>.{profile,risk_map}` |
| `judges` keywords `llm`, `decision` / `jev`, `escalation` | the chat model's name, the typed model's name; `escalation` entries are dropped (escalation runs once after the chain) |
| `yolonot provider`, `yolonot decision` | `yolonot models add [typed]` |
| `yolonot pre-check …` | `yolonot judges add|remove|move` |
| `yolonot classifier …` | `yolonot prompt …` |
| `LLM_MODEL`, `LLM_URL`, `LLM_TIMEOUT`, `LLM_ESCALATION_*`, `DECISION_*`, `YOLONOT_CLASSIFIER` | removed; endpoints are config only |
| log layer `llm`, `pre_check (name)` | the model name, `exec:<name>` |

`YOLONOT_DISABLED`, `YOLONOT_HARNESS`, `YOLONOT_PROFILE`,
`YOLONOT_<HARNESS>_PROFILE`, `YOLONOT_<HARNESS>_RISK_<TIER>`,
`YOLONOT_ESCALATION` and `YOLONOT_ESCALATION_UNRESOLVED` are unchanged. So
are `.yolonot` rule files and every directive in them.

## Migrating

```bash
yolonot migrate --dry-run   # print the 1.x file without writing
yolonot migrate             # write it; the 0.x file is kept at config.json.bak
yolonot migrate --undo      # put the .bak back
```

Model names are derived from the model id: the last path segment,
lowercased, with an OpenRouter `:variant` tag dropped (`google/gemini-2.5-flash-lite`
becomes `gemini-2.5-flash-lite`, `foo/bar:free` becomes `bar`; Ollama tags
like `gemma4:e4b` stay). Two entries that derive the same name get a `-2`
suffix. A 0.x escalation that named only a model inherits the primary
model's endpoint and key, as it did at runtime. Rename entries afterwards
in `yolonot config` if you prefer shorter banners.

`yolonot` and `yolonot config` offer the migration once on a 0.x file and
remember a decline (`~/.yolonot/migrate-declined`); `yolonot setup` asks
and stops if you say no. Commands that write the file (`models`, `judges`,
`profile use|reset|create|delete`, `risk`, `escalation`, `quiet`, saving in
`yolonot config`) ask first and do nothing if you say no; without a
terminal they print "Run `yolonot migrate` first" and exit 2. The hook
never asks and never writes. Reading commands (`yolonot judges`,
`yolonot models`, `yolonot check`) show the folded 1.x view of a 0.x file.

The 0.x reader stays through every 1.x release and goes away in 2.0.

## Validate and reinstall after updating

Run `yolonot config validate` before restarting a host. Unknown or duplicate
fields, invalid model references and invalid actions now produce actionable
errors instead of silently using defaults. A malformed configuration defaults
to deny. Supported legacy shapes still normalize in memory.

Reinstall each target (`yolonot install --harness <name>`) to update hook
registration and native skills. OpenCode V2 needs the new default plugin
export and native permission integration; Codex needs trusted hooks and the
PermissionRequest registration. See [harnesses.md](harnesses.md).

Old script-cache entries lack the new context fingerprint and are rejudged.
Canonical project paths can also require a fresh session approval for commands
previously approved through a symlink alias. Existing decision logs remain.
Learning defaults to enabled for compatibility; use `yolonot learning off`
to opt out, and retention/limit/prune/clear controls to manage stored precedents.
New failure policies, deadline, explicit model protocols and diagnostics are
listed in [configuration.md](configuration.md).

Pending asks no longer become inferred session rejections. Explicit mod/CLI
Deny still persists; older inferred denial and learning records are not
silently rewritten. If a known false rejection remains in a test session,
use the scoped CLI reset and learning controls deliberately, or test with a
fresh command/session. Reset preserves logs and learned history.

Native executables now require a current snapshot for session approval; an
older string-only approval can require one fresh decision. Recheck model keys
in each host process after upgrading, especially [Claude Desktop](harnesses.md#claude-desktop-model-credentials).

## Retired Gemini CLI integration

New yolonot installations support Antigravity for Google CLI workflows.
Gemini CLI is excluded from default/`--all` installations and explicit install
is rejected. Remove old hooks/skills with `yolonot uninstall --harness gemini`,
then install `--harness antigravity`. Old config remains readable for cleanup;
Google's upstream API/enterprise availability is separate from this decision.

## Native approval scope

Native PostToolUse cannot distinguish Allow once from a session grant.
Successful pending native asks now stay one-time and are excluded from
learning. To remember a human grant, use `yolonot approve` or the Claude mod's
session option. Existing stored approvals are retained; `yolonot reset`
clears the selected project's session decisions if desired.

Hook policy and hint lookup now follows payload cwd rather than the hook
process directory, including user-level Cursor registrations.

## Codex hook flag deprecation

`features.codex_hooks` is deprecated. Installation migrates it to
`features.hooks = true`, including quoted, dotted and inline-table forms.
If both names exist, the old assignment becomes an inert comment (or is
removed from its inline table). Unrelated TOML and comments are preserved.
The hook trust step is separate; renaming this equivalent feature flag does
not trust new hooks or remove existing trust records.
