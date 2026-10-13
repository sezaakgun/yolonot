# Upgrading from 0.x

yolonot 1.0 changes the shape of `~/.yolonot/config.json` and a few CLI
verbs. Nothing breaks on upgrade: a 0.x file is read as is, and the hook
keeps deciding exactly as before. The rewrite is yours to trigger.

## What changed

| 0.x | 1.x |
|-----|-----|
| `provider`, `decision`, `escalation.provider` | one `models` catalog; `judges` and `escalation.model` refer to entries by name |
| `pre_check`, `local_allow` | `judges` entries `fast_allow` and `exec:<path>` |
| `classifier.{context,allow_hints,ask_hints,system_prompt}` | `prompt.*` (`impl` dropped) |
| `profile`, `custom_profiles` | `policy.profile`, `policy.profiles` |
| `profile_override`, `risk_maps` | `policy.harness.<name>.{profile,risk_map}` |
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

Model names are derived from the model id (`google/gemini-2.5-flash-lite`
becomes `gemini-2.5-flash-lite`); rename them afterwards in `yolonot config`
if you prefer shorter banners.

Interactive commands (`yolonot`, `yolonot config`, `yolonot setup`) offer the
migration once on a 0.x file and remember a decline. Commands that write the
file (`models`, `judges`, `profile use|reset|create|delete`, `risk`,
`escalation`, `quiet`, saving in `yolonot config`) ask first and do nothing
if you say no; without a terminal they exit 2 instead of asking. The hook
never asks and never writes.

The 0.x reader stays through every 1.x release and goes away in 2.0.
