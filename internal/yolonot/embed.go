package yolonot

import "embed"

//go:embed skills/SKILL.md
var embeddedSkillMD []byte

//go:embed harness_opencode_plugin.ts
var embeddedOpencodePluginTS []byte

//go:embed mod/plugin.json mod/hooks.json mod/register.tsx
var embeddedMod embed.FS
