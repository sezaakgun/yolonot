package main

import _ "embed"

//go:embed skills/SKILL.md
var embeddedSkillMD []byte

//go:embed harness_opencode_plugin.ts
var embeddedOpencodePluginTS []byte
