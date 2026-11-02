package yolonot

import "path/filepath"

func init() { RegisterHarness(newMuseHarness()) }

type MuseHarness struct{ baseHarness }

func museConfigDir() string {
	return xdgOrHomeConfigDir([]string{"MUSE_CONFIG_DIR"}, "muse", filepath.Join(".config", "muse"))
}

func newMuseHarness() *MuseHarness {
	h := &MuseHarness{
		baseHarness: baseHarness{
			name:                 "muse",
			supportsAsk:          true,
			ambiguousPostToolUse: true,
			usesPermRequestPhase: true,
			sessionEnvKeys:       []string{"YOLONOT_MUSE_SESSION_ID", "MUSE_SESSION_ID"},
			configDirFn:          museConfigDir,
			settingsPathFn:       func() string { return filepath.Join(museConfigDir(), "settings.json") },
			riskMap:              claudeCompatRiskMap(),
			formatFn: func(r HookResponse) string {
				if r.HookSpecificOutput.PermissionDecision == ActionDeny && r.HookSpecificOutput.PermissionDecisionReason == "" {
					r.HookSpecificOutput.PermissionDecisionReason = "Blocked by yolonot"
				}
				return formatPermissionRequestOrClaude(r, false)
			},
			notes: []string{
				"Muse Code reads user hooks from ~/.config/muse/settings.json (with schema_version: 1) and prompts once in interactive TUI to trust new hooks.",
				"PreToolUse handles ask/deny (emitting empty stdout on allow), while PermissionRequest handles auto-approve.",
			},
		},
	}
	// Matcher "Bash" aliases ["Bash", "bash", "shell", "exec_command", "execute_command"]
	// while avoiding Muse's internal "submit_reminder_decision" background subagent tool.
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName:  "muse",
		events:       []string{"PreToolUse", "PermissionRequest", "PostToolUse"},
		matcher:      "Bash",
		rootDefaults: map[string]interface{}{"schema_version": 1},
	})
	return h
}
