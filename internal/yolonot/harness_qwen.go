package yolonot

import "path/filepath"

func init() { RegisterHarness(newQwenHarness()) }

type QwenHarness struct{ baseHarness }

func qwenConfigDir() string {
	return xdgOrHomeConfigDir([]string{"QWEN_HOME", "QWEN_CONFIG_DIR"}, "", ".qwen")
}

func newQwenHarness() *QwenHarness {
	h := &QwenHarness{
		baseHarness: baseHarness{
			name:                 "qwen",
			supportsAsk:          true,
			usesPermRequestPhase: true,
			sessionEnvKeys:       []string{"YOLONOT_QWEN_SESSION_ID", "QWEN_CODE_SESSION_ID", "QWEN_SESSION_ID"},
			configDirFn:          qwenConfigDir,
			settingsPathFn:       func() string { return filepath.Join(qwenConfigDir(), "settings.json") },
			riskMap:              claudeCompatRiskMap(),
			formatFn:             func(r HookResponse) string { return formatPermissionRequestOrClaude(r, true) },
			notes: []string{
				"Qwen Code uses PreToolUse for ask/deny and PermissionRequest for auto-approving allowed shell commands.",
				"In headless non-interactive runs and background subagents, 'ask' decisions fail closed as denials.",
			},
		},
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName: "qwen",
		events:      []string{"PreToolUse", "PermissionRequest", "PostToolUse"},
		matcher:     "run_shell_command|monitor",
	})
	return h
}
