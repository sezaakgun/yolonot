package yolonot

import (
	"encoding/json"
	"path/filepath"
)

func init() { RegisterHarness(newKimiHarness()) }

type KimiHarness struct{ baseHarness }

func kimiConfigDir() string {
	return xdgOrHomeConfigDir([]string{"KIMI_CODE_HOME"}, "", ".kimi-code")
}

func newKimiHarness() *KimiHarness {
	h := &KimiHarness{
		baseHarness: baseHarness{
			name:           "kimi",
			sessionEnvKeys: []string{"YOLONOT_KIMI_SESSION_ID", "KIMI_CODE_SESSION_ID", "KIMI_SESSION_ID"},
			configDirFn:    kimiConfigDir,
			settingsPathFn: func() string { return filepath.Join(kimiConfigDir(), "config.toml") },
			riskMap:        denyOnlyRiskMap(),
			formatFn: func(r HookResponse) string {
				if r.HookSpecificOutput.PermissionDecision != ActionDeny {
					return ""
				}
				reason := r.HookSpecificOutput.PermissionDecisionReason
				if reason == "" {
					reason = "Blocked by yolonot"
				}
				data, _ := json.Marshal(map[string]interface{}{
					"hookSpecificOutput": map[string]string{
						"permissionDecision":       ActionDeny,
						"permissionDecisionReason": reason,
					},
				})
				return string(data)
			},
			notes: []string{
				"Kimi Code PreToolUse supports deny; allow and ask decisions defer to Kimi Code's permission rules.",
			},
		},
	}
	h.useTaggedBlockHooks(func(binaryPath string) string {
		cmd := shellHookCommand(binaryPath, "kimi")
		return "\n# yolonot-hooks-start\n[[hooks]]\nevent = \"PreToolUse\"\nmatcher = \"Bash\"\ncommand = " + quoteYAMLString(cmd) + "\ntimeout = 60\n# yolonot-hooks-end\n"
	})
	return h
}
