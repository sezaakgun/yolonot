package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func init() { RegisterHarness(newGooseHarness()) }

type GooseHarness struct{ baseHarness }

func gooseConfigDir() string {
	if root := os.Getenv("GOOSE_PATH_ROOT"); root != "" {
		return filepath.Join(root, "config")
	}
	return xdgOrHomeConfigDir(nil, "goose", filepath.Join(".config", "goose"))
}

func newGooseHarness() *GooseHarness {
	h := &GooseHarness{
		baseHarness: baseHarness{
			name:           "goose",
			sessionEnvKeys: []string{"YOLONOT_GOOSE_SESSION_ID", "AGENT_SESSION_ID"},
			configDirFn:    gooseConfigDir,
			settingsPathFn: func() string {
				home, _ := os.UserHomeDir()
				return filepath.Join(home, ".agents", "plugins", "yolonot", "hooks", "hooks.json")
			},
			riskMap: denyOnlyRiskMap(),
			formatFn: func(r HookResponse) string {
				// Critical Goose quirk: non-empty JSON lacking "decision": "allow"|"block" is
				// treated as HookVerdict::HookFailure. Always emit empty stdout unless denying.
				if r.HookSpecificOutput.PermissionDecision != ActionDeny {
					return ""
				}
				reason := r.HookSpecificOutput.PermissionDecisionReason
				if reason == "" {
					reason = "Blocked by yolonot"
				}
				data, _ := json.Marshal(map[string]string{
					"decision": "block",
					"reason":   reason,
				})
				return string(data)
			},
			notes: []string{
				"Goose loads Open Plugins hooks from ~/.agents/plugins/yolonot/hooks/hooks.json.",
				"Note: Goose defaults GOOSE_MODE to 'auto', which bypasses permission.yaml; yolonot PreToolUse still blocks denied commands.",
			},
		},
	}
	h.isDetectedFn = func() bool {
		return dirExists(gooseConfigDir()) || dirExists(filepath.Dir(h.SettingsPath()))
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName: "goose",
		events:      []string{"PreToolUse"},
		matcher:     "shell|developer__shell",
		entryExtras: map[string]interface{}{
			"timeout":    60.0,
			"on_failure": "block",
		},
	})
	return h
}
