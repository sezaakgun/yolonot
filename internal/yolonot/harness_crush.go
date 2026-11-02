package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func init() { RegisterHarness(newCrushHarness()) }

type CrushHarness struct{ baseHarness }

func crushConfigDir() string {
	if p := os.Getenv("CRUSH_GLOBAL_CONFIG"); p != "" {
		if strings.HasSuffix(strings.ToLower(p), ".json") {
			return filepath.Dir(p)
		}
		return p
	}
	return xdgOrHomeConfigDir(nil, "crush", filepath.Join(".config", "crush"))
}

func newCrushHarness() *CrushHarness {
	h := &CrushHarness{
		baseHarness: baseHarness{
			name:           "crush",
			sessionEnvKeys: []string{"YOLONOT_CRUSH_SESSION_ID", "CRUSH_SESSION_ID"},
			configDirFn:    crushConfigDir,
			settingsPathFn: func() string {
				if p := os.Getenv("CRUSH_GLOBAL_CONFIG"); p != "" && strings.HasSuffix(strings.ToLower(p), ".json") {
					return p
				}
				return filepath.Join(crushConfigDir(), "crush.json")
			},
			riskMap: allowDenyRiskMap(),
			formatFn: func(r HookResponse) string {
				switch r.HookSpecificOutput.PermissionDecision {
				case "", ActionAsk:
					return ""
				}
				data, _ := json.Marshal(r)
				return string(data)
			},
			notes: []string{
				"Crush PreToolUse supports allow (auto-approve) and deny; ask defers to Crush's native permission prompt.",
				"Note: Crush sub-agent tool calls skip the hook runner upstream unless permissions are restricted.",
			},
		},
	}
	h.useFlatJSONHooks(flatJSONHooksSpec{
		harnessName: "crush",
		events:      []string{"PreToolUse"},
		stripEvents: []string{"PreToolUse", "PostToolUse"},
		matcher:     "bash",
		entryExtras: map[string]interface{}{
			"name":    "yolonot",
			"timeout": 60.0,
		},
	})
	return h
}
