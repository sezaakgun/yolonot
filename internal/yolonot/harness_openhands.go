package yolonot

import (
	"encoding/json"
	"path/filepath"
)

func init() { RegisterHarness(newOpenhandsHarness()) }

type OpenhandsHarness struct{ baseHarness }

func openhandsConfigDir() string {
	return xdgOrHomeConfigDir([]string{"OPENHANDS_CONFIG_DIR"}, "", ".openhands")
}

func newOpenhandsHarness() *OpenhandsHarness {
	h := &OpenhandsHarness{
		baseHarness: baseHarness{
			name:           "openhands",
			sessionEnvKeys: []string{"YOLONOT_OPENHANDS_SESSION_ID", "OPENHANDS_SESSION_ID"},
			configDirFn:    openhandsConfigDir,
			settingsPathFn: func() string { return filepath.Join(openhandsConfigDir(), "hooks.json") },
			riskMap:        denyOnlyRiskMap(),
			formatFn: func(r HookResponse) string {
				if r.HookSpecificOutput.PermissionDecision != ActionDeny {
					return ""
				}
				reason := r.HookSpecificOutput.PermissionDecisionReason
				if reason == "" {
					reason = "Blocked by yolonot"
				}
				data, _ := json.Marshal(map[string]string{
					"decision": ActionDeny,
					"reason":   reason,
				})
				return string(data)
			},
			notes: []string{
				"OpenHands PreToolUse supports deny; HookConfig.load() stops at the first existing hooks.json (<cwd>/.openhands/hooks.json overrides ~/.openhands/hooks.json).",
			},
		},
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName:             "openhands",
		events:                  []string{"PreToolUse", "PostToolUse"},
		matcher:                 "terminal",
		acceptRootHooksFallback: true,
	})
	return h
}
