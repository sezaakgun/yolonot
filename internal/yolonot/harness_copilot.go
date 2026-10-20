package yolonot

import (
	"encoding/json"
	"path/filepath"
)

func init() { RegisterHarness(newCopilotHarness()) }

type CopilotHarness struct{ baseHarness }

func copilotConfigDir() string {
	return xdgOrHomeConfigDir([]string{"COPILOT_HOME"}, "", ".copilot")
}

func newCopilotHarness() *CopilotHarness {
	h := &CopilotHarness{
		baseHarness: baseHarness{
			name:                 "copilot",
			supportsAsk:          true,
			ambiguousPostToolUse: true,
			sessionEnvKeys:       []string{"YOLONOT_COPILOT_SESSION_ID", "COPILOT_SESSION_ID"},
			configDirFn:    copilotConfigDir,
			settingsPathFn: func() string { return filepath.Join(copilotConfigDir(), "settings.json") },
			riskMap:        claudeCompatRiskMap(),
			formatFn: func(r HookResponse) string {
				d := r.HookSpecificOutput.PermissionDecision
				if d == "" {
					return ""
				}
				reason := r.HookSpecificOutput.PermissionDecisionReason
				if d == ActionDeny && reason == "" {
					reason = "Blocked by yolonot"
					r.HookSpecificOutput.PermissionDecisionReason = reason
				}
				out := map[string]interface{}{
					"permissionDecision": d,
					"hookSpecificOutput": r.HookSpecificOutput,
				}
				if reason != "" {
					out["permissionDecisionReason"] = reason
				}
				if r.SystemMessage != "" {
					out["systemMessage"] = r.SystemMessage
				}
				data, _ := json.Marshal(out)
				return string(data)
			},
			notes: []string{
				"GitHub Copilot CLI preToolUse hooks fail closed on process errors and fail open on timeout (timeoutSec: 60).",
				"When Copilot's session sandbox is enabled, hooks run inside the sandbox and need write access to ~/.yolonot.",
			},
		},
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName: "copilot",
		events:      []string{"preToolUse", "postToolUse"},
		stripEvents: []string{"preToolUse", "postToolUse", "PreToolUse", "PostToolUse"},
		matcher:     "bash|powershell|local_shell",
		entryExtras: map[string]interface{}{"timeoutSec": 60.0},
	})
	return h
}
