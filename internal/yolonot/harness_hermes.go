package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() { RegisterHarness(newHermesHarness()) }

type HermesHarness struct{ baseHarness }

func hermesConfigDir() string {
	return xdgOrHomeConfigDir([]string{"HERMES_HOME"}, "", ".hermes")
}

func newHermesHarness() *HermesHarness {
	h := &HermesHarness{
		baseHarness: baseHarness{
			name:                 "hermes",
			supportsAsk:          true,
			ambiguousPostToolUse: true,
			sessionEnvKeys:       []string{"YOLONOT_HERMES_SESSION_ID", "HERMES_SESSION_ID"},
			configDirFn:    hermesConfigDir,
			settingsPathFn: func() string { return filepath.Join(hermesConfigDir(), "config.yaml") },
			riskMap:        askDenyRiskMap(),
			formatFn: func(r HookResponse) string {
				msg := r.HookSpecificOutput.PermissionDecisionReason
				switch r.HookSpecificOutput.PermissionDecision {
				case ActionDeny:
					if msg == "" {
						msg = "Blocked by yolonot"
					}
					data, _ := json.Marshal(map[string]string{"action": "block", "message": msg})
					return string(data)
				case ActionAsk:
					if msg == "" {
						msg = "yolonot: approval required"
					}
					data, _ := json.Marshal(map[string]string{"action": "approve", "message": msg})
					return string(data)
				default:
					return ""
				}
			},
			notes: []string{
				"Hermes pre_tool_call supports ask (action: approve -> escalates to Hermes prompt) and deny (action: block).",
				"Allow decisions pass through to Hermes's built-in dangerous-command detector.",
			},
		},
	}
	h.useTaggedBlockHooks(func(binaryPath string) string {
		if binaryPath == "" {
			binaryPath = "yolonot"
		}
		cmd := shellHookCommand(binaryPath, "hermes")
		return "\n# yolonot-hooks-start\nhooks_auto_accept: true\nhooks:\n  pre_tool_call:\n    - matcher: \"terminal\"\n      command: " + quoteYAMLString(cmd) + "\n      timeout: 60\n      fail_closed: true\n  post_tool_call:\n    - matcher: \"terminal\"\n      command: " + quoteYAMLString(cmd) + "\n      timeout: 60\n# yolonot-hooks-end\n"
	})
	origInstall := h.installFn
	h.installFn = func(settingsPath, binaryPath string) error {
		if existing, err := os.ReadFile(settingsPath); err == nil {
			cleaned := stripTaggedBlock(string(existing), "# yolonot-hooks-start", "# yolonot-hooks-end")
			for _, line := range strings.Split(cleaned, "\n") {
				if strings.TrimSpace(line) == "hooks:" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
					return fmt.Errorf("%s already contains a top-level 'hooks:' section outside yolonot's block", settingsPath)
				}
			}
		}
		return origInstall(settingsPath, binaryPath)
	}
	return h
}
