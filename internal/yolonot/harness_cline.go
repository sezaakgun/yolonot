package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() { RegisterHarness(newClineHarness()) }

type ClineHarness struct{ baseHarness }

func clineConfigDir() string {
	return xdgOrHomeConfigDir([]string{"CLINE_DIR"}, "", ".cline")
}

func newClineHarness() *ClineHarness {
	return &ClineHarness{
		baseHarness: baseHarness{
			name:           "cline",
			sessionEnvKeys: []string{"YOLONOT_CLINE_SESSION_ID", "CLINE_SESSION_ID"},
			configDirFn:    clineConfigDir,
			settingsPathFn: func() string { return filepath.Join(clineConfigDir(), "hooks", "PreToolUse") },
			riskMap:        denyOnlyRiskMap(),
			parseFn: func(input []byte) (HookPayload, error) {
				p, err := parseFlexibleHookPayload(input)
				if err != nil {
					return p, err
				}
				if p.HookEventName == "" && p.ToolName != "" {
					p.HookEventName = "PreToolUse"
				}
				return p, nil
			},
			formatFn: func(r HookResponse) string {
				if r.HookSpecificOutput.PermissionDecision != ActionDeny {
					return ""
				}
				reason := r.HookSpecificOutput.PermissionDecisionReason
				if reason == "" {
					reason = "Blocked by yolonot"
				}
				data, _ := json.Marshal(map[string]interface{}{
					"cancel":       true,
					"errorMessage": reason,
				})
				return string(data)
			},
			isInstalledFn: func(settingsPath string) bool {
				data, err := os.ReadFile(settingsPath)
				return err == nil && strings.Contains(string(data), "--harness cline")
			},
			installFn: func(_, binaryPath string) error {
				cmd := shellHookCommand(binaryPath, "cline")
				script := "#!/bin/sh\n# yolonot-hook\nexec " + cmd + "\n"
				for _, ev := range []string{"PreToolUse", "PostToolUse"} {
					p := filepath.Join(clineConfigDir(), "hooks", ev)
					if existing, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(existing))) > 0 {
						if !strings.Contains(string(existing), "# yolonot-hook") && !strings.Contains(string(existing), "--harness cline") {
							return fmt.Errorf("%s already exists and was not created by yolonot", p)
						}
					}
					if err := atomicWriteFile(p, []byte(script), 0o755); err != nil {
						return err
					}
					_ = os.Chmod(p, 0o755)
				}
				return nil
			},
			uninstallFn: func(_ string) error {
				for _, ev := range []string{"PreToolUse", "PostToolUse"} {
					p := filepath.Join(clineConfigDir(), "hooks", ev)
					data, err := os.ReadFile(p)
					if err == nil && (strings.Contains(string(data), "# yolonot-hook") || strings.Contains(string(data), "--harness cline")) {
						_ = os.Remove(p)
					}
				}
				return nil
			},
			notes: []string{
				"Cline CLI uses directory-based executable hook scripts (~/.cline/hooks/PreToolUse) and passes multi-command arrays in run_commands.",
				"Warning: running Cline with -y / --yolo completely disables all runtime hooks upstream.",
			},
		},
	}
}
