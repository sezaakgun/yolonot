package yolonot

import "path/filepath"

func init() { RegisterHarness(newKiroHarness()) }

type KiroHarness struct{ baseHarness }

func kiroConfigDir() string {
	return xdgOrHomeConfigDir([]string{"KIRO_HOME"}, "", ".kiro")
}

func newKiroHarness() *KiroHarness {
	h := &KiroHarness{
		baseHarness: baseHarness{
			name:           "kiro",
			exitTwoOnDeny:  true,
			sessionEnvKeys: []string{"YOLONOT_KIRO_SESSION_ID", "KIRO_SESSION_ID"},
			configDirFn:    kiroConfigDir,
			settingsPathFn: func() string { return filepath.Join(kiroConfigDir(), "agents", "default.json") },
			riskMap:        denyOnlyRiskMap(),
			formatFn: func(r HookResponse) string {
				// Critical Kiro quirk: Kiro does not parse JSON decisions from stdout.
				// Any non-empty stdout on exit 0 is injected verbatim into the LLM prompt as context!
				// On deny, return the plaintext reason so emitHook writes it to stderr and exits 2.
				if r.HookSpecificOutput.PermissionDecision == ActionDeny {
					if r.HookSpecificOutput.PermissionDecisionReason != "" {
						return r.HookSpecificOutput.PermissionDecisionReason
					}
					return "Blocked by yolonot"
				}
				return ""
			},
			notes: []string{
				"Kiro CLI v3 uses exit code 2 (stderr reason) to block denied commands and requires empty stdout on exit 0 so hook output is not injected into the LLM prompt.",
			},
		},
	}
	h.useFlatJSONHooks(flatJSONHooksSpec{
		harnessName:  "kiro",
		events:       []string{"preToolUse", "postToolUse"},
		matcher:      "execute_bash",
		rootDefaults: map[string]interface{}{"name": "default"},
		entryExtras:  map[string]interface{}{"timeout_ms": 60000.0},
		postInstall: func(settingsPath string) error {
			cliSettingsPath := filepath.Join(filepath.Dir(filepath.Dir(settingsPath)), "settings", "cli.json")
			cfg, err := readHarnessJSON(cliSettingsPath)
			if err != nil {
				return nil
			}
			if _, ok := cfg["chat.defaultAgent"]; !ok {
				cfg["chat.defaultAgent"] = "default"
				return saveHarnessJSON(cliSettingsPath, cfg)
			}
			return nil
		},
	})
	return h
}
