package yolonot

import (
	"os"
	"path/filepath"
)

func init() { RegisterHarness(newZcodeHarness()) }

type ZcodeHarness struct{ baseHarness }

func zcodeConfigDir() string {
	return xdgOrHomeConfigDir([]string{"ZCODE_HOME"}, "", ".zcode")
}

func newZcodeHarness() *ZcodeHarness {
	h := &ZcodeHarness{
		baseHarness: baseHarness{
			name:           "zcode",
			supportsAsk:    true,
			sessionEnvKeys: []string{"YOLONOT_ZCODE_SESSION_ID", "ZCODE_SESSION_ID"},
			configDirFn:    zcodeConfigDir,
			settingsPathFn: func() string {
				if f := os.Getenv("ZCODE_CLI_SETTINGS_FILE"); f != "" {
					return f
				}
				return filepath.Join(zcodeConfigDir(), "cli", "setting.json")
			},
			riskMap: claudeCompatRiskMap(),
			notes: []string{
				"ZCode CLI hooks are registered in ~/.zcode/cli/setting.json with hooks.enabled=true.",
				"ZCode Desktop also reads ~/.claude/settings.json when Claude hooks are installed.",
			},
		},
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName:    "zcode",
		events:         []string{"PreToolUse", "PostToolUse"},
		matcher:        "Bash",
		eventsSubKey:   "events",
		setEnabledFlag: true,
	})
	return h
}
