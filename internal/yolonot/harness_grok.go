package yolonot

import "path/filepath"

func init() { RegisterHarness(newGrokHarness()) }

type GrokHarness struct{ baseHarness }

func grokConfigDir() string {
	return xdgOrHomeConfigDir([]string{"GROK_HOME"}, "", ".grok")
}

func newGrokHarness() *GrokHarness {
	h := &GrokHarness{
		baseHarness: baseHarness{
			name:           "grok",
			supportsAsk:    true,
			sessionEnvKeys: []string{"YOLONOT_GROK_SESSION_ID", "GROK_SESSION_ID"},
			configDirFn:    grokConfigDir,
			settingsPathFn: func() string { return filepath.Join(grokConfigDir(), "hooks", "yolonot.json") },
			riskMap:        claudeCompatRiskMap(),
			notes: []string{
				"Grok Build PreToolUse enforces ask and deny; 'allow' means not blocked and defers to Grok's permission mode.",
				"Grok Build also loads ~/.claude/settings.json by default unless [compat.claude] hooks = false is set in ~/.grok/config.toml.",
			},
		},
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName:         "grok",
		events:              []string{"PreToolUse", "PostToolUse"},
		matcher:             "Bash",
		removeFileWhenEmpty: true,
	})
	return h
}
