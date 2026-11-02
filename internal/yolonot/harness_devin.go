package yolonot

import (
	"os"
	"path/filepath"
)

func init() { RegisterHarness(newDevinHarness()) }

type DevinHarness struct{ baseHarness }

func devinConfigDir() string {
	return xdgOrHomeConfigDir([]string{"DEVIN_CONFIG_DIR"}, "devin", filepath.Join(".config", "devin"))
}

func newDevinHarness() *DevinHarness {
	h := &DevinHarness{
		baseHarness: baseHarness{
			name:           "devin",
			supportsAsk:    true,
			sessionEnvKeys: []string{"YOLONOT_DEVIN_SESSION_ID", "DEVIN_SESSION_ID"},
			configDirFn:    devinConfigDir,
			settingsPathFn: func() string { return filepath.Join(devinConfigDir(), "config.json") },
			riskMap:        claudeCompatRiskMap(),
			parseFn: func(input []byte) (HookPayload, error) {
				p, err := parseFlexibleHookPayload(input)
				if err == nil && p.HookEventName != "" {
					if p.Cwd == "" {
						p.Cwd, _ = os.Getwd()
					} else if !filepath.IsAbs(p.Cwd) {
						if wd, werr := os.Getwd(); werr == nil && wd != "" {
							p.Cwd = filepath.Join(wd, p.Cwd)
						}
					}
				}
				return p, err
			},
			notes: []string{
				"Devin CLI also imports ~/.claude/settings.json hooks automatically; its shell tool is 'exec'.",
				"Note: any Exec(...) rule under sandbox.excluded.allow in ~/.config/devin/config.json runs unsandboxed without prompting.",
			},
		},
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName: "devin",
		events:      []string{"PreToolUse", "PostToolUse"},
		matcher:     "exec",
	})
	return h
}
