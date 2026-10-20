package yolonot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func init() { RegisterHarness(newOpencodeHarness()) }

// OpencodeHarness is the sst/opencode adapter.
type OpencodeHarness struct {
	baseHarness
}

func newOpencodeHarness() *OpencodeHarness {
	supportsAsk := func() bool {
		return os.Getenv("YOLONOT_OPENCODE_API") == "2"
	}
	h := &OpencodeHarness{
		baseHarness: baseHarness{
			name:          "opencode",
			supportsAskFn: supportsAsk,
			riskMapFn: func() map[string]string {
				moderate := ActionAllow
				if supportsAsk() {
					moderate = ActionAsk
				}
				return map[string]string{
					RiskSafe:     ActionAllow,
					RiskLow:      ActionAllow,
					RiskModerate: moderate,
					RiskHigh:     ActionDeny,
					RiskCritical: ActionDeny,
				}
			},
			sessionEnvKeys: []string{"YOLONOT_OPENCODE_SESSION_ID", "OPENCODE_SESSION_ID"},
			configDirFn:    opencodeConfigDir,
			settingsPathFn: func() string {
				return filepath.Join(opencodeConfigDir(), "plugins", "yolonot.ts")
			},
			parseFn: func(input []byte) (HookPayload, error) {
				if len(input) == 0 {
					return HookPayload{}, nil
				}
				var p HookPayload
				if err := json.Unmarshal(input, &p); err != nil {
					return HookPayload{}, err
				}
				return p, nil
			},
			formatFn: func(r HookResponse) string {
				if r.HookSpecificOutput.PermissionDecision == "" {
					return ""
				}
				data, _ := json.Marshal(r)
				return string(data)
			},
			notesFn: func(settingsPath string) []string {
				return []string{
					fmt.Sprintf("OpenCode installs as a TypeScript plugin (%s). Reload or restart OpenCode to activate.", settingsPath),
					"OpenCode V2 uses native permission prompts for 'ask'. V1 defers ask to the host. Host auto-accept can approve native asks; use deny rules for hard blocks.",
					"Run 'yolonot upgrade' after updating the binary so the plugin shim stays in sync.",
				}
			},
		},
	}
	h.useShimFileHooks(shimFileHooksSpec{
		marker: "// yolonot — OpenCode plugin shim",
		legacyPathsFn: func(string) []string {
			return []string{filepath.Join(opencodeConfigDir(), "plugin", "yolonot.ts")}
		},
		buildShim: func(_, binaryPath string) ([]byte, error) {
			quotedBinary, _ := json.Marshal(binaryPath)
			return bytes.ReplaceAll(embeddedOpencodePluginTS, []byte(`"__YOLONOT_BIN__"`), quotedBinary), nil
		},
	})
	return h
}

func opencodeConfigDir() string {
	if config := os.Getenv("XDG_CONFIG_HOME"); config != "" {
		return filepath.Join(config, "opencode")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "opencode")
}
