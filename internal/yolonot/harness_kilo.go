package yolonot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func init() { RegisterHarness(newKiloHarness()) }

type KiloHarness struct{ baseHarness }

func kiloConfigDir() string {
	return xdgOrHomeConfigDir([]string{"KILO_CONFIG_DIR"}, "kilo", filepath.Join(".config", "kilo"))
}

func newKiloHarness() *KiloHarness {
	h := &KiloHarness{
		baseHarness: baseHarness{
			name:           "kilo",
			supportsAskFn:  func() bool { return os.Getenv("YOLONOT_OPENCODE_API") == "2" },
			sessionEnvKeys: []string{"YOLONOT_KILO_SESSION_ID", "KILO_SESSION_ID", "KILO_RUN_ID"},
			configDirFn:    kiloConfigDir,
			settingsPathFn: func() string { return filepath.Join(kiloConfigDir(), "plugins", "yolonot.ts") },
			formatFn:       formatCanonicalPluginResponse,
			notesFn: func(settingsPath string) []string {
				return []string{
					fmt.Sprintf("Kilo Code installs as a TypeScript plugin (%s).", settingsPath),
					"Note: Kilo Code's migrateBashPermission() sets permission.bash = 'allow' by default; yolonot still intercepts every bash tool call.",
				}
			},
		},
	}
	h.riskMapFn = func() map[string]string {
		moderate := ActionAllow
		if h.SupportsAsk() {
			moderate = ActionAsk
		}
		return map[string]string{
			RiskSafe:     ActionAllow,
			RiskLow:      ActionAllow,
			RiskModerate: moderate,
			RiskHigh:     ActionDeny,
			RiskCritical: ActionDeny,
		}
	}
	h.useShimFileHooks(shimFileHooksSpec{
		marker: "// yolonot — Kilo Code plugin shim",
		legacyPathsFn: func(_ string) []string {
			return []string{filepath.Join(kiloConfigDir(), "plugin", "yolonot.ts")}
		},
		buildShim: func(_, binaryPath string) ([]byte, error) {
			quotedBinary, _ := json.Marshal(binaryPath)
			ts := bytes.ReplaceAll(embeddedOpencodePluginTS, []byte(`"__YOLONOT_BIN__"`), quotedBinary)
			ts = bytes.ReplaceAll(ts, []byte(`// yolonot — OpenCode plugin shim`), []byte(`// yolonot — Kilo Code plugin shim`))
			ts = bytes.ReplaceAll(ts, []byte(`YOLONOT_HARNESS: "opencode"`), []byte(`YOLONOT_HARNESS: "kilo"`))
			return ts, nil
		},
	})
	return h
}
