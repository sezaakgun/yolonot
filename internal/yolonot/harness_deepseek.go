package yolonot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() { RegisterHarness(newDeepseekHarness()) }

type DeepseekHarness struct{ baseHarness }

func dshConfigDir() string {
	return xdgOrHomeConfigDir([]string{"DSH_HOME"}, "", ".dsh")
}

func dshCordisPatchPath() string {
	return filepath.Join(dshConfigDir(), "cordis.patch.yml")
}

func newDeepseekHarness() *DeepseekHarness {
	h := &DeepseekHarness{
		baseHarness: baseHarness{
			name:           "deepseek",
			supportsAsk:    true,
			sessionEnvKeys: []string{"YOLONOT_DEEPSEEK_SESSION_ID", "DSH_SESSION_ID"},
			configDirFn:    dshConfigDir,
			settingsPathFn: func() string { return filepath.Join(dshConfigDir(), "yolonot-hooks.json") },
			riskMap:        askDenyRiskMap(),
			parseFn: func(input []byte) (HookPayload, error) {
				p, err := parseFlexibleHookPayload(input)
				if err != nil {
					return p, err
				}
				if sp, ok := p.ToolInput["sandbox_permissions"].(string); ok && sp == "danger-full-access" {
					p.BypassSandbox = true
				}
				return p, nil
			},
			formatFn: func(r HookResponse) string {
				if r.HookSpecificOutput.PermissionDecision == ActionAllow {
					return ""
				}
				return formatClaudePreToolUse(r)
			},
			notes: []string{
				"DeepSeek Harness mounts @deepseek-ai/dsh-hooks-claude-code via ~/.dsh/cordis.patch.yml.",
				"PreToolUse supports ask (force approval prompt) and deny; allow passes through to DSH's downstream gates.",
			},
		},
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName: "deepseek",
		events:      []string{"PreToolUse", "PostToolUse"},
		matcher:     "Bash|bash|pwsh",
		postInstall: func(settingsPath string) error {
			patchPath := dshCordisPatchPath()
			existing, err := os.ReadFile(patchPath)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			cleaned := stripTaggedBlock(string(existing), "# yolonot-hooks-start", "# yolonot-hooks-end")
			if !strings.Contains(cleaned, "dsh-hooks-claude-code") {
				for _, line := range strings.Split(cleaned, "\n") {
					if strings.TrimSpace(line) == "plugins:" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
						return fmt.Errorf("%s already contains a top-level 'plugins:' section outside yolonot's block", patchPath)
					}
				}
				block := "\n# yolonot-hooks-start\nplugins:\n  - id: hooks-claude-code\n    package: \"@deepseek-ai/dsh-hooks-claude-code\"\n    config:\n      configPath: " + quoteYAMLString(settingsPath) + "\n# yolonot-hooks-end\n"
				return atomicWriteFile(patchPath, []byte(strings.TrimRight(cleaned, "\n")+block), 0o644)
			}
			return nil
		},
		postUninstall: func(_ string) error {
			patchPath := dshCordisPatchPath()
			data, err := os.ReadFile(patchPath)
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			cleaned := stripTaggedBlock(string(data), "# yolonot-hooks-start", "# yolonot-hooks-end")
			return atomicWriteFile(patchPath, []byte(cleaned), 0o644)
		},
	})
	origIsInstalled := h.isInstalledFn
	h.isInstalledFn = func(settingsPath string) bool {
		if !origIsInstalled(settingsPath) {
			return false
		}
		data, err := os.ReadFile(dshCordisPatchPath())
		return err == nil && strings.Contains(string(data), "dsh-hooks-claude-code")
	}
	return h
}
