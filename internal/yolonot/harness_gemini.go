package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func init() { RegisterHarness(newGeminiHarness()) }

// GeminiHarness is the Google Gemini CLI adapter (retired; kept for migration/uninstall).
type GeminiHarness struct {
	baseHarness
}

type geminiResponse struct {
	Decision      string `json:"decision"`
	Reason        string `json:"reason,omitempty"`
	SystemMessage string `json:"systemMessage,omitempty"`
}

const geminiMatcher = "^run_shell_command$"

func newGeminiHarness() *GeminiHarness {
	h := &GeminiHarness{
		baseHarness: baseHarness{
			name:           "gemini",
			supportsAsk:    true,
			riskMap:        claudeCompatRiskMap(),
			sessionEnvKeys: []string{"YOLONOT_GEMINI_SESSION_ID"},
			configDirFn: func() string {
				home, _ := os.UserHomeDir()
				return filepath.Join(home, ".gemini")
			},
			settingsPathFn: func() string {
				home, _ := os.UserHomeDir()
				return filepath.Join(home, ".gemini", "settings.json")
			},
			parseFn: func(input []byte) (HookPayload, error) {
				if len(input) == 0 {
					return HookPayload{}, nil
				}
				var p HookPayload
				if err := json.Unmarshal(input, &p); err != nil {
					return HookPayload{}, err
				}
				switch p.HookEventName {
				case "BeforeTool":
					p.HookEventName = "PreToolUse"
				case "AfterTool":
					p.HookEventName = "PostToolUse"
				}
				if p.ToolName == "run_shell_command" {
					p.ToolName = "Bash"
				}
				return p, nil
			},
			formatFn: func(r HookResponse) string {
				decision := r.HookSpecificOutput.PermissionDecision
				if decision == "" {
					return ""
				}
				out := geminiResponse{
					Decision:      decision,
					Reason:        r.HookSpecificOutput.PermissionDecisionReason,
					SystemMessage: r.SystemMessage,
				}
				data, _ := json.Marshal(out)
				return string(data)
			},
		},
	}
	h.notesFn = func(string) []string {
		s := h.loadSettings()
		general, _ := s["general"].(map[string]interface{})
		if mode, _ := general["defaultApprovalMode"].(string); mode == "yolo" {
			return nil
		}
		return []string{
			"Launch Gemini with `gemini --yolo` (or set general.defaultApprovalMode=\"yolo\" in ~/.gemini/settings.json).",
			"Without YOLO mode Gemini prompts on every shell command regardless of yolonot's decision — allow becomes cosmetic.",
		}
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName:     "gemini",
		events:          []string{"BeforeTool", "AfterTool"},
		matcher:         geminiMatcher,
		matchAnyYolonot: true,
		defaultPerm:     0o600,
		buildEntry: func(_, binaryPath string) map[string]interface{} {
			return map[string]interface{}{
				"type":    "command",
				"command": binaryPath + " hook --harness gemini",
				"timeout": 60000.0,
			}
		},
	})
	return h
}

func geminiSkillDir() string {
	return newGeminiHarness().skillDir()
}
