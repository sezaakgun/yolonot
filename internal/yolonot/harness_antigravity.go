package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func init() { RegisterHarness(newAntigravityHarness()) }

// AntigravityHarness implements the Antigravity CLI hook contract.
type AntigravityHarness struct {
	baseHarness
}

const antigravityHookName = "yolonot-command-guard"

type antigravityPayload struct {
	ConversationID string   `json:"conversationId"`
	WorkspacePaths []string `json:"workspacePaths"`
	HookEventName  string   `json:"hookEventName"`
	StepIdx        int      `json:"stepIdx,omitempty"`
	ToolCall       struct {
		Name string                 `json:"name"`
		Args map[string]interface{} `json:"args"`
	} `json:"toolCall"`
}

func newAntigravityHarness() *AntigravityHarness {
	h := &AntigravityHarness{
		baseHarness: baseHarness{
			name:           "antigravity",
			supportsAsk:    true,
			riskMap:        claudeCompatRiskMap(),
			sessionEnvKeys: []string{"YOLONOT_ANTIGRAVITY_SESSION_ID"},
			configDirFn: func() string {
				home, _ := os.UserHomeDir()
				return filepath.Join(home, ".gemini", "antigravity-cli")
			},
			settingsPathFn: func() string {
				home, _ := os.UserHomeDir()
				return filepath.Join(home, ".gemini", "config", "hooks.json")
			},
			isDetectedFn: func() bool {
				if _, err := exec.LookPath("agy"); err == nil {
					return true
				}
				home, err := os.UserHomeDir()
				if err != nil {
					return false
				}
				return dirExists(filepath.Join(home, ".gemini", "antigravity-cli"))
			},
			parseFn: func(input []byte) (HookPayload, error) {
				if len(input) == 0 {
					return HookPayload{}, nil
				}
				var raw antigravityPayload
				if err := json.Unmarshal(input, &raw); err != nil {
					return HookPayload{}, err
				}
				if raw.ToolCall.Name != "run_command" {
					return HookPayload{}, nil
				}
				command, ok := raw.ToolCall.Args["CommandLine"].(string)
				if !ok || command == "" {
					return HookPayload{}, fmt.Errorf("Antigravity run_command requires CommandLine")
				}
				cwd, _ := raw.ToolCall.Args["Cwd"].(string)
				if cwd == "" && len(raw.WorkspacePaths) == 1 {
					cwd = raw.WorkspacePaths[0]
				} else if cwd != "" && !filepath.IsAbs(cwd) && len(raw.WorkspacePaths) == 1 {
					cwd = filepath.Join(raw.WorkspacePaths[0], cwd)
				}
				if cwd == "" {
					return HookPayload{}, fmt.Errorf("Antigravity run_command requires an unambiguous working directory")
				}
				event := antigravityEvent(raw.HookEventName)
				if event != "PreToolUse" && event != "PostToolUse" {
					return HookPayload{}, fmt.Errorf("unsupported Antigravity hook event %q", event)
				}
				bypass, _ := raw.ToolCall.Args["BypassSandbox"].(bool)
				toolInput := map[string]interface{}{"command": command}
				if bypass {
					toolInput["BypassSandbox"] = true
				}
				toolUseID := ""
				if raw.StepIdx > 0 {
					toolUseID = fmt.Sprintf("step_%d", raw.StepIdx)
				}
				return HookPayload{
					HookEventName: event,
					ToolName:      "Bash",
					SessionID:     raw.ConversationID,
					ToolUseID:     toolUseID,
					Cwd:           cwd,
					ToolInput:     toolInput,
					BypassSandbox: bypass,
				}, nil
			},
			formatFn: formatAntigravityResponse,
			notes: []string{
				"Restart Antigravity CLI (`agy`) and inspect `/hooks` to confirm yolonot-command-guard is active.",
				"Global hooks use ~/.gemini/config/hooks.json; Gemini CLI's BeforeTool hooks require its separate adapter.",
				"Allow removes the default prompt via auto_approve; ask uses force_ask and still requires interactive approval.",
			},
		},
	}
	h.parseFailureFn = func(input []byte, err error) string {
		var raw antigravityPayload
		_ = json.Unmarshal(input, &raw)
		if antigravityEvent(raw.HookEventName) != "PreToolUse" {
			return ""
		}
		r := HookResponse{}
		r.HookSpecificOutput.PermissionDecision = ActionDeny
		r.HookSpecificOutput.PermissionDecisionReason = sanitizeBanner("yolonot: " + err.Error())
		return formatAntigravityResponse(r)
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName:   "antigravity",
		namedRootHook: antigravityHookName,
		events:        []string{"PreToolUse", "PostToolUse"},
		matcher:       "^run_command$",
		defaultPerm:   0o600,
		buildEntry: func(event, binaryPath string) map[string]interface{} {
			quoted := "'" + strings.ReplaceAll(binaryPath, "'", "'\"'\"'") + "'"
			return map[string]interface{}{
				"type":    "command",
				"command": quoted + " hook --harness antigravity --hook-event " + event,
				"timeout": 60,
			}
		},
	})
	return h
}

func antigravityEvent(fromInput string) string {
	if fromInput != "" {
		return fromInput
	}
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--hook-event" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
		if strings.HasPrefix(os.Args[i], "--hook-event=") {
			return strings.TrimPrefix(os.Args[i], "--hook-event=")
		}
	}
	return "PreToolUse"
}

func formatAntigravityResponse(r HookResponse) string {
	decision := r.HookSpecificOutput.PermissionDecision
	switch decision {
	case "":
		return ""
	case ActionAllow:
		decision = "auto_approve"
	case ActionAsk:
		// shortcut: force_ask narrows the prompt to one-time Allow/Deny and PostToolUse omits grant scope, switch to scope-aware ask when agy hooks expose the user's permission selection
		decision = "force_ask"
	case ActionDeny:
	default:
		decision = ActionDeny
	}
	reason := r.HookSpecificOutput.PermissionDecisionReason
	if reason == "" {
		reason = r.SystemMessage
	}
	data, _ := json.Marshal(struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason,omitempty"`
	}{decision, reason})
	return string(data)
}

func (a *AntigravityHarness) loadHooks() (map[string]interface{}, error) {
	return readHarnessJSON(a.SettingsPath())
}

func antigravitySkillDir() string {
	return newAntigravityHarness().skillDir()
}
