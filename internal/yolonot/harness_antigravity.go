package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func init() { RegisterHarness(&AntigravityHarness{}) }

// AntigravityHarness implements the Antigravity CLI 1.3.5 hook contract.
// https://www.antigravity.google/docs/hooks/ documents a named hook map,
// camelCase input, and distinct neutral allow / auto_approve decisions.
// The shared global hooks file is also understood by current Antigravity
// desktop/IDE releases; their individual releases are not assumed equal.
type AntigravityHarness struct{}

const antigravityHookName = "yolonot-command-guard"

func (a *AntigravityHarness) Name() string { return "antigravity" }

func (a *AntigravityHarness) SupportsAsk() bool { return true }

func (a *AntigravityHarness) SettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gemini", "config", "hooks.json")
}

func (a *AntigravityHarness) SessionIDFromEnv() string {
	return os.Getenv("YOLONOT_ANTIGRAVITY_SESSION_ID")
}

func (a *AntigravityHarness) RiskMap() map[string]string {
	return (&GeminiHarness{}).RiskMap()
}

type antigravityPayload struct {
	ConversationID string   `json:"conversationId"`
	WorkspacePaths []string `json:"workspacePaths"`
	HookEventName  string   `json:"hookEventName"`
	ToolCall       struct {
		Name string                 `json:"name"`
		Args map[string]interface{} `json:"args"`
	} `json:"toolCall"`
}

func (a *AntigravityHarness) ParseHookInput(input []byte) (HookPayload, error) {
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
	}
	if cwd == "" {
		return HookPayload{}, fmt.Errorf("Antigravity run_command requires an unambiguous working directory")
	}
	// Antigravity's common stdin fields do not include the event name.
	// Pin it in each installed command instead of inferring PostToolUse
	// from the optional error field (successful calls omit that field).
	event := raw.HookEventName
	if event == "" {
		event = "PreToolUse"
		for i := 2; i < len(os.Args); i++ {
			if os.Args[i] == "--hook-event" && i+1 < len(os.Args) {
				event = os.Args[i+1]
				break
			}
			if strings.HasPrefix(os.Args[i], "--hook-event=") {
				event = strings.TrimPrefix(os.Args[i], "--hook-event=")
				break
			}
		}
	}
	if event != "PreToolUse" && event != "PostToolUse" {
		return HookPayload{}, fmt.Errorf("unsupported Antigravity hook event %q", event)
	}
	return HookPayload{HookEventName: event, ToolName: "Bash", SessionID: raw.ConversationID,
		Cwd: cwd, ToolInput: map[string]interface{}{"command": command}}, nil
}

func (a *AntigravityHarness) FormatHookResponse(r HookResponse) string {
	decision := r.HookSpecificOutput.PermissionDecision
	switch decision {
	case "":
		return ""
	case ActionAllow:
		// "allow" is neutral in this host; auto_approve is the decision
		// that actually removes a default-policy prompt for a vetted call.
		decision = "auto_approve"
	case ActionAsk:
		// Cached/Always Allow grants must not suppress a fresh policy ask.
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
	data, err := os.ReadFile(a.SettingsPath())
	if os.IsNotExist(err) {
		return map[string]interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	var hooks map[string]interface{}
	if err := json.Unmarshal(data, &hooks); err != nil {
		return nil, fmt.Errorf("invalid Antigravity hooks config: %w", err)
	}
	if hooks == nil {
		return nil, fmt.Errorf("Antigravity hooks config must be an object")
	}
	return hooks, nil
}

func (a *AntigravityHarness) saveHooks(hooks map[string]interface{}) error {
	data, err := json.MarshalIndent(hooks, "", "  ")
	if err != nil {
		return err
	}
	perm := os.FileMode(0600)
	if info, err := os.Stat(a.SettingsPath()); err == nil {
		perm = info.Mode().Perm()
	}
	return atomicWriteFile(a.SettingsPath(), append(data, '\n'), perm)
}

func (a *AntigravityHarness) IsInstalled() bool {
	hooks, err := a.loadHooks()
	if err != nil {
		return false
	}
	definition, ok := hooks[antigravityHookName].(map[string]interface{})
	if !ok || definition["enabled"] == false {
		return false
	}
	entries, _ := definition["PreToolUse"].([]interface{})
	for _, entry := range entries {
		group, _ := entry.(map[string]interface{})
		handlers, _ := group["hooks"].([]interface{})
		for _, handler := range handlers {
			h, _ := handler.(map[string]interface{})
			command, _ := h["command"].(string)
			if strings.Contains(command, " hook --harness antigravity") {
				return true
			}
		}
	}
	return false
}

func (a *AntigravityHarness) Install(binaryPath string) error {
	hooks, err := a.loadHooks()
	if err != nil {
		return err
	}
	definition := map[string]interface{}{"enabled": true}
	// Hook commands are interpreted by the host shell. Quote executable
	// paths so spaces and shell metacharacters remain part of the path.
	quoted := "'" + strings.ReplaceAll(binaryPath, "'", "'\"'\"'") + "'"
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		definition[event] = []interface{}{map[string]interface{}{
			"matcher": "^run_command$",
			"hooks": []interface{}{map[string]interface{}{
				"type": "command", "command": quoted + " hook --harness antigravity --hook-event " + event, "timeout": 60,
			}},
		}}
	}
	hooks[antigravityHookName] = definition
	return a.saveHooks(hooks)
}

func (a *AntigravityHarness) Uninstall() error {
	hooks, err := a.loadHooks()
	if err != nil {
		return err
	}
	if _, exists := hooks[antigravityHookName]; !exists {
		return nil
	}
	delete(hooks, antigravityHookName)
	return a.saveHooks(hooks)
}

func antigravitySkillDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gemini", "antigravity-cli", "skills", "yolonot")
}

func (a *AntigravityHarness) InstallSkill() (string, error) {
	return installHarnessSkill(a.Name(), antigravitySkillDir())
}

func (a *AntigravityHarness) UninstallSkill() error {
	return uninstallHarnessSkill(antigravitySkillDir())
}

func (a *AntigravityHarness) IsDetected() bool {
	if _, err := exec.LookPath("agy"); err == nil {
		return true
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	info, err := os.Stat(filepath.Join(home, ".gemini", "antigravity-cli"))
	return err == nil && info.IsDir()
}

func (a *AntigravityHarness) PostInstallNotes() []string {
	return []string{
		"Restart Antigravity CLI (`agy`) and inspect `/hooks` to confirm yolonot-command-guard is active.",
		"Global hooks use ~/.gemini/config/hooks.json; Gemini CLI's BeforeTool hooks require its separate adapter.",
		"Allow removes the default prompt via auto_approve; ask uses force_ask and still requires interactive approval.",
	}
}
