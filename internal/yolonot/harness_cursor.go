package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func init() { RegisterHarness(newCursorHarness()) }

// CursorHarness is the Cursor / cursor-agent adapter.
type CursorHarness struct {
	baseHarness
}

type cursorPayload struct {
	ConversationID string                 `json:"conversation_id"`
	SessionID      string                 `json:"session_id"`
	ToolUseID      string                 `json:"tool_use_id"`
	HookEventName  string                 `json:"hook_event_name"`
	ToolName       string                 `json:"tool_name"`
	Cwd            string                 `json:"cwd"`
	Command        string                 `json:"command"`
	ToolInput      map[string]interface{} `json:"tool_input"`
	WorkspaceRoots []string               `json:"workspace_roots"`
	Sandbox        *bool                  `json:"sandbox,omitempty"`
	TranscriptPath string                 `json:"transcript_path,omitempty"`
}

type cursorResponse struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

func newCursorHarness() *CursorHarness {
	supportsAsk := func() bool {
		return os.Getenv("YOLONOT_CURSOR_NATIVE_ASK") == "1"
	}
	h := &CursorHarness{
		baseHarness: baseHarness{
			name:                 "cursor",
			supportsAskFn:        supportsAsk,
			ambiguousPostToolUse: true,
			riskMapFn: func() map[string]string {
				if supportsAsk() {
					return askDenyRiskMap()
				}
				return allowDenyRiskMap()
			},
			sessionEnvKeys: []string{"YOLONOT_CURSOR_SESSION_ID"},
			configDirFn: func() string {
				home, _ := os.UserHomeDir()
				return filepath.Join(home, ".cursor")
			},
			settingsPathFn: func() string {
				home, _ := os.UserHomeDir()
				return filepath.Join(home, ".cursor", "hooks.json")
			},
			parseFn: func(input []byte) (HookPayload, error) {
				if len(input) == 0 {
					return HookPayload{}, nil
				}
				var raw cursorPayload
				if err := json.Unmarshal(input, &raw); err != nil {
					return HookPayload{}, err
				}
				event := raw.HookEventName
				switch event {
				case "beforeShellExecution":
					event = "PreToolUse"
				case "afterShellExecution":
					event = "PostToolUse"
				case "preToolUse", "PreToolUse":
					if raw.ToolName != "" && raw.ToolName != "Shell" && raw.ToolName != "Bash" && raw.ToolName != "PowerShell" {
						return HookPayload{}, nil
					}
					event = "PreToolUse"
				case "postToolUse", "PostToolUse":
					if raw.ToolName != "" && raw.ToolName != "Shell" && raw.ToolName != "Bash" && raw.ToolName != "PowerShell" {
						return HookPayload{}, nil
					}
					event = "PostToolUse"
				}
				cmd := raw.Command
				if cmd == "" && raw.ToolInput != nil {
					cmd, _ = raw.ToolInput["command"].(string)
				}
				cwd := raw.Cwd
				if cwd == "" && raw.ToolInput != nil {
					cwd, _ = raw.ToolInput["cwd"].(string)
				}
				root := ""
				if len(raw.WorkspaceRoots) > 0 && raw.WorkspaceRoots[0] != "" {
					root = raw.WorkspaceRoots[0]
				} else {
					root = os.Getenv("CURSOR_PROJECT_DIR")
				}
				if cwd == "" {
					cwd = root
				} else if !filepath.IsAbs(cwd) && root != "" {
					cwd = filepath.Join(root, cwd)
				}
				toolInput := make(map[string]interface{}, len(raw.ToolInput)+1)
				for k, v := range raw.ToolInput {
					toolInput[k] = v
				}
				toolInput["command"] = cmd
				sid := raw.ConversationID
				if sid == "" {
					sid = raw.SessionID
				}
				bypass := (raw.Sandbox != nil && !*raw.Sandbox) || extractToolInputBypassSandbox(toolInput)
				return HookPayload{
					HookEventName:  event,
					ToolName:       "Bash",
					SessionID:      sid,
					ToolUseID:      raw.ToolUseID,
					Cwd:            cwd,
					ToolInput:      toolInput,
					BypassSandbox:  bypass,
					TranscriptPath: raw.TranscriptPath,
				}, nil
			},
			formatFn: func(r HookResponse) string {
				decision := r.HookSpecificOutput.PermissionDecision
				switch decision {
				case "":
					return ""
				case ActionAsk:
					if !supportsAsk() {
						return ""
					}
				}
				reason := r.HookSpecificOutput.PermissionDecisionReason
				if r.SystemMessage != "" && reason == "" {
					reason = r.SystemMessage
				}
				out := cursorResponse{
					Permission:   decision,
					UserMessage:  reason,
					AgentMessage: reason,
				}
				data, _ := json.Marshal(out)
				return string(data)
			},
			notesFn: func(string) []string {
				notes := []string{
					"Restart Cursor (or start a new chat) so the agent re-reads ~/.cursor/hooks.json.",
					"The same hooks.json governs the `cursor-agent` CLI — no extra install step needed.",
				}
				if supportsAsk() {
					return append(notes, "Native ask output is enabled via YOLONOT_CURSOR_NATIVE_ASK=1; verify a real approval prompt on your installed Cursor release.")
				}
				return append(notes, "Native ask output is disabled for compatibility with older Cursor releases. Verify prompting, then opt in with YOLONOT_CURSOR_NATIVE_ASK=1; deny rules remain hard blocks.")
			},
		},
	}
	h.useFlatJSONHooks(flatJSONHooksSpec{
		harnessName:     "cursor",
		events:          []string{"beforeShellExecution", "afterShellExecution"},
		matchAnyYolonot: true,
		defaultPerm:     0o600,
		rootDefaults:    map[string]interface{}{"version": 1.0},
		entryExtras:     map[string]interface{}{"timeout": 60.0},
	})
	return h
}

func cursorSkillDir() string {
	return newCursorHarness().skillDir()
}
