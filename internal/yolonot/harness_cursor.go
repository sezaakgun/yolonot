package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() { RegisterHarness(&CursorHarness{}) }

// CursorHarness is the Cursor / cursor-agent adapter.
//
// Cursor's hook protocol (verified against cursor.com/docs/hooks):
//   - Settings live in ~/.cursor/hooks.json — dedicated file, top-level
//     {"version": 1, "hooks": {<event>: [...]}}.
//   - Entries are FLAT: {"command": "...", "matcher": "...", "timeout": <s>}.
//     No Claude-style {"matcher", "hooks": [...]} wrapping.
//   - Event for shell gate is "beforeShellExecution" (pre) / "afterShellExecution".
//     More targeted than "preToolUse" (which fires for all tools).
//   - Stdin payload is snake_case with top-level `command` (not nested in
//     tool_input). ParseHookInput lifts command into canonical ToolInput and
//     sets ToolName=Bash so the rest of yolonot sees Claude-shaped values.
//   - Matcher is a regex against the command text (not tool name). Omitted
//     matcher = match all.
//   - Stdout response is FLAT: {"permission":"allow|ask|deny",
//     "user_message":"...","agent_message":"..."}. Current native ask
//     was verified on IDE 3.24.18. Older builds accepted ask without a
//     prompt, so deployments opt in with YOLONOT_CURSOR_NATIVE_ASK=1;
//     compatibility mode keeps host-deferred asks.
//   - Timeout is seconds (same as Claude, different from Gemini's ms).
//   - Session id arrives as `conversation_id` on stdin. No env export;
//     SessionIDFromEnv honours YOLONOT_CURSOR_SESSION_ID for user overrides.
type CursorHarness struct{}

func (c *CursorHarness) Name() string { return "cursor" }

// Current Cursor documentation specifies native ask handling. Keep the
// historical adapter behavior unless a deployment opts in after checking
// its installed IDE/CLI: older builds accepted ask without prompting.
func (c *CursorHarness) SupportsAsk() bool {
	return os.Getenv("YOLONOT_CURSOR_NATIVE_ASK") == "1"
}

// RiskMap keeps moderate risk host-deferred unless native ask is explicitly
// enabled. High/critical retain their deny defaults in either mode.
func (c *CursorHarness) RiskMap() map[string]string {
	if c.SupportsAsk() {
		return map[string]string{
			RiskSafe: ActionAllow, RiskLow: ActionAllow, RiskModerate: ActionAsk,
			RiskHigh: ActionDeny, RiskCritical: ActionDeny,
		}
	}
	return map[string]string{
		RiskSafe:     ActionAllow,
		RiskLow:      ActionAllow,
		RiskModerate: ActionPassthrough,
		RiskHigh:     ActionDeny,
		RiskCritical: ActionDeny,
	}
}

func (c *CursorHarness) SettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cursor", "hooks.json")
}

// SessionIDFromEnv honours YOLONOT_CURSOR_SESSION_ID. Cursor does not export
// its conversation id as an env var (it lives on stdin), so auto-detection
// via env is impossible — users set YOLONOT_HARNESS=cursor instead. The
// install step pins --harness cursor so routing is deterministic.
func (c *CursorHarness) SessionIDFromEnv() string {
	return os.Getenv("YOLONOT_CURSOR_SESSION_ID")
}

// cursorPayload is the stdin shape Cursor emits for beforeShellExecution.
// Only the fields yolonot needs are modelled; Unmarshal tolerates extras.
type cursorPayload struct {
	ConversationID string   `json:"conversation_id"`
	ToolUseID      string   `json:"tool_use_id"`
	HookEventName  string   `json:"hook_event_name"`
	Cwd            string   `json:"cwd"`
	Command        string   `json:"command"`
	WorkspaceRoots []string `json:"workspace_roots"`
	Sandbox        *bool    `json:"sandbox,omitempty"`
	TranscriptPath string   `json:"transcript_path,omitempty"`
}

// ParseHookInput decodes Cursor's stdin JSON into the canonical HookPayload
// and normalises event + tool-name aliases. Command is lifted into
// tool_input.command so rule/classifier code sees the Claude shape.
func (c *CursorHarness) ParseHookInput(input []byte) (HookPayload, error) {
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
	}
	// Current IDE/CLI shell hooks can omit cwd (Post) or send it empty
	// (Pre). Their primary workspace is the execution default, not the
	// hook subprocess's cwd, which wrappers may deliberately change.
	cwd := raw.Cwd
	if cwd == "" && len(raw.WorkspaceRoots) > 0 {
		cwd = raw.WorkspaceRoots[0]
	} else if cwd != "" && !filepath.IsAbs(cwd) && len(raw.WorkspaceRoots) > 0 {
		cwd = filepath.Join(raw.WorkspaceRoots[0], cwd)
	}
	bypass := raw.Sandbox != nil && !*raw.Sandbox
	return HookPayload{
		HookEventName:  event,
		ToolName:       "Bash",
		SessionID:      raw.ConversationID,
		ToolUseID:      raw.ToolUseID,
		Cwd:            cwd,
		ToolInput:      map[string]interface{}{"command": raw.Command},
		BypassSandbox:  bypass,
		TranscriptPath: raw.TranscriptPath,
	}, nil
}

// cursorResponse is the flat wire shape Cursor expects.
type cursorResponse struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

// FormatHookResponse emits the flat Cursor envelope. Cursor's contract is
// narrower than Claude's:
//
//   - allow → {"permission":"allow"} — explicit bypass of Cursor's own
//     permission UI. Empty stdout is NOT equivalent: Cursor treats empty as
//     "hook didn't decide" and falls back to its native confirmation prompt,
//     which reprompts on every invocation and makes yolonot's session-allow
//     memory invisible to the user. Verified live (2026-04-21).
//   - deny  → {"permission":"deny",…} flat envelope with user_message +
//     agent_message.
//   - ask   → explicit ask only with YOLONOT_CURSOR_NATIVE_ASK=1. Verified
//     IDE 3.24.18 and CLI 2026.10.14 prompt interactively; CLI --force
//     automatically permits asks. Compatibility mode defers to host policy.
//   - ""    → empty (no yolonot decision; retain host permissions).
func (c *CursorHarness) FormatHookResponse(r HookResponse) string {
	decision := r.HookSpecificOutput.PermissionDecision
	switch decision {
	case "":
		return ""
	case "ask":
		if !c.SupportsAsk() {
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
}

func (c *CursorHarness) IsInstalled() bool {
	s := c.loadHooks()
	hooks, _ := s["hooks"].(map[string]interface{})
	entries, _ := hooks["beforeShellExecution"].([]interface{})
	for _, entry := range entries {
		e, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		if cmd, ok := e["command"].(string); ok && strings.Contains(cmd, "yolonot") {
			return true
		}
	}
	return false
}

func (c *CursorHarness) Install(binaryPath string) error {
	s, err := c.readHooks()
	if err != nil {
		return err
	}
	stripCursorHooks(s)
	if _, ok := s["version"]; !ok {
		s["version"] = 1.0
	}
	hooks, _ := s["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = map[string]interface{}{}
		s["hooks"] = hooks
	}

	// Pin --harness cursor so ActiveHarness() routes through this adapter
	// regardless of any CLAUDE_SESSION_ID Cursor may emit for IDE-compat.
	bp := shellHookCommand(binaryPath, "cursor")
	entry := func() map[string]interface{} {
		return map[string]interface{}{"command": bp, "timeout": 60.0}
	}
	c.appendHookEntry(hooks, "beforeShellExecution", entry())
	c.appendHookEntry(hooks, "afterShellExecution", entry())

	if err := c.saveHooks(s); err != nil {
		return err
	}
	Verbosef("wrote %s (beforeShellExecution + afterShellExecution, timeout 60s)", c.SettingsPath())
	return nil
}

// appendHookEntry adds a flat Cursor hook entry under the given event,
// initialising the array if missing. Cursor's schema doesn't wrap entries
// in a {matcher, hooks: [...]} envelope, so we can't reuse addHookToEvent.
func (c *CursorHarness) appendHookEntry(hooks map[string]interface{}, event string, entry map[string]interface{}) {
	entries, _ := hooks[event].([]interface{})
	hooks[event] = append(entries, entry)
}

func (c *CursorHarness) Uninstall() error {
	Verbosef("stripping yolonot hooks from %s", c.SettingsPath())
	return c.removeHooks()
}

func cursorSkillDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cursor", "skills", "yolonot")
}

func (c *CursorHarness) InstallSkill() (string, error) {
	return installHarnessSkill(c.Name(), cursorSkillDir())
}

func (c *CursorHarness) UninstallSkill() error {
	return uninstallHarnessSkill(cursorSkillDir())
}

// PostInstallNotes surfaces the cursor-agent CLI compatibility, reload
// requirement, and the ask-not-enforced upstream limitation. Cursor's IDE
// reads hooks.json on agent start, so a running Cursor window needs a fresh
// chat/session for yolonot to take effect.
func (c *CursorHarness) PostInstallNotes() []string {
	notes := []string{
		"Restart Cursor (or start a new chat) so the agent re-reads ~/.cursor/hooks.json.",
		"The same hooks.json governs the `cursor-agent` CLI — no extra install step needed.",
	}
	if c.SupportsAsk() {
		return append(notes, "Native ask output is enabled via YOLONOT_CURSOR_NATIVE_ASK=1; verify a real approval prompt on your installed Cursor release.")
	}
	return append(notes, "Native ask output is disabled for compatibility with older Cursor releases. Verify prompting, then opt in with YOLONOT_CURSOR_NATIVE_ASK=1; deny rules remain hard blocks.")
}

// IsDetected returns true if ~/.cursor exists. Follows the Codex/Gemini
// convention: we don't create the dir speculatively.
func (c *CursorHarness) IsDetected() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(home, ".cursor"))
	return err == nil
}

func (c *CursorHarness) loadHooks() map[string]interface{} {
	s, _ := c.readHooks()
	if s == nil {
		return map[string]interface{}{}
	}
	return s
}

func (c *CursorHarness) readHooks() (map[string]interface{}, error) {
	data, err := os.ReadFile(c.SettingsPath())
	if os.IsNotExist(err) {
		return map[string]interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s map[string]interface{}
	if err := json.Unmarshal(data, &s); err != nil || s == nil {
		return nil, fmt.Errorf("%s: expected a valid JSON object", c.SettingsPath())
	}
	if err := uniqueJSONFields(data); err != nil {
		return nil, err
	}
	if value, exists := s["hooks"]; exists {
		hooks, ok := value.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s: hooks must be an object", c.SettingsPath())
		}
		for _, event := range []string{"beforeShellExecution", "afterShellExecution"} {
			if value, exists := hooks[event]; exists && value != nil {
				if _, ok := value.([]interface{}); !ok {
					return nil, fmt.Errorf("%s: hooks.%s must be an array", c.SettingsPath(), event)
				}
			}
		}
	}
	return s, nil
}

func (c *CursorHarness) saveHooks(s map[string]interface{}) error {
	data, _ := json.MarshalIndent(s, "", "  ")
	perm := os.FileMode(0600)
	if info, err := os.Stat(c.SettingsPath()); err == nil {
		perm = info.Mode().Perm()
	}
	return atomicWriteFile(c.SettingsPath(), append(data, '\n'), perm)
}

func (c *CursorHarness) removeHooks() error {
	s, err := c.readHooks()
	if err != nil {
		return err
	}
	stripCursorHooks(s)
	return c.saveHooks(s)
}

func stripCursorHooks(s map[string]interface{}) {
	hooks, _ := s["hooks"].(map[string]interface{})

	for _, event := range []string{"beforeShellExecution", "afterShellExecution"} {
		entries, _ := hooks[event].([]interface{})
		var remaining []interface{}
		for _, entry := range entries {
			e, ok := entry.(map[string]interface{})
			if !ok {
				remaining = append(remaining, entry)
				continue
			}
			if cmd, _ := e["command"].(string); strings.Contains(cmd, "yolonot") {
				continue
			}
			remaining = append(remaining, entry)
		}
		if len(remaining) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = remaining
		}
	}

}
