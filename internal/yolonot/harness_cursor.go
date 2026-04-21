package yolonot

import (
	"encoding/json"
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
//   - Stdout response is FLAT: {"permission":"allow|ask|deny","user_message":"...","agent_message":"..."}.
//     Schema accepts "ask" but Cursor does NOT enforce it — no TUI prompt
//     fires, and the hook is re-invoked before the user can respond, which
//     trips yolonot's asked-not-approved → session_deny heuristic. Verified
//     against Cursor docs ("ask is accepted by the schema but not enforced")
//     and live testing (2026-04-21). Treat Cursor as deny-only, same class
//     as Codex / OpenCode — FormatHookResponse collapses ask to empty
//     (passthrough) so Cursor's own permission UI handles moderate-risk
//     commands.
//   - Timeout is seconds (same as Claude, different from Gemini's ms).
//   - Session id arrives as `conversation_id` on stdin. No env export;
//     SessionIDFromEnv honours YOLONOT_CURSOR_SESSION_ID for user overrides.
type CursorHarness struct{}

func (c *CursorHarness) Name() string { return "cursor" }

// RiskMap matches the Codex pattern (see memory: cursor_ask_not_enforced).
// Cursor's schema accepts "ask" but does not surface a TUI prompt — the
// hook re-fires before the user can respond and session_deny pins the
// command as rejected. Moderate risk is therefore passthrough (Cursor's own
// permission UI takes over); high/critical escalate to deny.
func (c *CursorHarness) RiskMap() map[string]string {
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
	ConversationID string `json:"conversation_id"`
	HookEventName  string `json:"hook_event_name"`
	Cwd            string `json:"cwd"`
	Command        string `json:"command"`
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
	return HookPayload{
		HookEventName: event,
		ToolName:      "Bash",
		SessionID:     raw.ConversationID,
		Cwd:           raw.Cwd,
		ToolInput:     map[string]interface{}{"command": raw.Command},
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
//   - ask   → empty (passthrough). Cursor's schema accepts "ask" but never
//     surfaces a TUI prompt, and our asked-list bookkeeping pins the next
//     invocation as session_deny. Letting Cursor's own permission UI handle
//     moderate-risk commands is safer than silently denying. The risk map
//     sets moderate → passthrough, so ask should not reach the wire in
//     practice; if a rule forces ask, we still defer to Cursor rather than
//     rewriting to deny.
//   - ""    → empty (cmdHook silent mode, no decision to convey).
//
// This diverges from the earlier Cursor implementation, which assumed full
// 3-state parity based on the published schema. Live testing proved Cursor
// does not enforce ask AND does not honor "implicit allow"; we now match
// Codex/OpenCode semantics for ask/deny while still emitting explicit allow
// so session-approval memory actually bypasses Cursor's UI.
func (c *CursorHarness) FormatHookResponse(r HookResponse) string {
	decision := r.HookSpecificOutput.PermissionDecision
	switch decision {
	case "ask", "":
		return ""
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
	if c.IsInstalled() {
		Verbosef("existing install detected — removing old hooks from %s", c.SettingsPath())
		c.removeHooks()
	}

	s := c.loadHooks()
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
	bp := binaryPath + " hook --harness cursor"
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
	c.removeHooks()
	return nil
}

// InstallSkill / UninstallSkill are no-ops — Cursor has no skill concept.
func (c *CursorHarness) InstallSkill() (string, error) { return "", nil }
func (c *CursorHarness) UninstallSkill() error         { return nil }

// PostInstallNotes surfaces the cursor-agent CLI compatibility, reload
// requirement, and the ask-not-enforced upstream limitation. Cursor's IDE
// reads hooks.json on agent start, so a running Cursor window needs a fresh
// chat/session for yolonot to take effect.
func (c *CursorHarness) PostInstallNotes() []string {
	return []string{
		"Restart Cursor (or start a new chat) so the agent re-reads ~/.cursor/hooks.json.",
		"The same hooks.json governs the `cursor-agent` CLI — no extra install step needed.",
		"Cursor does not enforce hook 'ask' — yolonot 'ask' rules fall through to Cursor's own permission UI; use 'deny' rules for hard blocks.",
	}
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
	data, err := os.ReadFile(c.SettingsPath())
	if err != nil {
		return map[string]interface{}{}
	}
	var s map[string]interface{}
	json.Unmarshal(data, &s)
	if s == nil {
		s = map[string]interface{}{}
	}
	return s
}

func (c *CursorHarness) saveHooks(s map[string]interface{}) error {
	data, _ := json.MarshalIndent(s, "", "  ")
	return atomicWriteFile(c.SettingsPath(), append(data, '\n'), 0644)
}

func (c *CursorHarness) removeHooks() {
	s := c.loadHooks()
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

	c.saveHooks(s)
}
