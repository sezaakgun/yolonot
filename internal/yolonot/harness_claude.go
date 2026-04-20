package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() { RegisterHarness(&ClaudeHarness{}) }

// PostInstallNotes has nothing to surface for Claude — the canonical
// hook shape maps 1:1, so there are no caveats.
func (c *ClaudeHarness) PostInstallNotes() []string { return nil }

// ClaudeHarness is the Claude Code adapter. It is the historical default
// and the canonical hook protocol — HookPayload / HookResponse are shaped
// after Claude's JSON, so Parse/Format are near-passthrough.
type ClaudeHarness struct{}

func (c *ClaudeHarness) Name() string { return "claude" }

// RiskMap is Claude's default tier→action policy. Claude has a real "ask"
// primitive (TUI approval prompt), so every non-allow tier escalates to
// ask — deny stays rule-origin only. An LLM-emitted "critical" should
// stop the command for user review, not kill it silently; if the user
// wants hard denial they write a rule.
func (c *ClaudeHarness) RiskMap() map[string]string {
	return map[string]string{
		RiskSafe:     ActionAllow,
		RiskLow:      ActionAllow,
		RiskModerate: ActionAsk,
		RiskHigh:     ActionAsk,
		RiskCritical: ActionAsk,
	}
}

func (c *ClaudeHarness) SettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "settings.json")
}

func (c *ClaudeHarness) SessionIDFromEnv() string {
	return os.Getenv("CLAUDE_SESSION_ID")
}

// ParseHookInput decodes Claude's hook JSON. If stdin is empty, falls back
// to CLAUDE_TOOL_INPUT + peer env vars (legacy invocation path).
func (c *ClaudeHarness) ParseHookInput(input []byte) (HookPayload, error) {
	if len(input) == 0 {
		if toolInput := os.Getenv("CLAUDE_TOOL_INPUT"); toolInput != "" {
			input = []byte(fmt.Sprintf(
				`{"hook_event_name":"%s","tool_name":"%s","session_id":"%s","tool_input":%s}`,
				envOr("CLAUDE_HOOK_EVENT_NAME", "PreToolUse"),
				envOr("CLAUDE_TOOL_NAME", "Bash"),
				envOr("CLAUDE_SESSION_ID", "unknown"),
				toolInput))
		}
	}
	if len(input) == 0 {
		return HookPayload{}, nil
	}
	var p HookPayload
	if err := json.Unmarshal(input, &p); err != nil {
		return HookPayload{}, err
	}
	return p, nil
}

// FormatHookResponse serialises the canonical HookResponse. Claude's
// protocol is identical to the canonical shape, so this is a JSON marshal.
func (c *ClaudeHarness) FormatHookResponse(r HookResponse) string {
	data, _ := json.Marshal(r)
	return string(data)
}

func (c *ClaudeHarness) IsInstalled() bool {
	s := c.loadSettings()
	hooks, _ := s["hooks"].(map[string]interface{})
	pre, _ := hooks["PreToolUse"].([]interface{})
	for _, entry := range pre {
		e, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		hs, _ := e["hooks"].([]interface{})
		for _, h := range hs {
			hm, ok := h.(map[string]interface{})
			if !ok {
				continue
			}
			if cmd, ok := hm["command"].(string); ok && strings.Contains(cmd, "yolonot") {
				return true
			}
		}
	}
	return false
}

func (c *ClaudeHarness) Install(binaryPath string) error {
	if c.IsInstalled() {
		Verbosef("existing install detected — removing old hooks from %s", c.SettingsPath())
		c.removeHooks()
	}

	s := c.loadSettings()
	hooks, _ := s["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = map[string]interface{}{}
		s["hooks"] = hooks
	}

	bp := binaryPath + " hook"
	preHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 60.0}
	postHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 60.0}

	addHookToEvent(hooks, "PreToolUse", "Bash", preHook)
	addHookToEvent(hooks, "PostToolUse", "Bash", postHook)

	c.saveSettings(s)
	Verbosef("wrote %s (Bash matcher for PreToolUse + PostToolUse, timeout 60s)", c.SettingsPath())
	return nil
}

func (c *ClaudeHarness) Uninstall() error {
	Verbosef("stripping yolonot hooks from %s", c.SettingsPath())
	c.removeHooks()
	return nil
}

func (c *ClaudeHarness) InstallSkill() (string, error) {
	home, _ := os.UserHomeDir()
	skillDir := filepath.Join(home, ".claude", "skills", "yolonot")
	skillDst := filepath.Join(skillDir, "SKILL.md")
	if err := os.MkdirAll(skillDir, 0755); err != nil {
		return "", err
	}
	if err := os.WriteFile(skillDst, embeddedSkillMD, 0644); err != nil {
		return "", err
	}
	Verbosef("wrote SKILL.md to %s (%d bytes)", skillDst, len(embeddedSkillMD))
	return skillDir, nil
}

func (c *ClaudeHarness) UninstallSkill() error {
	home, _ := os.UserHomeDir()
	skillDir := filepath.Join(home, ".claude", "skills", "yolonot")
	Verbosef("removing skill dir %s", skillDir)
	return os.RemoveAll(skillDir)
}

// IsDetected returns true unless $HOME can't be resolved. Claude is the
// default target — we assume the user wants it installed even if the
// .claude directory doesn't exist yet (Install creates it).
func (c *ClaudeHarness) IsDetected() bool {
	_, err := os.UserHomeDir()
	return err == nil
}

func (c *ClaudeHarness) loadSettings() map[string]interface{} {
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

func (c *ClaudeHarness) saveSettings(s map[string]interface{}) {
	data, _ := json.MarshalIndent(s, "", "  ")
	// atomicWriteFile rejects symlinks at the target and renames over a
	// same-dir temp, preventing a TOCTOU symlink in ~/.claude/ from
	// redirecting our write elsewhere. See atomicwrite.go.
	atomicWriteFile(c.SettingsPath(), append(data, '\n'), 0644)
}

func (c *ClaudeHarness) removeHooks() {
	s := c.loadSettings()
	hooks, _ := s["hooks"].(map[string]interface{})

	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		entries, _ := hooks[event].([]interface{})
		var newEntries []interface{}
		for _, entry := range entries {
			e, ok := entry.(map[string]interface{})
			if !ok {
				continue
			}
			hs, _ := e["hooks"].([]interface{})
			var remaining []interface{}
			for _, h := range hs {
				if hm, ok := h.(map[string]interface{}); ok {
					if cmd, _ := hm["command"].(string); strings.Contains(cmd, "yolonot") {
						continue
					}
				}
				remaining = append(remaining, h)
			}
			if len(remaining) > 0 {
				e["hooks"] = remaining
				newEntries = append(newEntries, e)
			}
		}
		hooks[event] = newEntries
	}

	c.saveSettings(s)
}

// --- Package-level helpers kept for back-compat with existing tests ---
//
// Pre-refactor, tests reached for `loadSettings()` / `settingsPath()` as
// package globals. These wrappers delegate to the Claude adapter so the
// test surface doesn't change.

func claudeAdapter() *ClaudeHarness {
	if h, ok := GetHarness("claude").(*ClaudeHarness); ok {
		return h
	}
	return &ClaudeHarness{}
}

func settingsPath() string              { return claudeAdapter().SettingsPath() }
func loadSettings() map[string]interface{} { return claudeAdapter().loadSettings() }
func saveSettings(s map[string]interface{}) { claudeAdapter().saveSettings(s) }
func removeHooks()                       { claudeAdapter().removeHooks() }

// binaryPath returns the path to the running yolonot executable. Used by
// Install() to register the hook command.
func binaryPath() string {
	exe, _ := os.Executable()
	return exe
}

// addHookToEvent inserts a hook into Claude's settings.json "hooks" map
// under the given event + matcher. Placed before any ".*" catch-all so
// yolonot's pre-check runs first.
//
// Exposed at package scope because it mutates the generic map Claude uses —
// keeping it outside the struct lets tests that construct a raw map
// exercise the ordering logic directly.
func addHookToEvent(hooks map[string]interface{}, event, matcher string, hook map[string]interface{}) {
	entries, _ := hooks[event].([]interface{})

	for _, entry := range entries {
		if e, ok := entry.(map[string]interface{}); ok {
			if m, _ := e["matcher"].(string); m == matcher {
				hs, _ := e["hooks"].([]interface{})
				e["hooks"] = append(hs, hook)
				return
			}
		}
	}

	newEntry := map[string]interface{}{
		"matcher": matcher,
		"hooks":   []interface{}{hook},
	}
	insertIdx := len(entries)
	for i, entry := range entries {
		if e, ok := entry.(map[string]interface{}); ok {
			if m, _ := e["matcher"].(string); m == ".*" {
				insertIdx = i
				break
			}
		}
	}
	entries = append(entries, nil)
	copy(entries[insertIdx+1:], entries[insertIdx:])
	entries[insertIdx] = newEntry
	hooks[event] = entries
}
