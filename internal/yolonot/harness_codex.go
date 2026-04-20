package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func init() { RegisterHarness(&CodexHarness{}) }

// CodexHarness is the OpenAI Codex CLI adapter.
//
// Codex's hook protocol is a near-clone of Claude's: same stdin payload
// fields (session_id, hook_event_name, tool_name, tool_input.command,
// tool_response) and same response shape (hookSpecificOutput.hookEventName /
// permissionDecision / permissionDecisionReason). The canonical HookPayload
// / HookResponse pair therefore serializes verbatim — ParseHookInput and
// FormatHookResponse are passthroughs.
//
// Differences from Claude:
//   - Hooks live in ~/.codex/hooks.json (dedicated file, not a full settings
//     file). The JSON root is just {"hooks": {...}}.
//   - Codex does not expose a session-id env var; session IDs are only on
//     stdin. SessionIDFromEnv() returns the YOLONOT_CODEX_SESSION_ID
//     override if the user chooses to set one in their shell, otherwise
//     empty (CLI commands fall back to --current / --session-id).
//   - No skill concept — InstallSkill is a no-op.
type CodexHarness struct{}

func (c *CodexHarness) Name() string { return "codex" }

// RiskMap is Codex's default tier→action policy. Codex has no "ask"
// primitive (see memory: codex_ask_limitation) — so moderate is left to
// the host's own permission engine via passthrough, and high/critical
// escalate to deny. This replaces the old hardcoded ask→deny rewrite
// with an explicit, user-configurable policy.
func (c *CodexHarness) RiskMap() map[string]string {
	return map[string]string{
		RiskSafe:     ActionAllow,
		RiskLow:      ActionAllow,
		RiskModerate: ActionPassthrough,
		RiskHigh:     ActionDeny,
		RiskCritical: ActionDeny,
	}
}

func (c *CodexHarness) SettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".codex", "hooks.json")
}

// SessionIDFromEnv honours the optional YOLONOT_CODEX_SESSION_ID shell
// override. Codex itself does not export its session id (see
// github.com/openai/codex#8923), so auto-detecting "the active harness is
// Codex" from env is unreliable — users set YOLONOT_HARNESS=codex instead.
func (c *CodexHarness) SessionIDFromEnv() string {
	return os.Getenv("YOLONOT_CODEX_SESSION_ID")
}

func (c *CodexHarness) ParseHookInput(input []byte) (HookPayload, error) {
	if len(input) == 0 {
		return HookPayload{}, nil
	}
	var p HookPayload
	if err := json.Unmarshal(input, &p); err != nil {
		return HookPayload{}, err
	}
	return p, nil
}

// FormatHookResponse serialises a canonical HookResponse into the shape
// Codex's PreToolUse hook accepts. Codex's contract is narrower than
// Claude's: only `permissionDecision: "deny"` is valid.
//
//   - allow → empty output (implicit pass; Codex rejects "allow")
//   - deny  → passthrough
//   - ask   → empty (passthrough to host). The risk map is now responsible
//     for deciding whether ambiguous commands escalate to deny or fall
//     through; Codex's default map sets high/critical → deny and moderate
//     → passthrough, so ask should not reach the wire in practice. If a
//     user forces ask via config override, we defer to Codex's own engine
//     rather than silently rewriting to deny.
//
// This diverges from ClaudeHarness.FormatHookResponse (which emits all
// three verbatim) — Claude's PreToolUse accepts all three.
func (c *CodexHarness) FormatHookResponse(r HookResponse) string {
	switch r.HookSpecificOutput.PermissionDecision {
	case "allow", "ask", "":
		return ""
	}
	data, _ := json.Marshal(r)
	return string(data)
}

func (c *CodexHarness) IsInstalled() bool {
	s := c.loadHooks()
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

func (c *CodexHarness) Install(binaryPath string) error {
	if c.IsInstalled() {
		Verbosef("existing install detected — removing old hooks from %s", c.SettingsPath())
		c.removeHooks()
	}

	s := c.loadHooks()
	hooks, _ := s["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = map[string]interface{}{}
		s["hooks"] = hooks
	}

	// Pin --harness codex so the hook routes through CodexHarness.Format,
	// not Claude's (default when no harness env var is set — Codex doesn't
	// export CODEX_SESSION_ID, so auto-detection would otherwise pick claude
	// and emit permissionDecision:"allow", which Codex rejects).
	bp := binaryPath + " hook --harness codex"
	preHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 60.0}
	postHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 60.0}

	addHookToEvent(hooks, "PreToolUse", "Bash", preHook)
	addHookToEvent(hooks, "PostToolUse", "Bash", postHook)

	if err := c.saveHooks(s); err != nil {
		return err
	}
	Verbosef("wrote %s (Bash matcher for PreToolUse + PostToolUse, timeout 60s)", c.SettingsPath())

	// Codex hooks are gated behind [features] codex_hooks = true in
	// config.toml. Writing hooks.json alone is silently a no-op without it,
	// so enable the flag at install time — idempotent, preserves anything
	// else in the file.
	if err := c.ensureFeatureFlag(); err != nil {
		Verbosef("could not enable codex_hooks feature flag: %v", err)
	}
	return nil
}

// ensureFeatureFlag appends `[features] codex_hooks = true` to
// ~/.codex/config.toml if it isn't already present. Uses plain string
// append rather than a TOML parser so we don't rewrite user formatting.
func (c *CodexHarness) ensureFeatureFlag() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".codex", "config.toml")
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if strings.Contains(string(data), "codex_hooks") {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	block := "\n[features]\ncodex_hooks = true\n"
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		block = "\n" + block
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(block); err != nil {
		return err
	}
	Verbosef("enabled [features] codex_hooks = true in %s", path)
	return nil
}

func (c *CodexHarness) Uninstall() error {
	Verbosef("stripping yolonot hooks from %s", c.SettingsPath())
	c.removeHooks()
	return nil
}

// InstallSkill is a no-op — Codex has no skill concept.
func (c *CodexHarness) InstallSkill() (string, error) { return "", nil }
func (c *CodexHarness) UninstallSkill() error         { return nil }

// PostInstallNotes documents Codex's ask-primitive limitation. The
// canonical yolonot model has three decisions (allow/ask/deny) but
// Codex's hook protocol only honours deny — "ask" is surfaced as
// passthrough, letting Codex's own permission engine decide. Users
// porting an existing Claude .yolonot with ask rules need to know this.
func (c *CodexHarness) PostInstallNotes() []string {
	return []string{
		"Codex has no 'ask' hook primitive — yolonot 'ask' rules fall through to Codex's own permission prompt.",
		"Use 'allow' and 'deny' rules for deterministic behaviour; see 'yolonot risk codex' for the default risk map.",
		"Codex hooks require [features] codex_hooks = true in ~/.codex/config.toml (yolonot install enables this automatically).",
	}
}

// IsDetected returns true if ~/.codex exists. Unlike Claude, we don't
// optimistically create the dir — if a user hasn't installed Codex yet,
// we shouldn't pick it as the default install target.
func (c *CodexHarness) IsDetected() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(home, ".codex"))
	return err == nil
}

func (c *CodexHarness) loadHooks() map[string]interface{} {
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

func (c *CodexHarness) saveHooks(s map[string]interface{}) error {
	path := c.SettingsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func (c *CodexHarness) removeHooks() {
	s := c.loadHooks()
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

	c.saveHooks(s)
}
