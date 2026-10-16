package yolonot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

func init() { RegisterHarness(&CodexHarness{}) }

// CodexHarness is the OpenAI Codex CLI adapter.
//
// Codex's hook protocol is a near-clone of Claude's: same stdin payload
// fields (session_id, hook_event_name, tool_name, tool_input.command,
// tool_response) and same response shape (hookSpecificOutput.hookEventName /
// permissionDecision / permissionDecisionReason). The canonical HookPayload
// / HookResponse pair therefore shares the canonical payload, with response
// decisions narrowed to the PreToolUse contract below.
//
// Differences from Claude:
//   - Hooks live in ~/.codex/hooks.json (dedicated file, not a full settings
//     file). The JSON root is just {"hooks": {...}}.
//   - Codex does not expose a session-id env var; session IDs are only on
//     stdin. SessionIDFromEnv() returns the YOLONOT_CODEX_SESSION_ID
//     override if the user chooses to set one in their shell, otherwise
//     empty (CLI commands fall back to --current / --session-id).
//   - PermissionRequest approves host requests separately from PreToolUse.
type CodexHarness struct{}

func (c *CodexHarness) Name() string { return "codex" }

// RiskMap is Codex's default tier→action policy. Its PreToolUse hook has no
// "ask" primitive, so moderate is left to
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
	return filepath.Join(codexConfigDir(), "hooks.json")
}

func codexConfigDir() string {
	if dir := os.Getenv("CODEX_HOME"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".codex")
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

// FormatHookResponse emits explicit denies through PreToolUse and uses
// PermissionRequest's separate decision object to approve or deny an
// actual host permission request.
//
//   - allow → empty output (defer to host)
//   - deny  → explicit canonical response
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
	if r.HookSpecificOutput.HookEventName == "PermissionRequest" {
		decision := r.HookSpecificOutput.PermissionDecision
		if decision != "allow" && decision != "deny" {
			return ""
		}
		verdict := map[string]string{"behavior": decision}
		if decision == "deny" && r.HookSpecificOutput.PermissionDecisionReason != "" {
			verdict["message"] = r.HookSpecificOutput.PermissionDecisionReason
		}
		data, _ := json.Marshal(map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
			"hookEventName": "PermissionRequest", "decision": verdict,
		}})
		return string(data)
	}
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
	if _, err := c.readHooks(); err != nil {
		return err
	}
	// Validate and enable hooks before changing their registration. In
	// particular, an invalid config must not turn into a successful install.
	if err := c.ensureFeatureFlag(); err != nil {
		return fmt.Errorf("enable Codex hooks: %w", err)
	}
	if c.IsInstalled() {
		Verbosef("existing install detected — removing old hooks from %s", c.SettingsPath())
		if err := c.removeHooks(); err != nil {
			return err
		}
	}

	s, err := c.readHooks()
	if err != nil {
		return err
	}
	hooks, _ := s["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = map[string]interface{}{}
		s["hooks"] = hooks
	}

	// Pin --harness codex so the hook routes through CodexHarness.Format,
	// not Claude's (default when no harness env var is set — Codex doesn't
	// export CODEX_SESSION_ID, so auto-detection would otherwise pick claude
	// and emit permissionDecision:"allow", which Codex rejects).
	bp := shellHookCommand(binaryPath, "codex")
	preHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 60.0}
	postHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 60.0}

	addHookToEvent(hooks, "PreToolUse", "Bash", preHook)
	addHookToEvent(hooks, "PermissionRequest", "Bash", preHook)
	addHookToEvent(hooks, "PostToolUse", "Bash", postHook)

	if err := c.saveHooks(s); err != nil {
		return err
	}
	Verbosef("wrote %s (Bash matcher for PreToolUse + PermissionRequest + PostToolUse, timeout 60s)", c.SettingsPath())

	return nil
}

// ensureFeatureFlag enables canonical hooks and migrates its deprecated
// codex_hooks alias. Surgical edits
// preserve comments and unrelated settings; parsing before and after refuses
// invalid TOML rather than appending a duplicate [features] table.
func (c *CodexHarness) ensureFeatureFlag() error {
	path := filepath.Join(codexConfigDir(), "config.toml")
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	updated, err := enableCodexHookFlags(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if bytes.Equal(updated, data) {
		return nil
	}
	perm := os.FileMode(0600)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	if err := atomicWriteFile(path, updated, perm); err != nil {
		return err
	}
	Verbosef("enabled Codex hooks in %s", path)
	return nil
}

func enableCodexHookFlags(data []byte) ([]byte, error) {
	var config map[string]interface{}
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("invalid TOML: %w", err)
	}
	features, ok := config["features"].(map[string]interface{})
	if _, exists := config["features"]; exists && !ok {
		return nil, fmt.Errorf("features must be a table")
	}
	hasFlag := false
	for _, key := range []string{"hooks", "codex_hooks"} {
		if value, exists := features[key]; exists {
			if _, ok := value.(bool); !ok {
				return nil, fmt.Errorf("features.%s must be a boolean", key)
			}
			hasFlag = true
		}
	}
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	var parser unstable.Parser
	var table []string
	featureHeaderEnd, inlineStart := -1, -1
	inlineNonempty := false
	keys := func(n *unstable.Node) []string {
		var parts []string
		it := n.Key()
		for it.Next() {
			parts = append(parts, string(it.Node().Data))
		}
		return parts
	}
	var visit func(*unstable.Node, []string, bool)
	visit = func(n *unstable.Node, prefix []string, inline bool) {
		path := append(append([]string{}, prefix...), keys(n)...)
		value := n.Value()
		legacy := len(path) == 2 && path[0] == "features" && path[1] == "codex_hooks"
		_, canonicalExists := features["hooks"]
		if legacy {
			it := n.Key()
			var first, last *unstable.Node
			for it.Next() {
				last = it.Node()
				if first == nil {
					first = last
				}
			}
			if !canonicalExists {
				start, length := int(last.Raw.Offset), int(last.Raw.Length)
				key := "hooks"
				if data[start] == '\'' {
					key = "'hooks'"
				}
				if data[start] == '"' {
					key = "\"hooks\""
				}
				edits = append(edits, edit{start, start + length, key})
			} else {
				span := parser.Range(value.Data)
				start, end := int(first.Raw.Offset), int(span.Offset+span.Length)
				if inline {
					// Remove this entry and one adjacent comma, preserving
					// every other inline-table field and its formatting.
					right := end
					for right < len(data) && strings.ContainsRune(" \t\r\n", rune(data[right])) {
						right++
					}
					if right < len(data) && data[right] == ',' {
						end = right + 1
					} else {
						left := start - 1
						for left >= 0 && strings.ContainsRune(" \t\r\n", rune(data[left])) {
							left--
						}
						if left < 0 || data[left] != ',' {
							return
						}
						start = left
					}
					edits = append(edits, edit{start, end, ""})
				} else {
					// Keep the old line/comment as an inert migration note.
					edits = append(edits, edit{start, end, "# deprecated alias: " + string(data[start:end])})
				}
			}
		}
		if len(path) == 2 && path[0] == "features" && (path[1] == "hooks" || (legacy && !canonicalExists)) && string(value.Data) == "false" {
			span := parser.Range(value.Data)
			start := int(span.Offset)
			edits = append(edits, edit{start, start + int(span.Length), "true"})
		}
		if value.Kind == unstable.InlineTable {
			children := value.Children()
			if len(path) == 1 && path[0] == "features" {
				inlineStart = int(value.Raw.Offset) + 1 // immediately after {
				inlineNonempty = value.Child() != nil
			}
			for children.Next() {
				visit(children.Node(), path, true)
			}
		}
	}
	parser.Reset(data)
	for parser.NextExpression() {
		n := parser.Expression()
		switch n.Kind {
		case unstable.Table, unstable.ArrayTable:
			table = keys(n)
			if n.Kind == unstable.Table && len(table) == 1 && table[0] == "features" {
				it := n.Key()
				it.Next()
				start := int(it.Node().Raw.Offset)
				featureHeaderEnd = len(data)
				if end := bytes.IndexByte(data[start:], '\n'); end >= 0 {
					featureHeaderEnd = start + end + 1
				}
			}
		case unstable.KeyValue:
			visit(n, table, false)
		}
	}
	if err := parser.Error(); err != nil {
		return nil, err
	}
	if !hasFlag {
		newline := "\n"
		if bytes.Contains(data, []byte("\r\n")) {
			newline = "\r\n"
		}
		switch {
		case inlineStart >= 0:
			text := "hooks = true"
			if inlineNonempty {
				text += ", "
			}
			edits = append(edits, edit{inlineStart, inlineStart, text})
		case featureHeaderEnd >= 0:
			text := "hooks = true" + newline
			if featureHeaderEnd > 0 && data[featureHeaderEnd-1] != '\n' {
				text = newline + text
			}
			edits = append(edits, edit{featureHeaderEnd, featureHeaderEnd, text})
		case features != nil:
			// A dotted key or child table can define features without an
			// explicit [features] header. A root dotted key extends it safely.
			edits = append(edits, edit{0, 0, "features.hooks = true" + newline})
		default:
			text := "[features]" + newline + "hooks = true" + newline
			if len(data) > 0 && data[len(data)-1] != '\n' {
				text = newline + text
			}
			edits = append(edits, edit{len(data), len(data), text})
		}
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	updated := append([]byte{}, data...)
	for _, e := range edits {
		updated = append(append(append([]byte{}, updated[:e.start]...), e.text...), updated[e.end:]...)
	}
	var verified map[string]interface{}
	if err := toml.Unmarshal(updated, &verified); err != nil {
		return nil, fmt.Errorf("cannot safely enable hooks: %w", err)
	}
	flags, _ := verified["features"].(map[string]interface{})
	if _, exists := flags["codex_hooks"]; exists {
		return nil, fmt.Errorf("cannot safely migrate deprecated features.codex_hooks")
	}
	if flags["hooks"] != true {
		return nil, fmt.Errorf("cannot safely enable features.hooks")
	}
	return updated, nil
}

func (c *CodexHarness) Uninstall() error {
	Verbosef("stripping yolonot hooks from %s", c.SettingsPath())
	return c.removeHooks()
}

func (c *CodexHarness) InstallSkill() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return installHarnessSkill("codex", filepath.Join(home, ".agents", "skills", "yolonot"))
}
func (c *CodexHarness) UninstallSkill() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return uninstallHarnessSkill(filepath.Join(home, ".agents", "skills", "yolonot"))
}

// PostInstallNotes documents this adapter's enforcement capabilities.
// The PreToolUse integration only emits deny — "ask" is surfaced as
// passthrough, letting Codex's own permission engine decide. Users
// porting an existing Claude .yolonot with ask rules need to know this.
func (c *CodexHarness) PostInstallNotes() []string {
	return []string{
		"PreToolUse blocks deny decisions; PermissionRequest approves allowed requests and leaves ask decisions to Codex's own permission dialog.",
		"Use 'deny' rules for hard blocks; see 'yolonot risk codex' for the default risk map.",
		"Review and trust the installed hooks in Codex /hooks; changed non-managed hooks are skipped until trusted.",
		"yolonot install enables features.hooks in Codex config.toml (CODEX_HOME is supported).",
	}
}

// IsDetected returns true if ~/.codex exists. Unlike Claude, we don't
// optimistically create the dir — if a user hasn't installed Codex yet,
// we shouldn't pick it as the default install target.
func (c *CodexHarness) IsDetected() bool {
	_, err := os.Stat(codexConfigDir())
	return err == nil
}

func (c *CodexHarness) loadHooks() map[string]interface{} {
	s, _ := c.readHooks()
	if s == nil {
		return map[string]interface{}{}
	}
	return s
}

func (c *CodexHarness) readHooks() (map[string]interface{}, error) {
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
	if hooks, present := s["hooks"]; present {
		if _, ok := hooks.(map[string]interface{}); !ok {
			return nil, fmt.Errorf("%s: hooks must be an object", c.SettingsPath())
		}
	}
	return s, nil
}

func (c *CodexHarness) saveHooks(s map[string]interface{}) error {
	data, _ := json.MarshalIndent(s, "", "  ")
	return atomicWriteFile(c.SettingsPath(), append(data, '\n'), 0644)
}

func (c *CodexHarness) removeHooks() error {
	s, err := c.readHooks()
	if err != nil {
		return err
	}
	hooks, _ := s["hooks"].(map[string]interface{})

	for _, event := range []string{"PreToolUse", "PermissionRequest", "PostToolUse"} {
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
		if len(newEntries) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = newEntries
		}
	}

	return c.saveHooks(s)
}
