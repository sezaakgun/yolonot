package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests lock the Claude adapter's behavior so the harness-abstraction
// refactor (and future non-Claude adapters) cannot regress Claude Code.

func TestClaudeHarnessRegistered(t *testing.T) {
	if h := GetHarness("claude"); h == nil {
		t.Fatal("claude harness not registered")
	}
}

func TestClaudeHarnessName(t *testing.T) {
	h := &ClaudeHarness{}
	if h.Name() != "claude" {
		t.Errorf("Name() = %s, want claude", h.Name())
	}
}

func TestClaudeHarnessSettingsPath(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")

	h := &ClaudeHarness{}
	want := filepath.Join(dir, ".claude", "settings.json")
	if got := h.SettingsPath(); got != want {
		t.Errorf("SettingsPath() = %s, want %s", got, want)
	}
}

func TestClaudeHarnessSessionIDFromEnv(t *testing.T) {
	os.Setenv("CLAUDE_SESSION_ID", "sid-123")
	defer os.Unsetenv("CLAUDE_SESSION_ID")

	h := &ClaudeHarness{}
	if got := h.SessionIDFromEnv(); got != "sid-123" {
		t.Errorf("SessionIDFromEnv() = %s, want sid-123", got)
	}
}

func TestClaudeHarnessParseHookInputStdin(t *testing.T) {
	h := &ClaudeHarness{}
	raw := `{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"sid","cwd":"/tmp","tool_input":{"command":"ls"}}`
	p, err := h.ParseHookInput([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if p.HookEventName != "PreToolUse" || p.SessionID != "sid" {
		t.Errorf("parsed = %+v", p)
	}
	if cmd, _ := p.ToolInput["command"].(string); cmd != "ls" {
		t.Errorf("command = %q, want ls", cmd)
	}
}

func TestClaudeHarnessParseHookInputEnvFallback(t *testing.T) {
	os.Setenv("CLAUDE_TOOL_INPUT", `{"command":"echo hi"}`)
	os.Setenv("CLAUDE_HOOK_EVENT_NAME", "PreToolUse")
	os.Setenv("CLAUDE_TOOL_NAME", "Bash")
	os.Setenv("CLAUDE_SESSION_ID", "env-sid")
	defer func() {
		os.Unsetenv("CLAUDE_TOOL_INPUT")
		os.Unsetenv("CLAUDE_HOOK_EVENT_NAME")
		os.Unsetenv("CLAUDE_TOOL_NAME")
		os.Unsetenv("CLAUDE_SESSION_ID")
	}()

	h := &ClaudeHarness{}
	p, err := h.ParseHookInput(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.HookEventName != "PreToolUse" || p.SessionID != "env-sid" {
		t.Errorf("env fallback parsed = %+v", p)
	}
	if cmd, _ := p.ToolInput["command"].(string); cmd != "echo hi" {
		t.Errorf("env fallback command = %q, want echo hi", cmd)
	}
}

func TestClaudeHarnessParseHookInputEmpty(t *testing.T) {
	os.Unsetenv("CLAUDE_TOOL_INPUT")
	h := &ClaudeHarness{}
	p, err := h.ParseHookInput(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.HookEventName != "" {
		t.Errorf("empty parse should be zero, got %+v", p)
	}
}

func TestClaudeHarnessParseHookInputInvalidJSON(t *testing.T) {
	// Malformed stdin must surface as an error so the pipeline aborts
	// rather than silently skipping via the zero-payload guard.
	h := &ClaudeHarness{}
	if _, err := h.ParseHookInput([]byte("{not json")); err == nil {
		t.Fatal("ParseHookInput on malformed JSON must return error, got nil")
	}
}

func TestClaudeHarnessFormatHookResponseRoundTrip(t *testing.T) {
	h := &ClaudeHarness{}
	r := HookResponse{}
	r.HookSpecificOutput.HookEventName = "PreToolUse"
	r.HookSpecificOutput.PermissionDecision = "allow"
	r.HookSpecificOutput.PermissionDecisionReason = "ok"

	out := h.FormatHookResponse(r)
	var decoded HookResponse
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("round trip failed: %v (output=%s)", err, out)
	}
	if decoded.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("round trip decision = %q", decoded.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeHarnessInstallUninstall(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")
	os.MkdirAll(filepath.Join(dir, ".claude"), 0755)

	h := &ClaudeHarness{}
	if h.IsInstalled() {
		t.Fatal("should not be installed initially")
	}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}
	if !h.IsInstalled() {
		t.Fatal("should be installed after Install()")
	}

	data, err := os.ReadFile(h.SettingsPath())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "yolonot") {
		t.Errorf("settings missing yolonot: %s", s)
	}
	if !strings.Contains(s, "PreToolUse") || !strings.Contains(s, "PostToolUse") {
		t.Errorf("settings missing hook events: %s", s)
	}
	if !strings.Contains(s, `"matcher": "Bash"`) {
		t.Errorf("settings missing Bash matcher: %s", s)
	}

	if err := h.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if h.IsInstalled() {
		t.Fatal("should not be installed after Uninstall()")
	}
}

func TestClaudeHarnessInstallSkill(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")

	h := &ClaudeHarness{}
	path, err := h.InstallSkill()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, filepath.Join(".claude", "skills", "yolonot")) {
		t.Errorf("skill dir = %s", path)
	}
	if _, err := os.Stat(filepath.Join(path, "SKILL.md")); err != nil {
		t.Errorf("SKILL.md missing: %v", err)
	}

	if err := h.UninstallSkill(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("skill dir still exists after UninstallSkill: %v", err)
	}
}

func TestClaudeHarnessIsDetected(t *testing.T) {
	os.Setenv("HOME", t.TempDir())
	defer os.Unsetenv("HOME")

	h := &ClaudeHarness{}
	if !h.IsDetected() {
		t.Error("claude harness should always be detected when HOME resolves")
	}
}

func TestActiveHarnessDefaultsToClaude(t *testing.T) {
	os.Unsetenv("YOLONOT_HARNESS")
	os.Unsetenv("CLAUDE_SESSION_ID")

	h := ActiveHarness()
	if h == nil || h.Name() != "claude" {
		t.Errorf("ActiveHarness() = %v, want claude", h)
	}
}

func TestActiveHarnessHonoursEnvOverride(t *testing.T) {
	os.Setenv("YOLONOT_HARNESS", "claude")
	defer os.Unsetenv("YOLONOT_HARNESS")

	h := ActiveHarness()
	if h == nil || h.Name() != "claude" {
		t.Errorf("ActiveHarness() = %v, want claude", h)
	}
}

func TestActiveHarnessHonoursUnknownOverride(t *testing.T) {
	os.Setenv("YOLONOT_HARNESS", "nonexistent")
	defer os.Unsetenv("YOLONOT_HARNESS")
	os.Unsetenv("CLAUDE_SESSION_ID")

	// Unknown name falls through to session-id detection / claude default.
	h := ActiveHarness()
	if h == nil || h.Name() != "claude" {
		t.Errorf("ActiveHarness() = %v, want claude fallback", h)
	}
}

func TestGetSessionIDFromEnvClaudeOnly(t *testing.T) {
	os.Setenv("CLAUDE_SESSION_ID", "claude-sid")
	defer os.Unsetenv("CLAUDE_SESSION_ID")
	if got := GetSessionIDFromEnv(); got != "claude-sid" {
		t.Errorf("GetSessionIDFromEnv() = %s, want claude-sid", got)
	}
}

// TestCmdHookRoutesThroughActiveHarness exercises the full cmdHook pipeline
// for each non-Claude harness, pinned via YOLONOT_HARNESS. A deny-rule
// short-circuits before any LLM call — the only thing varying across the
// table is the wire-shape of stdout. Guards against regressions that
// bypass the adapter (e.g. hook.go hardcoded json.Marshal on error paths).
func TestCmdHookRoutesThroughActiveHarness(t *testing.T) {
	cases := []struct {
		name   string
		assert func(t *testing.T, out string)
	}{
		{
			name: "codex",
			assert: func(t *testing.T, out string) {
				// Codex: deny is the canonical Claude shape.
				var r HookResponse
				if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &r); err != nil {
					t.Fatalf("codex deny output not JSON: %q (err=%v)", out, err)
				}
				if r.HookSpecificOutput.PermissionDecision != "deny" {
					t.Errorf("codex decision = %q", r.HookSpecificOutput.PermissionDecision)
				}
			},
		},
		{
			name: "opencode",
			assert: func(t *testing.T, out string) {
				// OpenCode: same canonical shape (plugin parses
				// hookSpecificOutput.permissionDecision).
				var r HookResponse
				if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &r); err != nil {
					t.Fatalf("opencode deny output not JSON: %q (err=%v)", out, err)
				}
				if r.HookSpecificOutput.PermissionDecision != "deny" {
					t.Errorf("opencode decision = %q", r.HookSpecificOutput.PermissionDecision)
				}
			},
		},
		{
			name: "gemini",
			assert: func(t *testing.T, out string) {
				// Gemini: flat envelope {decision, reason, systemMessage}.
				var flat struct {
					Decision string `json:"decision"`
					Reason   string `json:"reason"`
				}
				if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &flat); err != nil {
					t.Fatalf("gemini deny output not JSON: %q (err=%v)", out, err)
				}
				if flat.Decision != "deny" {
					t.Errorf("gemini decision = %q", flat.Decision)
				}
				// Gemini's flat shape must NOT wrap the decision in
				// hookSpecificOutput — Gemini's scheduler fails open on that.
				if strings.Contains(out, "hookSpecificOutput") {
					t.Errorf("gemini output leaked Claude envelope: %s", out)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, cleanup := withFakeHome(t)
			defer cleanup()

			// Global deny rule short-circuits before any LLM call.
			os.WriteFile(filepath.Join(home, ".yolonot", "rules"), []byte("deny-cmd rm*\n"), 0644)

			os.Setenv("YOLONOT_HARNESS", tc.name)
			defer os.Unsetenv("YOLONOT_HARNESS")

			payload := HookPayload{
				HookEventName: "PreToolUse",
				ToolName:      "Bash",
				SessionID:     "smoke-" + tc.name,
				Cwd:           home,
				ToolInput:     map[string]interface{}{"command": "rm -rf /"},
			}
			data, _ := json.Marshal(payload)

			oldStdin := os.Stdin
			r, w, _ := os.Pipe()
			w.Write(data)
			w.Close()
			os.Stdin = r
			defer func() { os.Stdin = oldStdin }()

			out := captureStdout(func() { cmdHook() })
			if strings.TrimSpace(out) == "" {
				t.Fatal("no output from cmdHook — deny rule should emit a response")
			}
			tc.assert(t, out)
		})
	}
}
