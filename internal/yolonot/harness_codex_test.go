package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexHarnessRegistered(t *testing.T) {
	if h := GetHarness("codex"); h == nil {
		t.Fatal("codex harness not registered")
	}
}

func TestCodexHarnessSettingsPath(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")

	h := &CodexHarness{}
	want := filepath.Join(dir, ".codex", "hooks.json")
	if got := h.SettingsPath(); got != want {
		t.Errorf("SettingsPath() = %s, want %s", got, want)
	}
}

func TestCodexHarnessParseHookInputCanonical(t *testing.T) {
	// Codex stdin shape is field-compatible with Claude's canonical payload.
	raw := `{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"cdx-1","cwd":"/tmp","tool_input":{"command":"ls"},"turn_id":"t1","tool_use_id":"u1"}`
	h := &CodexHarness{}
	p, err := h.ParseHookInput([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if p.HookEventName != "PreToolUse" || p.SessionID != "cdx-1" {
		t.Errorf("parsed = %+v", p)
	}
	if cmd, _ := p.ToolInput["command"].(string); cmd != "ls" {
		t.Errorf("command = %q", cmd)
	}
}

func TestCodexHarnessFormatHookResponseAskIsPassthrough(t *testing.T) {
	// Codex's PreToolUse contract rejects permissionDecision:"ask". With the
	// new risk-map architecture, policy lives in RiskMap (high/critical →
	// deny, moderate → passthrough). The wire-level adapter only needs to
	// keep "ask" from reaching Codex verbatim; it now returns empty so the
	// host's own permission engine takes over. Claude's adapter MUST remain
	// unchanged.
	r := HookResponse{}
	r.HookSpecificOutput.HookEventName = "PreToolUse"
	r.HookSpecificOutput.PermissionDecision = "ask"
	r.HookSpecificOutput.PermissionDecisionReason = "suspicious"

	claudeOut := (&ClaudeHarness{}).FormatHookResponse(r)
	var claudeDecoded HookResponse
	if err := json.Unmarshal([]byte(claudeOut), &claudeDecoded); err != nil {
		t.Fatal(err)
	}
	if claudeDecoded.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("Claude emitted %q for ask (should stay ask)", claudeDecoded.HookSpecificOutput.PermissionDecision)
	}

	codexOut := (&CodexHarness{}).FormatHookResponse(r)
	if codexOut != "" {
		t.Errorf("Codex emitted %q for ask (should be empty, passthrough to host)", codexOut)
	}
}

func TestCodexHarnessFormatHookResponseAllowIsSilent(t *testing.T) {
	// Codex rejects permissionDecision:"allow" as unsupported. The adapter
	// must emit an empty string so emitHook() skips stdout entirely.
	r := HookResponse{}
	r.HookSpecificOutput.HookEventName = "PreToolUse"
	r.HookSpecificOutput.PermissionDecision = "allow"
	r.HookSpecificOutput.PermissionDecisionReason = "fine"

	out := (&CodexHarness{}).FormatHookResponse(r)
	if out != "" {
		t.Errorf("FormatHookResponse(allow) = %q, want empty", out)
	}
}

func TestCodexHarnessFormatHookResponseMatchesClaude(t *testing.T) {
	// Codex documents the same response shape as Claude — the canonical
	// HookResponse marshals identically for both adapters. Assert byte-for-
	// byte equivalence so future divergence is caught at the adapter seam.
	r := HookResponse{}
	r.HookSpecificOutput.HookEventName = "PreToolUse"
	r.HookSpecificOutput.PermissionDecision = "deny"
	r.HookSpecificOutput.PermissionDecisionReason = "blocked"

	claude := (&ClaudeHarness{}).FormatHookResponse(r)
	codex := (&CodexHarness{}).FormatHookResponse(r)
	if claude != codex {
		t.Errorf("claude vs codex divergence:\n  claude=%s\n  codex=%s", claude, codex)
	}

	var decoded HookResponse
	if err := json.Unmarshal([]byte(codex), &decoded); err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if decoded.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("round trip decision = %q", decoded.HookSpecificOutput.PermissionDecision)
	}
}

func TestCodexHarnessInstallUninstall(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")

	h := &CodexHarness{}
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
	if !strings.Contains(s, "yolonot") || !strings.Contains(s, "PreToolUse") || !strings.Contains(s, `"matcher": "Bash"`) {
		t.Errorf("hooks.json missing expected entries: %s", s)
	}

	if err := h.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if h.IsInstalled() {
		t.Fatal("should not be installed after Uninstall()")
	}
}

func TestCodexHarnessIsDetected(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")

	h := &CodexHarness{}
	if h.IsDetected() {
		t.Fatal("should not be detected without ~/.codex dir")
	}

	os.MkdirAll(filepath.Join(dir, ".codex"), 0755)
	if !h.IsDetected() {
		t.Fatal("should be detected with ~/.codex dir")
	}
}

func TestCodexHarnessInstallEnablesFeatureFlag(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")
	os.MkdirAll(filepath.Join(dir, ".codex"), 0755)
	// Seed a pre-existing config.toml to make sure we don't clobber it.
	cfgPath := filepath.Join(dir, ".codex", "config.toml")
	os.WriteFile(cfgPath, []byte("model = \"gpt-5.4\"\n"), 0644)

	h := &CodexHarness{}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}

	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(cfg)
	if !strings.Contains(s, "codex_hooks = true") {
		t.Errorf("config.toml missing feature flag: %s", s)
	}
	if !strings.Contains(s, `model = "gpt-5.4"`) {
		t.Errorf("config.toml clobbered user content: %s", s)
	}

	// Idempotency: reinstalling must not duplicate the flag block.
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}
	cfg2, _ := os.ReadFile(cfgPath)
	if strings.Count(string(cfg2), "codex_hooks = true") != 1 {
		t.Errorf("duplicate feature flag after reinstall: %s", string(cfg2))
	}
}

func TestCodexHarnessInstallSkillNoOp(t *testing.T) {
	h := &CodexHarness{}
	path, err := h.InstallSkill()
	if err != nil || path != "" {
		t.Errorf("InstallSkill() = (%q, %v), want (\"\", nil)", path, err)
	}
	if err := h.UninstallSkill(); err != nil {
		t.Errorf("UninstallSkill() = %v, want nil", err)
	}
}

func TestActiveHarnessPicksCodexByOverride(t *testing.T) {
	os.Setenv("YOLONOT_HARNESS", "codex")
	defer os.Unsetenv("YOLONOT_HARNESS")

	h := ActiveHarness()
	if h == nil || h.Name() != "codex" {
		t.Errorf("ActiveHarness() = %v, want codex", h)
	}
}

func TestCodexHarnessParseHookInputInvalidJSON(t *testing.T) {
	// Malformed stdin must error out so the hook pipeline aborts rather
	// than operating on a zero-value HookPayload (which would skip the
	// classifier entirely via the empty hook_event_name guard).
	h := &CodexHarness{}
	if _, err := h.ParseHookInput([]byte("{not json")); err == nil {
		t.Fatal("ParseHookInput on malformed JSON must return error, got nil")
	}
}

func TestCodexHarnessPostInstallNotesMentionAskLimitation(t *testing.T) {
	notes := (&CodexHarness{}).PostInstallNotes()
	if len(notes) == 0 {
		t.Fatal("Codex must surface ask-primitive limitation in PostInstallNotes")
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(strings.ToLower(joined), "ask") {
		t.Errorf("PostInstallNotes should mention the ask limitation; got:\n%s", joined)
	}
}

func TestActiveHarnessPicksCodexBySessionEnv(t *testing.T) {
	os.Unsetenv("YOLONOT_HARNESS")
	os.Unsetenv("CLAUDE_SESSION_ID")
	os.Setenv("YOLONOT_CODEX_SESSION_ID", "cdx-sid")
	defer os.Unsetenv("YOLONOT_CODEX_SESSION_ID")

	h := ActiveHarness()
	if h == nil || h.Name() != "codex" {
		t.Errorf("ActiveHarness() = %v, want codex", h)
	}
}
