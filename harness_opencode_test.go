package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpencodeHarnessRegistered(t *testing.T) {
	if h := GetHarness("opencode"); h == nil {
		t.Fatal("opencode harness not registered")
	}
}

func TestOpencodeHarnessSettingsPath(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")

	h := &OpencodeHarness{}
	want := filepath.Join(dir, ".config", "opencode", "plugin", "yolonot.ts")
	if got := h.SettingsPath(); got != want {
		t.Errorf("SettingsPath() = %s, want %s", got, want)
	}
}

func TestOpencodeHarnessInstallWritesPlugin(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")

	h := &OpencodeHarness{}
	if h.IsInstalled() {
		t.Fatal("should not be installed initially")
	}

	bin := "/usr/local/bin/yolonot"
	if err := h.Install(bin); err != nil {
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
	// Binary path placeholder must be replaced.
	if strings.Contains(s, "__YOLONOT_BIN__") {
		t.Errorf("plugin still contains __YOLONOT_BIN__ placeholder")
	}
	if !strings.Contains(s, bin) {
		t.Errorf("plugin missing binary path %q: %s", bin, s)
	}
	// Plugin must implement the OpenCode hook surface.
	if !strings.Contains(s, "tool.execute.before") || !strings.Contains(s, "tool.execute.after") {
		t.Errorf("plugin missing expected hooks: %s", s)
	}
	// OpenCode 1.4.3 only recognises named exports; a regression to
	// `export default` silently no-ops in the loader.
	if !strings.Contains(s, "export const YolonotPlugin") {
		t.Errorf("plugin missing named export (must be `export const YolonotPlugin`, not default): %s", s)
	}
}

func TestOpencodeHarnessUninstallRemovesPlugin(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")

	h := &OpencodeHarness{}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}
	if err := h.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if h.IsInstalled() {
		t.Fatal("should not be installed after Uninstall()")
	}
	// Uninstall on absent file must be a no-op.
	if err := h.Uninstall(); err != nil {
		t.Errorf("second Uninstall() = %v, want nil", err)
	}
}

func TestOpencodeHarnessIsDetected(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")

	h := &OpencodeHarness{}
	if h.IsDetected() {
		t.Fatal("should not be detected without ~/.config/opencode")
	}

	os.MkdirAll(filepath.Join(dir, ".config", "opencode"), 0755)
	if !h.IsDetected() {
		t.Fatal("should be detected with ~/.config/opencode")
	}
}

func TestOpencodeHarnessSkillNoOp(t *testing.T) {
	h := &OpencodeHarness{}
	path, err := h.InstallSkill()
	if err != nil || path != "" {
		t.Errorf("InstallSkill() = (%q, %v), want (\"\", nil)", path, err)
	}
	if err := h.UninstallSkill(); err != nil {
		t.Errorf("UninstallSkill() = %v, want nil", err)
	}
}

func TestActiveHarnessPicksOpencodeByOverride(t *testing.T) {
	os.Setenv("YOLONOT_HARNESS", "opencode")
	defer os.Unsetenv("YOLONOT_HARNESS")

	h := ActiveHarness()
	if h == nil || h.Name() != "opencode" {
		t.Errorf("ActiveHarness() = %v, want opencode", h)
	}
}

func TestActiveHarnessPicksOpencodeBySessionEnv(t *testing.T) {
	t.Setenv("YOLONOT_HARNESS", "")
	t.Setenv("CLAUDE_SESSION_ID", "")
	t.Setenv("YOLONOT_OPENCODE_SESSION_ID", "opencode-sid")

	h := ActiveHarness()
	if h == nil || h.Name() != "opencode" {
		t.Errorf("ActiveHarness() = %v, want opencode", h)
	}
}

func TestOpencodeHarnessSessionIDFromEnv(t *testing.T) {
	t.Setenv("YOLONOT_OPENCODE_SESSION_ID", "oc-42")
	h := &OpencodeHarness{}
	if got := h.SessionIDFromEnv(); got != "oc-42" {
		t.Errorf("SessionIDFromEnv() = %q, want oc-42", got)
	}
}

func TestOpencodeHarnessParseHookInputCanonical(t *testing.T) {
	// The embedded TS plugin constructs a canonical Claude-shaped payload,
	// so ParseHookInput is a passthrough. Lock the happy path.
	raw := `{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"oc-1","cwd":"/tmp","tool_input":{"command":"ls"}}`
	h := &OpencodeHarness{}
	p, err := h.ParseHookInput([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if p.HookEventName != "PreToolUse" || p.SessionID != "oc-1" {
		t.Errorf("parsed = %+v", p)
	}
	if cmd, _ := p.ToolInput["command"].(string); cmd != "ls" {
		t.Errorf("command = %q, want ls", cmd)
	}
}

func TestOpencodeHarnessParseHookInputEmpty(t *testing.T) {
	h := &OpencodeHarness{}
	p, err := h.ParseHookInput(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.HookEventName != "" {
		t.Errorf("empty parse should be zero, got %+v", p)
	}
}

func TestOpencodeHarnessParseHookInputInvalidJSON(t *testing.T) {
	// Bogus JSON must surface as an error so the hook pipeline skips this
	// event — silent fallthrough with a zero payload would let malformed
	// input bypass the classifier entirely.
	h := &OpencodeHarness{}
	if _, err := h.ParseHookInput([]byte("{not json")); err == nil {
		t.Fatal("ParseHookInput on malformed JSON must return error, got nil")
	}
}

func TestOpencodeHarnessFormatHookResponseDeny(t *testing.T) {
	// The plugin reads permissionDecision out of hookSpecificOutput and
	// throws on "deny". Lock the wire shape so a refactor to Codex-style
	// empty-on-allow doesn't silently break deny.
	r := HookResponse{}
	r.HookSpecificOutput.HookEventName = "PreToolUse"
	r.HookSpecificOutput.PermissionDecision = "deny"
	r.HookSpecificOutput.PermissionDecisionReason = "blocked"

	out := (&OpencodeHarness{}).FormatHookResponse(r)
	var decoded HookResponse
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("round trip failed: %v (output=%s)", err, out)
	}
	if decoded.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("decision = %q, want deny", decoded.HookSpecificOutput.PermissionDecision)
	}
	if decoded.HookSpecificOutput.PermissionDecisionReason != "blocked" {
		t.Errorf("reason = %q", decoded.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestOpencodeHarnessFormatHookResponseMatchesClaude(t *testing.T) {
	// OpenCode's plugin consumes the canonical Claude shape. Byte-for-byte
	// equivalence with ClaudeHarness.FormatHookResponse guards against an
	// accidental envelope divergence that would break the TS shim parser.
	r := HookResponse{}
	r.HookSpecificOutput.HookEventName = "PreToolUse"
	r.HookSpecificOutput.PermissionDecision = "allow"
	r.HookSpecificOutput.PermissionDecisionReason = "ok"

	claude := (&ClaudeHarness{}).FormatHookResponse(r)
	opencode := (&OpencodeHarness{}).FormatHookResponse(r)
	if claude != opencode {
		t.Errorf("claude vs opencode divergence:\n  claude=%s\n  opencode=%s", claude, opencode)
	}
}

func TestOpencodeHarnessDefaultRiskMap(t *testing.T) {
	// OpenCode's plugin treats empty stdout as allow, so ActionPassthrough
	// would silently promote moderate to allow. Guard against a regression
	// that reintroduces passthrough to this map.
	m := (&OpencodeHarness{}).RiskMap()
	cases := map[string]string{
		RiskSafe: ActionAllow, RiskLow: ActionAllow, RiskModerate: ActionAllow,
		RiskHigh: ActionDeny, RiskCritical: ActionDeny,
	}
	for tier, want := range cases {
		if m[tier] != want {
			t.Errorf("opencode[%s]=%q want %q", tier, m[tier], want)
		}
	}
	for tier, action := range m {
		if action == ActionPassthrough {
			t.Errorf("opencode[%s]=%q — plugin treats empty stdout as allow, passthrough silently promotes", tier, action)
		}
	}
}

func TestOpencodeHarnessPostInstallNotesMentionAskLimitation(t *testing.T) {
	// Users porting a Claude .yolonot must learn that ask-rules don't
	// behave the same on OpenCode. This guard keeps that disclosure in
	// PostInstallNotes even as copy evolves.
	notes := (&OpencodeHarness{}).PostInstallNotes()
	if len(notes) == 0 {
		t.Fatal("OpenCode must surface ask-primitive limitation in PostInstallNotes")
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(strings.ToLower(joined), "ask") {
		t.Errorf("PostInstallNotes should mention the ask limitation; got:\n%s", joined)
	}
}
