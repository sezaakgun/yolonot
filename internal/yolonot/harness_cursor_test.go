package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCursorHarnessRegistered(t *testing.T) {
	if h := GetHarness("cursor"); h == nil {
		t.Fatal("cursor harness not registered")
	}
}

func TestCursorHarnessSettingsPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	h := &CursorHarness{}
	want := filepath.Join(dir, ".cursor", "hooks.json")
	if got := h.SettingsPath(); got != want {
		t.Errorf("SettingsPath() = %s, want %s", got, want)
	}
}

func TestCursorHarnessParseHookInputNormalisesEventName(t *testing.T) {
	// Cursor emits beforeShellExecution / afterShellExecution; yolonot's
	// internal rule engine branches on PreToolUse / PostToolUse.
	h := &CursorHarness{}
	cases := map[string]string{
		"beforeShellExecution": "PreToolUse",
		"afterShellExecution":  "PostToolUse",
	}
	for in, want := range cases {
		raw := `{"hook_event_name":"` + in + `","command":"ls","cwd":"/tmp","conversation_id":"c1"}`
		p, err := h.ParseHookInput([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if p.HookEventName != want {
			t.Errorf("%s → %q, want %q", in, p.HookEventName, want)
		}
	}
}

func TestCursorHarnessParseHookInputLiftsCommandAndSetsBash(t *testing.T) {
	// Cursor's payload has top-level `command`, not nested in tool_input.
	// The rule engine / fast_allow logic branches on tool_name == "Bash"
	// and pulls the command from tool_input["command"].
	raw := `{"hook_event_name":"beforeShellExecution","command":"rm -rf /tmp/x","cwd":"/w","conversation_id":"c42"}`
	h := &CursorHarness{}
	p, err := h.ParseHookInput([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if p.ToolName != "Bash" {
		t.Errorf("ToolName = %q, want Bash", p.ToolName)
	}
	if p.SessionID != "c42" {
		t.Errorf("SessionID = %q, want c42", p.SessionID)
	}
	if p.Cwd != "/w" {
		t.Errorf("Cwd = %q, want /w", p.Cwd)
	}
	if cmd, _ := p.ToolInput["command"].(string); cmd != "rm -rf /tmp/x" {
		t.Errorf("command = %q", cmd)
	}
}

func TestCursorHarnessParseHookInputEmpty(t *testing.T) {
	// Empty stdin is valid — cmdHook returns zero payload and exits silently.
	h := &CursorHarness{}
	p, err := h.ParseHookInput(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.HookEventName != "" || p.ToolName != "" {
		t.Errorf("empty stdin should zero-value payload, got %+v", p)
	}
}

func TestCursorHarnessParseHookInputInvalidJSON(t *testing.T) {
	h := &CursorHarness{}
	if _, err := h.ParseHookInput([]byte("{not json")); err == nil {
		t.Fatal("ParseHookInput on malformed JSON must return error, got nil")
	}
}

func TestCursorHarnessFormatHookResponseDenyFlat(t *testing.T) {
	// Cursor's scheduler reads permission/user_message/agent_message as
	// TOP-LEVEL fields. Only deny is emitted on the wire (allow/ask collapse
	// to empty — see TestCursorHarnessFormatHookResponseAllowAndAskAreEmpty).
	r := HookResponse{}
	r.HookSpecificOutput.HookEventName = "PreToolUse"
	r.HookSpecificOutput.PermissionDecision = "deny"
	r.HookSpecificOutput.PermissionDecisionReason = "why"

	out := (&CursorHarness{}).FormatHookResponse(r)
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v (raw=%s)", err, out)
	}
	if _, nested := decoded["hookSpecificOutput"]; nested {
		t.Errorf("emitted nested envelope (should be flat): %s", out)
	}
	if got, _ := decoded["permission"].(string); got != "deny" {
		t.Errorf("permission = %q, want deny", got)
	}
	if got, _ := decoded["user_message"].(string); got != "why" {
		t.Errorf("user_message = %q, want why", got)
	}
	if got, _ := decoded["agent_message"].(string); got != "why" {
		t.Errorf("agent_message = %q, want why", got)
	}
}

func TestCursorHarnessFormatHookResponseAskIsEmpty(t *testing.T) {
	// Cursor's schema accepts "ask" but does not enforce it — no TUI prompt
	// fires, and asked-not-approved pins the next invocation as session_deny.
	// We collapse ask to empty stdout (passthrough) so Cursor's own
	// permission UI handles moderate-risk commands. Parallels Codex/OpenCode.
	r := HookResponse{}
	r.HookSpecificOutput.PermissionDecision = "ask"
	r.HookSpecificOutput.PermissionDecisionReason = "why"
	if out := (&CursorHarness{}).FormatHookResponse(r); out != "" {
		t.Errorf("ask: FormatHookResponse = %q, want empty", out)
	}
}

func TestCursorHarnessFormatHookResponseAllowIsExplicit(t *testing.T) {
	// Empty stdout is NOT equivalent to allow for Cursor — it falls back to
	// the native confirmation prompt, which reprompts on every invocation
	// and makes yolonot's session-allow memory invisible. Must emit explicit
	// {"permission":"allow"} so Cursor's UI is bypassed. Regression guard
	// for the session-approval bug observed 2026-04-21.
	r := HookResponse{}
	r.HookSpecificOutput.PermissionDecision = "allow"
	r.HookSpecificOutput.PermissionDecisionReason = "previously approved this session"

	out := (&CursorHarness{}).FormatHookResponse(r)
	if out == "" {
		t.Fatal("allow must not collapse to empty — Cursor would reprompt via its native UI")
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v (raw=%s)", err, out)
	}
	if decoded["permission"] != "allow" {
		t.Errorf("permission = %v, want allow", decoded["permission"])
	}
}

func TestCursorHarnessFormatHookResponseEmptyIsSilent(t *testing.T) {
	r := HookResponse{}
	if out := (&CursorHarness{}).FormatHookResponse(r); out != "" {
		t.Errorf("FormatHookResponse(empty) = %q, want empty", out)
	}
}

func TestCursorHarnessFormatHookResponseDenyFallsBackToSystemMessage(t *testing.T) {
	// When the rule engine only sets SystemMessage (no decision reason),
	// feed it through as the message so the user still sees yolonot's banner.
	r := HookResponse{}
	r.HookSpecificOutput.PermissionDecision = "deny"
	r.SystemMessage = "banner"

	out := (&CursorHarness{}).FormatHookResponse(r)
	var decoded map[string]interface{}
	json.Unmarshal([]byte(out), &decoded)
	if decoded["user_message"] != "banner" {
		t.Errorf("user_message = %v, want banner", decoded["user_message"])
	}
}

func TestCursorHarnessInstallWritesFlatEntries(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".cursor"), 0755)

	h := &CursorHarness{}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(h.SettingsPath())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "beforeShellExecution") || !strings.Contains(s, "afterShellExecution") {
		t.Errorf("hooks.json missing before/after entries: %s", s)
	}
	if !strings.Contains(s, `"version": 1`) {
		t.Errorf("missing version: 1 top-level key: %s", s)
	}
	// Timeout is seconds in Cursor's schema (same as Claude, unlike Gemini's ms).
	if !strings.Contains(s, `"timeout": 60`) || strings.Contains(s, `"timeout": 60000`) {
		t.Errorf("timeout should be 60 seconds, not ms: %s", s)
	}

	// Entries must be flat, not Claude-style {matcher, hooks:[...]}.
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	hooks, _ := root["hooks"].(map[string]interface{})
	entries, _ := hooks["beforeShellExecution"].([]interface{})
	if len(entries) == 0 {
		t.Fatal("no beforeShellExecution entries")
	}
	entry, _ := entries[0].(map[string]interface{})
	if _, wrapped := entry["hooks"]; wrapped {
		t.Errorf("entry wraps a nested hooks array (Claude shape); Cursor wants flat: %v", entry)
	}
	if cmd, _ := entry["command"].(string); !strings.Contains(cmd, "yolonot") {
		t.Errorf("entry.command missing yolonot: %v", entry)
	}
}

func TestCursorHarnessInstallPinsHarnessFlag(t *testing.T) {
	// Without --harness cursor, ActiveHarness() would pick Claude (no session
	// id is exported) and emit nested hookSpecificOutput, which Cursor would
	// fail-open on.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".cursor"), 0755)

	h := &CursorHarness{}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(h.SettingsPath())
	if !strings.Contains(string(data), "hook --harness cursor") {
		t.Errorf("install did not pin --harness cursor: %s", string(data))
	}
}

func TestCursorHarnessInstallPreservesOtherHooks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".cursor"), 0755)

	// Seed hooks.json with an unrelated peer hook.
	seed := map[string]interface{}{
		"version": 1,
		"hooks": map[string]interface{}{
			"beforeShellExecution": []interface{}{
				map[string]interface{}{
					"command": "/usr/local/bin/my-other-tool",
					"matcher": "curl|wget",
					"timeout": 30,
				},
			},
			"sessionStart": []interface{}{
				map[string]interface{}{"command": "/usr/local/bin/unrelated"},
			},
		},
	}
	seedBytes, _ := json.MarshalIndent(seed, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, ".cursor", "hooks.json"), seedBytes, 0644); err != nil {
		t.Fatal(err)
	}

	h := &CursorHarness{}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(h.SettingsPath())
	if !strings.Contains(string(data), "my-other-tool") {
		t.Errorf("install removed peer beforeShellExecution hook: %s", string(data))
	}
	if !strings.Contains(string(data), "unrelated") {
		t.Errorf("install removed peer sessionStart hook: %s", string(data))
	}
}

func TestCursorHarnessInstallUninstall(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".cursor"), 0755)

	h := &CursorHarness{}
	if h.IsInstalled() {
		t.Fatal("should not be installed initially")
	}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}
	if !h.IsInstalled() {
		t.Fatal("should be installed after Install()")
	}
	if err := h.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if h.IsInstalled() {
		t.Fatal("should not be installed after Uninstall()")
	}
}

func TestCursorHarnessUninstallKeepsPeerHooks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".cursor"), 0755)

	h := &CursorHarness{}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}

	// Inject a peer shell-execution hook after install.
	s := h.loadHooks()
	hooks, _ := s["hooks"].(map[string]interface{})
	entries, _ := hooks["beforeShellExecution"].([]interface{})
	entries = append(entries, map[string]interface{}{
		"command": "/usr/local/bin/my-other-tool",
		"matcher": "curl",
		"timeout": 30,
	})
	hooks["beforeShellExecution"] = entries
	h.saveHooks(s)

	if err := h.Uninstall(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(h.SettingsPath())
	if !strings.Contains(string(data), "my-other-tool") {
		t.Errorf("uninstall removed peer hook: %s", string(data))
	}
	if strings.Contains(string(data), "yolonot") {
		t.Errorf("uninstall left yolonot behind: %s", string(data))
	}
}

func TestCursorHarnessIsDetected(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	h := &CursorHarness{}
	if h.IsDetected() {
		t.Fatal("should not be detected without ~/.cursor")
	}
	os.MkdirAll(filepath.Join(dir, ".cursor"), 0755)
	if !h.IsDetected() {
		t.Fatal("should be detected with ~/.cursor")
	}
}

func TestCursorHarnessSkillNoOp(t *testing.T) {
	h := &CursorHarness{}
	path, err := h.InstallSkill()
	if err != nil || path != "" {
		t.Errorf("InstallSkill() = (%q, %v), want (\"\", nil)", path, err)
	}
	if err := h.UninstallSkill(); err != nil {
		t.Errorf("UninstallSkill() = %v, want nil", err)
	}
}

func TestCursorHarnessSessionIDFromEnv(t *testing.T) {
	t.Setenv("YOLONOT_CURSOR_SESSION_ID", "cur-99")
	h := &CursorHarness{}
	if got := h.SessionIDFromEnv(); got != "cur-99" {
		t.Errorf("SessionIDFromEnv() = %q, want cur-99", got)
	}
}

func TestActiveHarnessPicksCursorByOverride(t *testing.T) {
	t.Setenv("YOLONOT_HARNESS", "cursor")
	h := ActiveHarness()
	if h == nil || h.Name() != "cursor" {
		t.Errorf("ActiveHarness() = %v, want cursor", h)
	}
}

func TestCursorHarnessPostInstallNotes(t *testing.T) {
	notes := (&CursorHarness{}).PostInstallNotes()
	if len(notes) == 0 {
		t.Fatal("PostInstallNotes empty — restart hint missing")
	}
	joined := strings.ToLower(strings.Join(notes, "\n"))
	if !strings.Contains(joined, "restart") && !strings.Contains(joined, "new chat") {
		t.Errorf("PostInstallNotes should tell user to restart/start new chat; got: %s", strings.Join(notes, "\n"))
	}
	if !strings.Contains(joined, "ask") {
		t.Errorf("PostInstallNotes should warn about ask not being enforced; got: %s", strings.Join(notes, "\n"))
	}
}

func TestCursorHarnessRiskMapDenyOnly(t *testing.T) {
	// Cursor matches the Codex pattern because ask isn't enforced upstream.
	// safe/low → allow; moderate → passthrough (Cursor's UI decides);
	// high/critical → deny. Regressing moderate to ActionAsk would pin every
	// moderate command as session_deny via asked-not-approved.
	rm := (&CursorHarness{}).RiskMap()
	if rm[RiskSafe] != ActionAllow || rm[RiskLow] != ActionAllow {
		t.Errorf("safe/low should allow: %v", rm)
	}
	if rm[RiskModerate] != ActionPassthrough {
		t.Errorf("moderate should be passthrough (ask is not enforced by Cursor): %v", rm)
	}
	if rm[RiskHigh] != ActionDeny || rm[RiskCritical] != ActionDeny {
		t.Errorf("high/critical should deny: %v", rm)
	}
}
