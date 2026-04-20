package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeminiHarnessRegistered(t *testing.T) {
	if h := GetHarness("gemini"); h == nil {
		t.Fatal("gemini harness not registered")
	}
}

func TestGeminiHarnessSettingsPath(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")

	h := &GeminiHarness{}
	want := filepath.Join(dir, ".gemini", "settings.json")
	if got := h.SettingsPath(); got != want {
		t.Errorf("SettingsPath() = %s, want %s", got, want)
	}
}

func TestGeminiHarnessParseHookInputNormalisesEventName(t *testing.T) {
	// Gemini emits BeforeTool / AfterTool; yolonot's internal rule engine
	// branches on PreToolUse / PostToolUse. ParseHookInput must rewrite.
	h := &GeminiHarness{}
	cases := map[string]string{
		"BeforeTool": "PreToolUse",
		"AfterTool":  "PostToolUse",
	}
	for in, want := range cases {
		raw := `{"hook_event_name":"` + in + `","tool_name":"run_shell_command","tool_input":{"command":"ls"}}`
		p, err := h.ParseHookInput([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if p.HookEventName != want {
			t.Errorf("%s → %q, want %q", in, p.HookEventName, want)
		}
	}
}

func TestGeminiHarnessParseHookInputNormalisesToolName(t *testing.T) {
	// The rule engine / fast_allow logic branches on tool_name == "Bash".
	// Gemini's shell tool is "run_shell_command"; ParseHookInput aliases it.
	raw := `{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","session_id":"g1","cwd":"/tmp","tool_input":{"command":"ls"}}`
	h := &GeminiHarness{}
	p, err := h.ParseHookInput([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if p.ToolName != "Bash" {
		t.Errorf("ToolName = %q, want Bash", p.ToolName)
	}
	if p.SessionID != "g1" {
		t.Errorf("SessionID = %q, want g1", p.SessionID)
	}
	if cmd, _ := p.ToolInput["command"].(string); cmd != "ls" {
		t.Errorf("command = %q", cmd)
	}
}

func TestGeminiHarnessParseHookInputLeavesOtherToolsAlone(t *testing.T) {
	// Gemini's matcher scopes yolonot to run_shell_command, so non-shell
	// tools shouldn't normally reach us — but if they do, don't silently
	// rename them to Bash (which would make the rule engine misbehave).
	raw := `{"hook_event_name":"BeforeTool","tool_name":"read_file","tool_input":{"path":"/etc/passwd"}}`
	h := &GeminiHarness{}
	p, err := h.ParseHookInput([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if p.ToolName != "read_file" {
		t.Errorf("ToolName = %q, want read_file (unmapped)", p.ToolName)
	}
}

func TestGeminiHarnessFormatHookResponseFlat(t *testing.T) {
	// Gemini's scheduler reads decision/reason/systemMessage as TOP-LEVEL
	// fields. Any nested hookSpecificOutput is ignored and falls open.
	h := &GeminiHarness{}
	for _, dec := range []string{"allow", "ask", "deny"} {
		r := HookResponse{}
		r.HookSpecificOutput.HookEventName = "PreToolUse"
		r.HookSpecificOutput.PermissionDecision = dec
		r.HookSpecificOutput.PermissionDecisionReason = "why"
		r.SystemMessage = "banner"

		out := h.FormatHookResponse(r)
		var decoded map[string]interface{}
		if err := json.Unmarshal([]byte(out), &decoded); err != nil {
			t.Fatalf("%s: unmarshal failed: %v (raw=%s)", dec, err, out)
		}
		if _, nested := decoded["hookSpecificOutput"]; nested {
			t.Errorf("%s: emitted nested envelope (should be flat): %s", dec, out)
		}
		if got, _ := decoded["decision"].(string); got != dec {
			t.Errorf("%s: decision = %q, want %q", dec, got, dec)
		}
		if got, _ := decoded["reason"].(string); got != "why" {
			t.Errorf("%s: reason = %q, want why", dec, got)
		}
		if got, _ := decoded["systemMessage"].(string); got != "banner" {
			t.Errorf("%s: systemMessage = %q, want banner", dec, got)
		}
	}
}

func TestGeminiHarnessFormatHookResponseAskIsPreserved(t *testing.T) {
	// Regression guard: unlike Codex (ask→deny) and OpenCode (ask→throw),
	// Gemini has native ask support via scheduler.ts forcing PolicyDecision.
	// ASK_USER when decision=="ask". Translating it would defeat the whole
	// point of the Gemini adapter. Mirror of harness_codex_test.go's
	// TestCodexHarnessFormatHookResponseAskBecomesDeny — asserts the OPPOSITE.
	r := HookResponse{}
	r.HookSpecificOutput.HookEventName = "PreToolUse"
	r.HookSpecificOutput.PermissionDecision = "ask"
	r.HookSpecificOutput.PermissionDecisionReason = "suspicious"

	out := (&GeminiHarness{}).FormatHookResponse(r)
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["decision"] != "ask" {
		t.Errorf("Gemini rewrote ask → %v (must stay ask)", decoded["decision"])
	}
	if decoded["reason"] != "suspicious" {
		t.Errorf("Gemini dropped reason: %v", decoded["reason"])
	}

	// Sanity: Claude should also still emit ask (untouched).
	claudeOut := (&ClaudeHarness{}).FormatHookResponse(r)
	var claudeDecoded HookResponse
	if err := json.Unmarshal([]byte(claudeOut), &claudeDecoded); err != nil {
		t.Fatal(err)
	}
	if claudeDecoded.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("Claude adapter broken: %q (should stay ask)", claudeDecoded.HookSpecificOutput.PermissionDecision)
	}
}

func TestGeminiHarnessFormatHookResponseEmptyIsSilent(t *testing.T) {
	// Empty decision → empty stdout. Emitting `{"decision":""}` would fail
	// open on Gemini's parser; empty stdout is the documented implicit-allow
	// path. Matches CodexHarness behavior for allow-silent mode.
	r := HookResponse{}
	if out := (&GeminiHarness{}).FormatHookResponse(r); out != "" {
		t.Errorf("FormatHookResponse(empty) = %q, want empty", out)
	}
}

func TestGeminiHarnessInstallWritesMatcherAndTimeout(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")
	os.MkdirAll(filepath.Join(dir, ".gemini"), 0755)

	h := &GeminiHarness{}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(h.SettingsPath())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "BeforeTool") || !strings.Contains(s, "AfterTool") {
		t.Errorf("settings.json missing Before/After entries: %s", s)
	}
	if !strings.Contains(s, `"matcher": "^run_shell_command$"`) {
		t.Errorf("missing anchored shell matcher: %s", s)
	}
	// Timeout is milliseconds in Gemini's schema, not seconds. 60 would be
	// 60ms — useless. 60000 = 60s.
	if !strings.Contains(s, "60000") {
		t.Errorf("timeout should be 60000ms: %s", s)
	}
}

func TestGeminiHarnessInstallPinsHarnessFlag(t *testing.T) {
	// Without --harness gemini, the hook process would resolve Claude as the
	// active harness and emit the nested hookSpecificOutput envelope, which
	// Gemini would fail-open on.
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")
	os.MkdirAll(filepath.Join(dir, ".gemini"), 0755)

	h := &GeminiHarness{}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(h.SettingsPath())
	if !strings.Contains(string(data), "hook --harness gemini") {
		t.Errorf("install did not pin --harness gemini: %s", string(data))
	}
}

func TestGeminiHarnessInstallPreservesOtherSettings(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")
	os.MkdirAll(filepath.Join(dir, ".gemini"), 0755)

	// Seed settings.json with unrelated user-owned keys.
	seed := map[string]interface{}{
		"theme":        "GitHub",
		"selectedAuth": "oauth-personal",
		"telemetry":    map[string]interface{}{"enabled": false},
	}
	seedBytes, _ := json.Marshal(seed)
	settingsPath := filepath.Join(dir, ".gemini", "settings.json")
	if err := os.WriteFile(settingsPath, seedBytes, 0644); err != nil {
		t.Fatal(err)
	}

	h := &GeminiHarness{}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(settingsPath)
	var out map[string]interface{}
	json.Unmarshal(data, &out)
	if out["theme"] != "GitHub" {
		t.Errorf("theme clobbered: %v", out["theme"])
	}
	if out["selectedAuth"] != "oauth-personal" {
		t.Errorf("selectedAuth clobbered: %v", out["selectedAuth"])
	}
	if _, ok := out["hooks"]; !ok {
		t.Errorf("hooks key not added")
	}
}

func TestGeminiHarnessInstallUninstall(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")
	os.MkdirAll(filepath.Join(dir, ".gemini"), 0755)

	h := &GeminiHarness{}
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

func TestGeminiHarnessUninstallKeepsOtherHooks(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")
	os.MkdirAll(filepath.Join(dir, ".gemini"), 0755)

	h := &GeminiHarness{}
	if err := h.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}

	// Inject a peer BeforeTool hook that isn't ours.
	s := h.loadSettings()
	hooks, _ := s["hooks"].(map[string]interface{})
	addHookToEvent(hooks, "BeforeTool", "^write_file$", map[string]interface{}{
		"type":    "command",
		"command": "/usr/local/bin/my-other-tool",
		"timeout": 30000.0,
	})
	h.saveSettings(s)

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

func TestGeminiHarnessIsDetected(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	defer os.Unsetenv("HOME")

	h := &GeminiHarness{}
	if h.IsDetected() {
		t.Fatal("should not be detected without ~/.gemini")
	}
	os.MkdirAll(filepath.Join(dir, ".gemini"), 0755)
	if !h.IsDetected() {
		t.Fatal("should be detected with ~/.gemini")
	}
}

func TestGeminiHarnessSkillNoOp(t *testing.T) {
	h := &GeminiHarness{}
	path, err := h.InstallSkill()
	if err != nil || path != "" {
		t.Errorf("InstallSkill() = (%q, %v), want (\"\", nil)", path, err)
	}
	if err := h.UninstallSkill(); err != nil {
		t.Errorf("UninstallSkill() = %v, want nil", err)
	}
}

func TestActiveHarnessPicksGeminiByOverride(t *testing.T) {
	os.Setenv("YOLONOT_HARNESS", "gemini")
	defer os.Unsetenv("YOLONOT_HARNESS")

	h := ActiveHarness()
	if h == nil || h.Name() != "gemini" {
		t.Errorf("ActiveHarness() = %v, want gemini", h)
	}
}

func TestActiveHarnessPicksGeminiBySessionEnv(t *testing.T) {
	t.Setenv("YOLONOT_HARNESS", "")
	t.Setenv("CLAUDE_SESSION_ID", "")
	t.Setenv("YOLONOT_CODEX_SESSION_ID", "")
	t.Setenv("YOLONOT_OPENCODE_SESSION_ID", "")
	t.Setenv("YOLONOT_GEMINI_SESSION_ID", "gem-sid")

	h := ActiveHarness()
	if h == nil || h.Name() != "gemini" {
		t.Errorf("ActiveHarness() = %v, want gemini", h)
	}
}

func TestGeminiHarnessSessionIDFromEnv(t *testing.T) {
	t.Setenv("YOLONOT_GEMINI_SESSION_ID", "gem-99")
	h := &GeminiHarness{}
	if got := h.SessionIDFromEnv(); got != "gem-99" {
		t.Errorf("SessionIDFromEnv() = %q, want gem-99", got)
	}
}

func TestGeminiHarnessParseHookInputInvalidJSON(t *testing.T) {
	// Malformed stdin must error — empty hook_event_name alone would also
	// short-circuit, but returning an error surfaces the bug sooner.
	h := &GeminiHarness{}
	if _, err := h.ParseHookInput([]byte("{not json")); err == nil {
		t.Fatal("ParseHookInput on malformed JSON must return error, got nil")
	}
}

func TestGeminiHarnessPostInstallNotesWarnAboutYolo(t *testing.T) {
	// With no settings.json (or defaultApprovalMode unset) the --yolo
	// warning must fire, otherwise a user who never opens settings.json
	// will see yolonot's allow decisions silently ignored.
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	notes := (&GeminiHarness{}).PostInstallNotes()
	if len(notes) == 0 {
		t.Fatal("Gemini PostInstallNotes empty — --yolo warning missing")
	}
	joined := strings.ToLower(strings.Join(notes, "\n"))
	if !strings.Contains(joined, "yolo") {
		t.Errorf("PostInstallNotes should mention --yolo; got:\n%s", strings.Join(notes, "\n"))
	}
}

func TestGeminiHarnessPostInstallNotesSuppressedWhenYoloDefault(t *testing.T) {
	// If the user already set general.defaultApprovalMode=yolo, suppress
	// the warning — noise on every install would teach users to skim past
	// the notes section entirely.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".gemini"), 0755)
	settings := `{"general":{"defaultApprovalMode":"yolo"}}`
	if err := os.WriteFile(filepath.Join(dir, ".gemini", "settings.json"), []byte(settings), 0644); err != nil {
		t.Fatal(err)
	}

	notes := (&GeminiHarness{}).PostInstallNotes()
	if len(notes) != 0 {
		t.Errorf("PostInstallNotes should be empty when yolo is default; got %v", notes)
	}
}
