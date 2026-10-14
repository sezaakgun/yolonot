package yolonot

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
	want := filepath.Join(dir, ".config", "opencode", "plugins", "yolonot.ts")
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
	// V1 retains its named factory; V2 requires a default id/setup definition.
	if !strings.Contains(s, "export const YolonotPlugin") {
		t.Errorf("plugin missing named export (must be `export const YolonotPlugin`, not default): %s", s)
	}
	if !strings.Contains(s, "export default") || !strings.Contains(s, "async setup(ctx") {
		t.Errorf("plugin missing V2 definition: %s", s)
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

func TestOpencodeHarnessSkillInstall(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	h := &OpencodeHarness{}
	path, err := h.InstallSkill()
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(opencodeConfigDir(), "skills", "yolonot") {
		t.Fatalf("skill installed outside OpenCode's config: %s", path)
	}
	if data, err := os.ReadFile(filepath.Join(path, "SKILL.md")); err != nil || !strings.Contains(string(data), "yolonot") {
		t.Fatalf("skill bundle not written: %v", err)
	}
	if err := h.UninstallSkill(); err != nil {
		t.Errorf("UninstallSkill() = %v, want nil", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("skill not uninstalled: %v", err)
	}
}

func TestOpencodeHarnessXDGAndLegacyPluginMigration(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	h := &OpencodeHarness{}
	legacy := filepath.Join(opencodeConfigDir(), "plugin", "yolonot.ts")
	if err := os.MkdirAll(filepath.Dir(legacy), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, embeddedOpencodePluginTS, 0600); err != nil {
		t.Fatal(err)
	}
	if !h.IsDetected() || !h.IsInstalled() {
		t.Fatal("legacy installation must still be detected")
	}
	if err := h.Install("/path/to/yolonot"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy plugin could cause duplicate policy execution: %v", err)
	}
	if !strings.HasPrefix(h.SettingsPath(), os.Getenv("XDG_CONFIG_HOME")+string(os.PathSeparator)) {
		t.Fatal("XDG_CONFIG_HOME was ignored")
	}
	if err := os.WriteFile(legacy, []byte("// unrelated user plugin named yolonot.ts\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("uninstall must preserve unowned legacy file")
	}
}

func TestOpencodeHarnessNativeAskCapability(t *testing.T) {
	h := &OpencodeHarness{}
	for _, version := range []string{"", "1", "2"} {
		t.Setenv("YOLONOT_OPENCODE_API", version)
		if h.SupportsAsk() != (version == "2") {
			t.Fatalf("API %q capability mismatch", version)
		}
		wantModerate := ActionAllow
		if version == "2" {
			wantModerate = ActionAsk
		}
		if h.RiskMap()[RiskModerate] != wantModerate {
			t.Fatalf("API %q moderate policy mismatch", version)
		}
	}
	t.Setenv("YOLONOT_OPENCODE_SESSION_ID", "")
	t.Setenv("OPENCODE_SESSION_ID", "native-session")
	if h.SessionIDFromEnv() != "native-session" {
		t.Fatal("shell commands must target the session exported by OpenCode V2")
	}
	t.Setenv("YOLONOT_OPENCODE_SESSION_ID", "explicit-override")
	if h.SessionIDFromEnv() != "explicit-override" {
		t.Fatal("explicit session override must win")
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

func TestOpencodeHarnessDecisionlessWarningIsPassthrough(t *testing.T) {
	response := HookResponse{SystemMessage: "yolonot: model unavailable, falling back to host permissions"}
	response.HookSpecificOutput.HookEventName = "PreToolUse"
	if got := (&OpencodeHarness{}).FormatHookResponse(response); got != "" {
		t.Fatalf("trusted no-decision fallback must be empty stdout, got %q", got)
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

// Execute the installed shim, not a copy of its response parser. The child
// hook fixture exercises Bun's actual stdin/stdout/exit-code bridge.
func TestOpencodePluginHookContract(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	requestPath := filepath.Join(home, "request.json")
	t.Setenv("YOLONOT_SHIM_REQUEST", requestPath)
	fixture := filepath.Join(home, "fake-yolonot")
	const hookFixture = "#!/bin/sh\ncat > \"$YOLONOT_SHIM_REQUEST\"\nprintf '%s' \"$YOLONOT_SHIM_REPLY\"\nexit \"$YOLONOT_SHIM_EXIT\"\n"
	if err := os.WriteFile(fixture, []byte(hookFixture), 0700); err != nil {
		t.Fatal(err)
	}
	runShim := installedOpencodeDriver(t, fixture)
	response := func(decision string) string {
		return `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"` + decision + `","permissionDecisionReason":"fixture reason"}}`
	}
	cases := []struct {
		name, event, reply string
		exit               string
		blocked            bool
	}{
		{"intentional empty passthrough", "tool.execute.before", "", "0", false},
		{"whitespace passthrough", "tool.execute.before", " \n", "0", false},
		{"explicit allow", "tool.execute.before", response("allow"), "0", false},
		{"explicit ask defers to host", "tool.execute.before", response("ask"), "0", false},
		{"explicit deny", "tool.execute.before", response("deny"), "0", true},
		{"failure without output", "tool.execute.before", "", "1", true},
		{"failure despite allow output", "tool.execute.before", response("allow"), "7", true},
		{"invalid JSON", "tool.execute.before", "{broken", "0", true},
		{"missing envelope", "tool.execute.before", "{}", "0", true},
		{"null response", "tool.execute.before", "null", "0", true},
		{"array envelope", "tool.execute.before", `{"hookSpecificOutput":[]}`, "0", true},
		{"missing decision", "tool.execute.before", `{"hookSpecificOutput":{}}`, "0", true},
		{"invalid decision", "tool.execute.before", response("permit"), "0", true},
		{"invalid decision type", "tool.execute.before", `{"hookSpecificOutput":{"permissionDecision":true}}`, "0", true},
		{"invalid reason type", "tool.execute.before", `{"hookSpecificOutput":{"permissionDecision":"allow","permissionDecisionReason":42}}`, "0", true},
		{"post tool use empty output", "tool.execute.after", "", "0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YOLONOT_SHIM_REPLY", tc.reply)
			t.Setenv("YOLONOT_SHIM_EXIT", tc.exit)
			shimErr := runShim(tc.event, "/project")
			if blocked := shimErr != ""; blocked != tc.blocked {
				t.Fatalf("blocked=%v, want %v (error=%q)", blocked, tc.blocked, shimErr)
			}
			data, err := os.ReadFile(requestPath)
			if err != nil {
				t.Fatal(err)
			}
			var payload HookPayload
			if err := json.Unmarshal(data, &payload); err != nil {
				t.Fatal(err)
			}
			wantEvent := "PreToolUse"
			if tc.event == "tool.execute.after" {
				wantEvent = "PostToolUse"
				var raw map[string]interface{}
				if err := json.Unmarshal(data, &raw); err != nil {
					t.Fatal(err)
				}
				response, _ := raw["tool_response"].(map[string]interface{})
				if response["output"] != "probe output" || response["title"] != "probe title" {
					t.Error("post-tool-use payload must contain the response")
				}
			}
			if payload.HookEventName != wantEvent || payload.SessionID != "shim-session" || payload.Cwd != "/project" || payload.ToolInput["command"] != "my-tool --probe" {
				t.Errorf("canonical payload lost bridge context: %+v", payload)
			}
		})
	}
}
