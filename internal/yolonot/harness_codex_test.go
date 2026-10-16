package yolonot

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
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
	// This adapter defers allows to the host's permission engine, emitting
	// an empty string so emitHook() skips stdout entirely.
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
	if !strings.Contains(s, "hooks = true") {
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
	if strings.Count(string(cfg2), "hooks = true") != 1 {
		t.Errorf("duplicate feature flag after reinstall: %s", string(cfg2))
	}
}

func TestCodexHarnessInstallSkill(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	h := &CodexHarness{}
	path, err := h.InstallSkill()
	if err != nil || !strings.HasSuffix(path, filepath.Join(".agents", "skills", "yolonot")) {
		t.Fatalf("InstallSkill() = (%q, %v)", path, err)
	}
	if _, err := os.Stat(filepath.Join(path, "SKILL.md")); err != nil {
		t.Fatal(err)
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

func TestCodexHookFlagsPreserveTOML(t *testing.T) {
	cases := []struct {
		name, before, after string
	}{
		{"empty", "", "[features]\nhooks = true\n"},
		{"existing table", "[features]\nshell_snapshot = true\n[other]\nx = 1\n", "[features]\nhooks = true\nshell_snapshot = true\n[other]\nx = 1\n"},
		{"legacy false", "[features]\ncodex_hooks = false # intentional comment\n", "[features]\nhooks = true # intentional comment\n"},
		{"modern false", "[features]\nhooks = false # modern name\n", "[features]\nhooks = true # modern name\n"},
		{"both false", "[features]\nhooks = false\ncodex_hooks = false\n", "[features]\nhooks = true\n# deprecated alias: codex_hooks = false\n"},
		{"already enabled", "[features]\nhooks = true # retained\n", "[features]\nhooks = true # retained\n"},
		{"comment is not a flag", "# codex_hooks = true\nmodel = 'm'\n", "# codex_hooks = true\nmodel = 'm'\n[features]\nhooks = true\n"},
		{"multiline string is not config", "note = '''\n[features]\ncodex_hooks = true\n'''\n", "note = '''\n[features]\ncodex_hooks = true\n'''\n[features]\nhooks = true\n"},
		{"quoted keys", "['features'] # keep header\n\"codex_hooks\" = false # keep key\n", "['features'] # keep header\n\"hooks\" = true # keep key\n"},
		{"escaped legacy key", "[features]\n\"codex\\u005fhooks\" = true\n", "[features]\n\"hooks\" = true\n"},
		{"legacy true", "[features]\ncodex_hooks = true # retain\n", "[features]\nhooks = true # retain\n"},
		{"legacy dotted", "features.'codex_hooks' = false\n", "features.'hooks' = true\n"},
		{"legacy inline", "features = { codex_hooks = false, other = true }\n", "features = { hooks = true, other = true }\n"},
		{"both inline first", "features = {codex_hooks = false, hooks = false, other = true}\n", "features = { hooks = true, other = true}\n"},
		{"both inline last", "features = {hooks = false, other = true, codex_hooks = true}\n", "features = {hooks = true, other = true}\n"},
		{"both dotted", "features.codex_hooks = true # old\nfeatures.hooks = false\n", "# deprecated alias: features.codex_hooks = true # old\nfeatures.hooks = true\n"},
		{"dotted flag", "features.'hooks' = false\n", "features.'hooks' = true\n"},
		{"dotted features", "features.shell_snapshot = true\n", "features.hooks = true\nfeatures.shell_snapshot = true\n"},
		{"implicit parent", "[features.custom]\nenabled = true\n", "features.hooks = true\n[features.custom]\nenabled = true\n"},
		{"inline empty", "features = {} # keep\n", "features = {hooks = true} # keep\n"},
		{"inline missing", "features = { other = true } # keep\n", "features = {hooks = true,  other = true } # keep\n"},
		{"inline false", "features = { 'hooks' = false, nested = { hooks = false } }\n", "features = { 'hooks' = true, nested = { hooks = false } }\n"},
		{"nested unrelated features", "[profiles.dev.features]\nhooks = false\n", "[profiles.dev.features]\nhooks = false\n[features]\nhooks = true\n"},
		{"header without newline", "[features] # keep", "[features] # keep\nhooks = true\n"},
		{"CRLF", "[features]\r\nother = true\r\n", "[features]\r\nhooks = true\r\nother = true\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			updated, err := enableCodexHookFlags([]byte(tc.before))
			if err != nil {
				t.Fatal(err)
			}
			if string(updated) != tc.after {
				t.Fatalf("unrelated formatting changed:\n got: %q\nwant: %q", updated, tc.after)
			}
			var parsed map[string]interface{}
			if err := toml.Unmarshal(updated, &parsed); err != nil {
				t.Fatal(err)
			}
			features := parsed["features"].(map[string]interface{})
			if features["hooks"] != true || features["codex_hooks"] != nil {
				t.Fatalf("no enabled hook flag: %#v", features)
			}
			again, err := enableCodexHookFlags(updated)
			if err != nil || !bytes.Equal(again, updated) {
				t.Fatalf("not idempotent: %q, %v", again, err)
			}
		})
	}
}

func TestCodexHarnessInstallRejectsInvalidConfigWithoutChangingIt(t *testing.T) {
	for _, content := range []string{
		"[features]\n[features]\n",
		"features = false\n",
		"[features]\nhooks = 'false'\n",
	} {
		t.Run(content, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			path := filepath.Join(home, ".codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			h := &CodexHarness{}
			if err := h.Install("/test/yolonot"); err == nil {
				t.Fatal("install must report invalid config")
			}
			got, _ := os.ReadFile(path)
			if string(got) != content || h.IsInstalled() {
				t.Fatal("invalid config or hook registration changed on failed install")
			}
		})
	}
}

func TestCodexHarnessFeatureWriteRefusesSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	outside := filepath.Join(t.TempDir(), "config.toml")
	const content = "[features]\nhooks = false\n"
	if err := os.WriteFile(outside, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if err := (&CodexHarness{}).Install("/test/yolonot"); err == nil {
		t.Fatal("install must surface config write failure")
	}
	got, _ := os.ReadFile(outside)
	if string(got) != content {
		t.Fatal("symlink target changed")
	}
}

func TestCodexHarnessGeneratedConfigLoadsInInstalledCodex(t *testing.T) {
	bin, err := exec.LookPath("codex")
	if err != nil {
		t.Skip("Codex CLI not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[features]\nshell_snapshot = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&CodexHarness{}).Install("/test/yolonot"); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions widened: %o", info.Mode().Perm())
	}
	if output, err := exec.Command(bin, "features", "list").CombinedOutput(); err != nil {
		t.Fatalf("installed Codex rejects generated config: %v\n%s", err, output)
	}
}

func TestRemoveHooksWithoutHooksKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CODEX_HOME", dir)
	t.Setenv("CLAUDE_CONFIG_DIR", dir)
	os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(`{}`), 0644)
	os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"theme":"dark"}`), 0644)
	if err := (&CodexHarness{}).removeHooks(); err != nil {
		t.Fatal(err)
	}
	if err := (&ClaudeHarness{}).removeHooks(); err != nil {
		t.Fatal(err)
	}
}

func TestCodexPostAfterAskCannotInventHumanApproval(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "codex")
	t.Setenv("YOLONOT_MOD", "")
	writeGlobalRules(t, home, "ask-cmd touch *ASK*\n")
	cwd := t.TempDir()
	sid, command := "codex-deferred-ask", "touch ASK.marker"
	runHookWithStruct(t, makePrePayload(sid, command, cwd))
	project := ProjectSessionID(sid, cwd)
	if !ContainsLine(project, "asked", command) {
		t.Fatal("ask was not recorded as pending")
	}
	post := makePostPayloadStruct(sid, command)
	post.Cwd = cwd
	runHookWithStruct(t, post)
	if ContainsLine(project, "asked", command) {
		t.Fatal("pending ask survived the completed call")
	}
	for _, entry := range ReadRecentDecisions(100) {
		if entry.SessionID == sid && entry.Layer == "human" {
			t.Fatalf("invented human verdict: %+v", entry)
		}
	}
}
