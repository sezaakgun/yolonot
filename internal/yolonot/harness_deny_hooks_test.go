package yolonot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupCHarnessesLifecycleAndProtocol(t *testing.T) {
	home, _ := withFakeHome(t)

	for alias, canonical := range map[string]string{
		"kimi-code":  "kimi",
		"kimi-cli":   "kimi",
		"devin-cli":  "devin",
		"fusion":     "devin",
		"muse-code":  "muse",
		"musecode":   "muse",
		"open-hands": "openhands",
		"kiro-cli":   "kiro",
	} {
		h := GetHarness(alias)
		if h == nil || h.Name() != canonical {
			t.Fatalf("GetHarness(%q) = %v, want %q", alias, h, canonical)
		}
	}

	for _, name := range []string{"kimi", "devin", "muse", "goose", "openhands", "kiro", "cline"} {
		h := GetHarness(name)
		if h == nil {
			t.Fatalf("missing harness %s", name)
		}
		if h.IsInstalled() {
			t.Fatalf("%s should not be installed initially", name)
		}
		if err := h.Install("/usr/local/bin/yolonot"); err != nil {
			t.Fatalf("%s Install() failed: %v", name, err)
		}
		if !h.IsInstalled() {
			t.Fatalf("%s should be installed after Install()", name)
		}
		if !h.IsDetected() {
			t.Fatalf("%s should be detected in %s after Install()", name, home)
		}
		if _, err := h.InstallSkill(); err != nil {
			t.Fatalf("%s InstallSkill() failed: %v", name, err)
		}
		if err := h.UninstallSkill(); err != nil {
			t.Fatalf("%s UninstallSkill() failed: %v", name, err)
		}
		if err := h.Uninstall(); err != nil {
			t.Fatalf("%s Uninstall() failed: %v", name, err)
		}
		if h.IsInstalled() {
			t.Fatalf("%s should not be installed after Uninstall()", name)
		}
	}

	// 8. Kimi: deny-only
	kimi := GetHarness("kimi")
	if got := kimi.FormatHookResponse(makeHookResp("PreToolUse", ActionAllow, "")); got != "" {
		t.Fatalf("kimi allow should be empty, got %q", got)
	}
	if got := kimi.FormatHookResponse(makeHookResp("PreToolUse", ActionDeny, "bad")); !strings.Contains(got, `"permissionDecision":"deny"`) {
		t.Fatalf("kimi deny = %s", got)
	}

	// 9. Devin: tool_name: exec, full allow/ask/deny + omitted cwd fallback to os.Getwd()
	devin := GetHarness("devin")
	dp, err := devin.ParseHookInput([]byte(`{"hook_event_name":"PreToolUse","session_id":"dv1","tool_name":"exec","tool_input":{"command":"cargo build"}}`))
	if err != nil || dp.ToolInput["command"] != "cargo build" || dp.Cwd == "" {
		t.Fatalf("devin parse with omitted cwd failed: %+v, err=%v", dp, err)
	}
	if got := devin.FormatHookResponse(makeHookResp("PreToolUse", ActionAllow, "")); !strings.Contains(got, `"permissionDecision":"allow"`) {
		t.Fatalf("devin allow = %s", got)
	}

	// 10. Muse: dual-phase PreToolUse + PermissionRequest, bare allow on PreToolUse must be empty, deny must have non-empty reason
	muse := GetHarness("muse").(*MuseHarness)
	if !muse.UsesPermissionRequestPhase() {
		t.Fatalf("muse should use PermissionRequest phase")
	}
	if err := muse.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatalf("muse Install: %v", err)
	}
	museSettings, err := os.ReadFile(filepath.Join(home, ".config", "muse", "settings.json"))
	if err != nil || !strings.Contains(string(museSettings), `"schema_version"`) {
		t.Fatalf("muse settings.json unexpected: err=%v, body=%s", err, string(museSettings))
	}
	_ = muse.Uninstall()
	if got := muse.FormatHookResponse(makeHookResp("PreToolUse", ActionAllow, "")); got != "" {
		t.Fatalf("muse PreToolUse allow must emit empty stdout (bare allow is rejected by Muse), got %q", got)
	}
	if got := muse.FormatHookResponse(makeHookResp("PermissionRequest", ActionAllow, "")); !strings.Contains(got, `"behavior":"allow"`) {
		t.Fatalf("muse PermissionRequest allow = %s", got)
	}
	if got := muse.FormatHookResponse(makeHookResp("PreToolUse", ActionDeny, "")); !strings.Contains(got, `"Blocked by yolonot"`) {
		t.Fatalf("muse PreToolUse deny must populate non-empty reason, got %s", got)
	}

	// 11. Goose: event + working_dir, empty stdout on allow, {"decision":"block"} on deny
	goose := GetHarness("goose")
	gp, err := goose.ParseHookInput([]byte(`{"event":"PreToolUse","session_id":"gs1","tool_name":"shell","tool_input":{"command":"ls"},"working_dir":"/tmp/ws"}`))
	if err != nil || gp.HookEventName != "PreToolUse" || gp.Cwd != "/tmp/ws" || gp.ToolInput["command"] != "ls" {
		t.Fatalf("goose parse failed: %+v, err=%v", gp, err)
	}
	if got := goose.FormatHookResponse(makeHookResp("PreToolUse", ActionAllow, "")); got != "" {
		t.Fatalf("goose allow must emit empty stdout, got %q", got)
	}
	if got := goose.FormatHookResponse(makeHookResp("PreToolUse", ActionDeny, "stop")); !strings.Contains(got, `"decision":"block"`) {
		t.Fatalf("goose deny = %s", got)
	}

	// 12. OpenHands: event_type: PreToolUse, tool_name: terminal, {"decision":"deny"}
	oh := GetHarness("openhands")
	ohp, err := oh.ParseHookInput([]byte(`{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"pwd"},"session_id":"oh1","working_dir":"/tmp/ws"}`))
	if err != nil || ohp.HookEventName != "PreToolUse" || ohp.ToolInput["command"] != "pwd" {
		t.Fatalf("openhands parse failed: %+v, err=%v", ohp, err)
	}
	if got := oh.FormatHookResponse(makeHookResp("PreToolUse", ActionDeny, "no")); !strings.Contains(got, `"decision":"deny"`) {
		t.Fatalf("openhands deny = %s", got)
	}

	// 13. Kiro: ExitTwoOnDeny() = true, matcher: "execute_bash", settings/cli.json chat.defaultAgent: "default"
	kiro := GetHarness("kiro")
	if !harnessExitTwoOnDeny(kiro) {
		t.Fatalf("kiro must set ExitTwoOnDeny() = true")
	}
	if err := kiro.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatalf("kiro Install: %v", err)
	}
	kiroAgent, err := os.ReadFile(filepath.Join(home, ".kiro", "agents", "default.json"))
	if err != nil || !strings.Contains(string(kiroAgent), `"matcher": "execute_bash"`) {
		t.Fatalf("kiro default.json matcher unexpected: err=%v, body=%s", err, string(kiroAgent))
	}
	kiroCLI, err := os.ReadFile(filepath.Join(home, ".kiro", "settings", "cli.json"))
	if err != nil || !strings.Contains(string(kiroCLI), `"chat.defaultAgent": "default"`) {
		t.Fatalf("kiro cli.json chat.defaultAgent unexpected: err=%v, body=%s", err, string(kiroCLI))
	}
	_ = kiro.Uninstall()
	if got := kiro.FormatHookResponse(makeHookResp("PreToolUse", ActionAllow, "")); got != "" {
		t.Fatalf("kiro allow must emit empty stdout, got %q", got)
	}
	if got := kiro.FormatHookResponse(makeHookResp("PreToolUse", ActionDeny, "no")); got != "no" {
		t.Fatalf("kiro deny must return plaintext reason for stderr, got %q", got)
	}

	// 14. Cline: hookName: tool_call / tool_result + run_commands array -> joined with \n, {"cancel":true,"errorMessage":...}
	cline := GetHarness("cline")
	cp, err := cline.ParseHookInput([]byte(`{"hookName":"tool_call","taskId":"t1","workspaceRoots":["/tmp/ws"],"tool_call":{"id":"c1","name":"run_commands","input":{"commands":["git status","npm test"]}}}`))
	if err != nil || cp.HookEventName != "PreToolUse" || cp.ToolInput["command"] != "git status\nnpm test" || cp.Cwd != "/tmp/ws" {
		t.Fatalf("cline multi-command parse failed: %+v, err=%v", cp, err)
	}
	cpComment, err := cline.ParseHookInput([]byte(`{"hookName":"tool_call","taskId":"t1","workspaceRoots":["/tmp/ws"],"tool_call":{"id":"c2","name":"run_commands","input":{"commands":["ls # comment","rm -rf /"]}}}`))
	if err != nil || !hasChainOperator(cpComment.ToolInput["command"].(string)) || len(splitSegments(cpComment.ToolInput["command"].(string))) != 2 {
		t.Fatalf("cline multi-command with # comment must split into 2 segments: %+v, err=%v", cpComment, err)
	}
	cpPost, err := cline.ParseHookInput([]byte(`{"hookName":"tool_result","taskId":"t1","workspaceRoots":["/tmp/ws"],"tool_result":{"id":"c1","name":"execute_command","input":{"command":"git status"}}}`))
	if err != nil || cpPost.HookEventName != "PostToolUse" || cpPost.ToolName != "execute_command" || cpPost.ToolInput["command"] != "git status" {
		t.Fatalf("cline tool_result parse failed: %+v, err=%v", cpPost, err)
	}
	if got := cline.FormatHookResponse(makeHookResp("PreToolUse", ActionDeny, "halt")); !strings.Contains(got, `"cancel":true`) {
		t.Fatalf("cline deny = %s", got)
	}
}

func TestGroupCDiscoverHostPermissions(t *testing.T) {
	home, _ := withFakeHome(t)
	ws := filepath.Join(home, "workspace")
	_ = os.MkdirAll(ws, 0o755)

	// Kimi
	kimiDir := filepath.Join(home, ".kimi-code")
	_ = os.MkdirAll(kimiDir, 0o755)
	_ = os.WriteFile(filepath.Join(kimiDir, "config.toml"), []byte("default_permission_mode = \"auto\"\n[[permission.rules]]\ndecision = \"allow\"\npattern = \"Bash(git status:*)\"\n"), 0o600)

	// Devin
	devinDir := filepath.Join(home, ".config", "devin")
	_ = os.MkdirAll(devinDir, 0o755)
	_ = os.WriteFile(filepath.Join(devinDir, "config.json"), []byte(`{"permissions":{"allow":["Exec(git status)"]}, "sandbox":{"excluded":{"allow":["Exec(docker *)"]}}}`), 0o600)

	// Muse
	museDir := filepath.Join(home, ".config", "muse")
	_ = os.MkdirAll(museDir, 0o755)
	_ = os.WriteFile(filepath.Join(museDir, "settings.json"), []byte(`{"permissions":{"default_profile":":unrestricted"}}`), 0o600)
	_ = os.WriteFile(filepath.Join(museDir, "approval-policy.json"), []byte(`{"rules":[{"effect":"allow","rule":{"kind":"shell_command_argv_prefix","argv_prefix":["git","status"]}}]}`), 0o600)

	// Goose
	gooseDir := filepath.Join(home, ".config", "goose")
	_ = os.MkdirAll(gooseDir, 0o755)
	_ = os.WriteFile(filepath.Join(gooseDir, "permission.yaml"), []byte("user:\n  always_allow:\n    - shell\n"), 0o600)

	// OpenHands
	ohDir := filepath.Join(home, ".openhands")
	_ = os.MkdirAll(ohDir, 0o755)
	_ = os.WriteFile(filepath.Join(ohDir, "agent_settings.json"), []byte(`{"security_policy_filename":""}`), 0o600)

	// Kiro
	kiroDir := filepath.Join(home, ".kiro", "settings")
	_ = os.MkdirAll(kiroDir, 0o755)
	_ = os.WriteFile(filepath.Join(kiroDir, "cli.json"), []byte(`{"chat.disableTrustAllConfirmation":true}`), 0o600)

	// Cline
	clineDir := filepath.Join(home, ".cline", "data", "settings")
	_ = os.MkdirAll(clineDir, 0o755)
	_ = os.WriteFile(filepath.Join(clineDir, "global-settings.json"), []byte(`{"toolAutoApprove":true,"yolo":true}`), 0o600)

	summary := DiscoverHostPermissions(ws)
	found := map[string]bool{}
	for _, hf := range summary.HostFiles {
		found[hf.Harness] = true
	}
	for _, name := range []string{"kimi", "devin", "muse", "goose", "openhands", "kiro", "cline"} {
		if !found[name] {
			t.Errorf("DiscoverHostPermissions did not find %s; got %+v", name, summary.HostFiles)
		}
	}
}
