package yolonot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupBHarnessesLifecycleAndProtocol(t *testing.T) {
	home, _ := withFakeHome(t)

	for alias, canonical := range map[string]string{
		"dsh":              "deepseek",
		"deepseek-harness": "deepseek",
		"hermes-agent":     "hermes",
	} {
		h := GetHarness(alias)
		if h == nil || h.Name() != canonical {
			t.Fatalf("GetHarness(%q) = %v, want %q", alias, h, canonical)
		}
	}

	for _, name := range []string{"deepseek", "hermes"} {
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

	// DeepSeek Harness protocol + sandbox_permissions: danger-full-access
	dsh := GetHarness("deepseek")
	dp, err := dsh.ParseHookInput([]byte(`{"hook_event_name":"PreToolUse","session_id":"ds1","cwd":"/tmp/ws","tool_name":"bash","tool_input":{"command":"pytest","sandbox_permissions":"danger-full-access"}}`))
	if err != nil || dp.ToolInput["command"] != "pytest" || !dp.BypassSandbox {
		t.Fatalf("deepseek parse failed: %+v, err=%v", dp, err)
	}
	if got := dsh.FormatHookResponse(makeHookResp("PreToolUse", ActionAllow, "")); got != "" {
		t.Fatalf("deepseek allow should emit empty stdout, got %q", got)
	}
	if got := dsh.FormatHookResponse(makeHookResp("PreToolUse", ActionAsk, "confirm")); !strings.Contains(got, `"permissionDecision":"ask"`) {
		t.Fatalf("deepseek ask = %s", got)
	}

	// Hermes protocol: pre_tool_call -> PreToolUse, action: approve / block
	hermes := GetHarness("hermes")
	hp, err := hermes.ParseHookInput([]byte(`{"hook_event_name":"pre_tool_call","session_id":"hs1","cwd":"/tmp/ws","tool_name":"terminal","tool_input":{"command":"git push --force"}}`))
	if err != nil || hp.HookEventName != "PreToolUse" || hp.ToolInput["command"] != "git push --force" {
		t.Fatalf("hermes parse failed: %+v, err=%v", hp, err)
	}
	if got := hermes.FormatHookResponse(makeHookResp("PreToolUse", ActionAsk, "needs review")); !strings.Contains(got, `"action":"approve"`) {
		t.Fatalf("hermes ask should emit action:approve, got %s", got)
	}
	if got := hermes.FormatHookResponse(makeHookResp("PreToolUse", ActionDeny, "blocked")); !strings.Contains(got, `"action":"block"`) {
		t.Fatalf("hermes deny should emit action:block, got %s", got)
	}
	if got := hermes.FormatHookResponse(makeHookResp("PreToolUse", ActionAllow, "")); got != "" {
		t.Fatalf("hermes allow should emit empty stdout, got %s", got)
	}
}

func TestGroupBDiscoverHostPermissions(t *testing.T) {
	home, _ := withFakeHome(t)
	ws := filepath.Join(home, "workspace")
	_ = os.MkdirAll(ws, 0o755)

	dshDir := filepath.Join(home, ".dsh")
	_ = os.MkdirAll(dshDir, 0o755)
	_ = os.WriteFile(filepath.Join(dshDir, "cordis.patch.yml"), []byte("plugins:\n  - id: sandbox-policy\n    config:\n      mode: danger-full-access\n"), 0o600)

	hermesDir := filepath.Join(home, ".hermes")
	_ = os.MkdirAll(hermesDir, 0o755)
	_ = os.WriteFile(filepath.Join(hermesDir, "config.yaml"), []byte("command_allowlist:\n  - \"git status\"\napprovals:\n  mode: off\n  deny:\n    - \"rm -rf /\"\nterminal:\n  backend: local\n"), 0o600)

	summary := DiscoverHostPermissions(ws)
	found := map[string]bool{}
	for _, hf := range summary.HostFiles {
		found[hf.Harness] = true
	}
	for _, name := range []string{"deepseek", "hermes"} {
		if !found[name] {
			t.Errorf("DiscoverHostPermissions did not find %s; got %+v", name, summary.HostFiles)
		}
	}
}
