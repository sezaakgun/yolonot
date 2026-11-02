package yolonot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroupDHarnessesLifecycleAndProtocol(t *testing.T) {
	home, _ := withFakeHome(t)

	for alias, canonical := range map[string]string{
		"kilocode":          "kilo",
		"kilo-code":         "kilo",
		"open-claw":         "openclaw",
		"pi-coding-agent":   "pi",
		"reflection-mirror": "mirror",
		"ampcode":           "amp",
	} {
		h := GetHarness(alias)
		if h == nil || h.Name() != canonical {
			t.Fatalf("GetHarness(%q) = %v, want %q", alias, h, canonical)
		}
	}

	for _, name := range []string{"kilo", "openclaw", "pi", "mirror", "amp"} {
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

	// OpenClaw elevated / gateway host sandbox bypass detection + ctx sessionId/cwd in shim
	oc := GetHarness("openclaw")
	if err := oc.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatalf("openclaw Install: %v", err)
	}
	ocShim, err := os.ReadFile(filepath.Join(home, ".openclaw", "extensions", "yolonot", "index.js"))
	if err != nil || !strings.Contains(string(ocShim), "ctx.sessionId") || !strings.Contains(string(ocShim), "ctx.cwd") {
		t.Fatalf("openclaw index.js missing ctx.sessionId / ctx.cwd: err=%v, body=%s", err, string(ocShim))
	}
	_ = oc.Uninstall()
	ocp, err := oc.ParseHookInput([]byte(`{"hook_event_name":"PreToolUse","tool_name":"exec","session_id":"oc1","cwd":"/tmp/ws","tool_input":{"command":"docker ps","elevated":true}}`))
	if err != nil || ocp.ToolInput["command"] != "docker ps" || !ocp.BypassSandbox {
		t.Fatalf("openclaw elevated parse failed: %+v, err=%v", ocp, err)
	}
	ocpHost, err := oc.ParseHookInput([]byte(`{"hook_event_name":"PreToolUse","tool_name":"exec","session_id":"oc1","cwd":"/tmp/ws","tool_input":{"command":"docker ps","host":"gateway"}}`))
	if err != nil || !ocpHost.BypassSandbox {
		t.Fatalf("openclaw gateway host parse failed: %+v, err=%v", ocpHost, err)
	}

	// Amp cmd field normalization
	amp := GetHarness("amp")
	ap, err := amp.ParseHookInput([]byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"amp1","cwd":"/tmp/ws","tool_input":{"cmd":"pnpm test"}}`))
	if err != nil || ap.ToolInput["command"] != "pnpm test" {
		t.Fatalf("amp cmd parse failed: %+v, err=%v", ap, err)
	}
	if got := amp.FormatHookResponse(makeHookResp("PreToolUse", ActionAsk, "confirm")); !strings.Contains(got, `"permissionDecision":"ask"`) {
		t.Fatalf("amp ask = %s", got)
	}
}

func TestGroupDDiscoverHostPermissions(t *testing.T) {
	home, _ := withFakeHome(t)
	ws := filepath.Join(home, "workspace")
	_ = os.MkdirAll(ws, 0o755)

	// Kilo Code
	kiloDir := filepath.Join(home, ".config", "kilo")
	_ = os.MkdirAll(kiloDir, 0o755)
	_ = os.WriteFile(filepath.Join(kiloDir, "kilo.json"), []byte(`{"permission":{"bash":"allow"},"sandbox":{"enabled":false}}`), 0o600)

	// OpenClaw
	ocDir := filepath.Join(home, ".openclaw")
	_ = os.MkdirAll(ocDir, 0o755)
	_ = os.WriteFile(filepath.Join(ocDir, "openclaw.json"), []byte(`{"tools":{"exec":{"mode":"full","safeBins":["git"]}},"agents":{"defaults":{"sandbox":{"mode":"off"}}}}`), 0o600)

	// Pi
	piDir := filepath.Join(home, ".pi", "agent")
	_ = os.MkdirAll(piDir, 0o755)
	_ = os.WriteFile(filepath.Join(piDir, "settings.json"), []byte(`{"defaultProjectTrust":"always"}`), 0o600)

	// Mirror
	mirrorDir := filepath.Join(home, ".mirror")
	_ = os.MkdirAll(mirrorDir, 0o755)
	_ = os.WriteFile(filepath.Join(mirrorDir, "config.json"), []byte(`{"approval_mode":"auto"}`), 0o600)

	// Amp
	ampDir := filepath.Join(home, ".config", "amp")
	_ = os.MkdirAll(ampDir, 0o755)
	_ = os.WriteFile(filepath.Join(ampDir, "settings.json"), []byte(`{"amp.dangerouslyAllowAll":true,"amp.permissions":[{"tool":"Bash","action":"reject","matches":{"cmd":"rm -rf *"}}]}`), 0o600)

	summary := DiscoverHostPermissions(ws)
	found := map[string]bool{}
	for _, hf := range summary.HostFiles {
		found[hf.Harness] = true
	}
	for _, name := range []string{"kilo", "openclaw", "pi", "mirror", "amp"} {
		if !found[name] {
			t.Errorf("DiscoverHostPermissions did not find %s; got %+v", name, summary.HostFiles)
		}
	}
}
