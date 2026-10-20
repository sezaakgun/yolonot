package yolonot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeHookResp(event, decision, reason string) HookResponse {
	var r HookResponse
	r.HookSpecificOutput.HookEventName = event
	r.HookSpecificOutput.PermissionDecision = decision
	r.HookSpecificOutput.PermissionDecisionReason = reason
	return r
}

func TestGroupAHarnessesLifecycleAndProtocol(t *testing.T) {
	home, _ := withFakeHome(t)

	// Alias resolution
	aliases := map[string]string{
		"crush":          "crush",
		"qwen-code":      "qwen",
		"qwencode":       "qwen",
		"z-code":         "zcode",
		"github-copilot": "copilot",
		"gh-copilot":     "copilot",
		"grok-build":     "grok",
	}
	for alias, canonical := range aliases {
		h := GetHarness(alias)
		if h == nil || h.Name() != canonical {
			t.Fatalf("GetHarness(%q) = %v, want canonical %q", alias, h, canonical)
		}
	}

	// Install / IsInstalled / Uninstall + Skill lifecycle for all 5 Group A harnesses
	for _, name := range []string{"crush", "qwen", "zcode", "copilot", "grok"} {
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
			t.Fatalf("%s should be detected after Install() creates config dir in %s", name, home)
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
}

func TestGroupAParseAndFormatProtocols(t *testing.T) {
	// 1. Crush: "event": "PreToolUse", "tool_name": "bash"
	crush := GetHarness("crush")
	cp, err := crush.ParseHookInput([]byte(`{"event":"PreToolUse","session_id":"s1","cwd":"/tmp/ws","tool_name":"bash","tool_input":{"command":"git status"}}`))
	if err != nil || cp.ToolInput["command"] != "git status" || cp.HookEventName != "PreToolUse" || cp.SessionID != "s1" {
		t.Fatalf("crush ParseHookInput failed: %+v, err=%v", cp, err)
	}
	if got := crush.FormatHookResponse(makeHookResp("PreToolUse", ActionAllow, "")); !strings.Contains(got, `"permissionDecision":"allow"`) {
		t.Fatalf("crush allow response = %s", got)
	}
	if got := crush.FormatHookResponse(makeHookResp("PreToolUse", ActionDeny, "blocked")); !strings.Contains(got, `"permissionDecision":"deny"`) {
		t.Fatalf("crush deny response = %s", got)
	}
	if crush.RiskMap()["critical"] != "deny" || crush.RiskMap()["low"] != "allow" {
		t.Fatalf("crush RiskMap = %+v", crush.RiskMap())
	}

	// 2. Qwen: dual-phase PreToolUse + PermissionRequest, tool_name: run_shell_command
	qwen := GetHarness("qwen").(*QwenHarness)
	if !qwen.UsesPermissionRequestPhase() {
		t.Fatalf("qwen should use PermissionRequest phase")
	}
	qp, err := qwen.ParseHookInput([]byte(`{"hook_event_name":"PreToolUse","session_id":"qs","cwd":"/tmp/ws","tool_name":"run_shell_command","tool_input":{"command":"npm test"}}`))
	if err != nil || qp.ToolInput["command"] != "npm test" || qp.HookEventName != "PreToolUse" {
		t.Fatalf("qwen PreToolUse parse failed: %+v, err=%v", qp, err)
	}
	if got := qwen.FormatHookResponse(makeHookResp("PreToolUse", ActionAllow, "")); len(got) != 0 {
		t.Fatalf("qwen PreToolUse allow should emit empty stdout so PermissionRequest handles auto-approve, got %s", got)
	}
	if got := qwen.FormatHookResponse(makeHookResp("PreToolUse", ActionAsk, "confirm")); !strings.Contains(got, `"permissionDecision":"ask"`) {
		t.Fatalf("qwen PreToolUse ask = %s", got)
	}
	if got := qwen.FormatHookResponse(makeHookResp("PermissionRequest", ActionAllow, "")); !strings.Contains(got, `"behavior":"allow"`) {
		t.Fatalf("qwen PermissionRequest allow = %s", got)
	}

	// 3. ZCode: dual-case payload, PreToolUse allow/ask/deny
	zcode := GetHarness("zcode")
	zp, err := zcode.ParseHookInput([]byte(`{"hookEventName":"PreToolUse","sessionId":"zs","cwd":"/tmp/ws","toolName":"Bash","toolInput":{"command":"ls -la","dangerouslyDisableSandbox":true}}`))
	if err != nil || zp.ToolInput["command"] != "ls -la" || !zp.BypassSandbox {
		t.Fatalf("zcode parse failed: %+v, err=%v", zp, err)
	}
	if got := zcode.FormatHookResponse(makeHookResp("PreToolUse", ActionAllow, "")); !strings.Contains(got, `"permissionDecision":"allow"`) {
		t.Fatalf("zcode allow = %s", got)
	}

	// 4. Copilot: preToolUse + requestSandboxBypass + native omitted eventName + top-level permissionDecision
	copilot := GetHarness("copilot")
	copP, err := copilot.ParseHookInput([]byte(`{"eventName":"preToolUse","sessionId":"cs","cwd":"/tmp/ws","toolName":"bash","toolArgs":{"command":"cargo test","requestSandboxBypass":true}}`))
	if err != nil || copP.ToolInput["command"] != "cargo test" || copP.HookEventName != "PreToolUse" || !copP.BypassSandbox {
		t.Fatalf("copilot parse failed: %+v, err=%v", copP, err)
	}
	copNoEvent, err := copilot.ParseHookInput([]byte(`{"sessionId":"cs","cwd":"/tmp/ws","toolName":"bash","toolArgs":{"command":"cargo test"}}`))
	if err != nil || copNoEvent.HookEventName != "PreToolUse" || copNoEvent.ToolInput["command"] != "cargo test" {
		t.Fatalf("copilot omitted-eventName preToolUse parse failed: %+v, err=%v", copNoEvent, err)
	}
	copPost, err := copilot.ParseHookInput([]byte(`{"sessionId":"cs","cwd":"/tmp/ws","toolName":"bash","toolArgs":{"command":"cargo test"},"toolResult":{"resultType":"success"}}`))
	if err != nil || copPost.HookEventName != "PostToolUse" {
		t.Fatalf("copilot omitted-eventName postToolUse parse failed: %+v, err=%v", copPost, err)
	}
	if got := copilot.FormatHookResponse(makeHookResp("PreToolUse", ActionAsk, "check")); !strings.Contains(got, `"permissionDecision":"ask"`) || !strings.Contains(got, `"permissionDecisionReason":"check"`) {
		t.Fatalf("copilot ask = %s", got)
	}

	// 5. Grok: camelCase run_terminal_command on both GrokHarness and ClaudeHarness (compat mode)
	grokPayload := []byte(`{"hookEventName":"pre_tool_use","hook_event_name":"PreToolUse","sessionId":"gs","cwd":"/tmp/ws","toolName":"run_terminal_command","toolInput":{"command":"go test ./..."}}`)
	grok := GetHarness("grok")
	gp, err := grok.ParseHookInput(grokPayload)
	if err != nil || gp.ToolInput["command"] != "go test ./..." || gp.SessionID != "gs" {
		t.Fatalf("grok parse failed: %+v, err=%v", gp, err)
	}
	claude := GetHarness("claude")
	cpCompat, err := claude.ParseHookInput(grokPayload)
	if err != nil || cpCompat.ToolInput["command"] != "go test ./..." || cpCompat.SessionID != "gs" {
		t.Fatalf("claude compat parse for grok camelCase payload failed: %+v, err=%v", cpCompat, err)
	}
}

func TestGroupADiscoverHostPermissions(t *testing.T) {
	home, _ := withFakeHome(t)
	ws := filepath.Join(home, "workspace")
	_ = os.MkdirAll(ws, 0o755)

	// Crush config
	crushDir := filepath.Join(home, ".config", "crush")
	_ = os.MkdirAll(crushDir, 0o755)
	_ = os.WriteFile(filepath.Join(crushDir, "crush.json"), []byte(`{"permissions":{"allowed_tools":["bash"]}}`), 0o600)

	// Qwen config
	qwenDir := filepath.Join(home, ".qwen")
	_ = os.MkdirAll(qwenDir, 0o755)
	_ = os.WriteFile(filepath.Join(qwenDir, "settings.json"), []byte(`{
		"tools": {"approvalMode": "yolo", "sandbox": false},
		"permissions": {
			"allow": ["run_shell_command(git status:*)"],
			"autoMode": {"hints": {"allow": ["Allow local tests"]}}
		}
	}`), 0o600)

	// ZCode config
	zcodeDir := filepath.Join(home, ".zcode", "cli")
	_ = os.MkdirAll(zcodeDir, 0o755)
	_ = os.WriteFile(filepath.Join(zcodeDir, "setting.json"), []byte(`{"permission":{"mode":"yolo","allowedTools":["Bash"]}}`), 0o600)

	// Copilot config
	copilotDir := filepath.Join(home, ".copilot")
	_ = os.MkdirAll(copilotDir, 0o755)
	_ = os.WriteFile(filepath.Join(copilotDir, "settings.json"), []byte(`{
		"defaultMode": "autopilot",
		"sandbox": {"enabled": false},
		"permissions": {"allow": ["Bash(npm test:*)"]}
	}`), 0o600)

	// Grok config
	grokDir := filepath.Join(home, ".grok")
	_ = os.MkdirAll(grokDir, 0o755)
	_ = os.WriteFile(filepath.Join(grokDir, "config.toml"), []byte(`
[ui]
permission_mode = "always-approve"
[sandbox]
profile = "off"
[permission]
allow = ["Bash(cargo check:*)"]
`), 0o600)

	summary := DiscoverHostPermissions(ws)
	found := map[string]bool{}
	for _, hf := range summary.HostFiles {
		found[hf.Harness] = true
	}
	for _, name := range []string{"crush", "qwen", "zcode", "copilot", "grok"} {
		if !found[name] {
			t.Errorf("DiscoverHostPermissions did not find %s host file; got %+v", name, summary.HostFiles)
		}
	}
}
