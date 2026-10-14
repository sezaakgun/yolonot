package yolonot

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAntigravityHarnessPayloadAndDecisions(t *testing.T) {
	h := &AntigravityHarness{}
	if GetHarness(h.Name()) == nil {
		t.Fatal("Antigravity adapter not registered")
	}
	input := `{"toolCall":{"name":"run_command","args":{"CommandLine":"npm test","Cwd":"/workspace/project"}},"stepIdx":19,"conversationId":"agy-conversation","workspacePaths":["/workspace/project"]}`
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		os.Args = []string{"yolonot", "hook", "--harness", "antigravity", "--hook-event", event}
		payload, err := h.ParseHookInput([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		if payload.HookEventName != event || payload.SessionID != "agy-conversation" || payload.Cwd != "/workspace/project" || payload.ToolName != "Bash" || payload.ToolInput["command"] != "npm test" {
			t.Fatalf("canonical context lost: %+v", payload)
		}
	}
	for canonical, native := range map[string]string{ActionAllow: "auto_approve", ActionAsk: "force_ask", ActionDeny: ActionDeny} {
		response := buildHookResponse(canonical, "rule", "test reason", "test command")
		var wire map[string]interface{}
		if err := json.Unmarshal([]byte(h.FormatHookResponse(response)), &wire); err != nil {
			t.Fatal(err)
		}
		if wire["decision"] != native || wire["reason"] == "" {
			t.Fatalf("%s was not translated to %s: %#v", canonical, native, wire)
		}
	}
	if h.FormatHookResponse(HookResponse{}) != "" {
		t.Fatal("no decision must preserve host policy")
	}
	if payload, err := h.ParseHookInput([]byte(`{"toolCall":{"name":"write_to_file","args":{}}}`)); err != nil || payload.ToolName != "" {
		t.Fatal("non-shell tool must not pass through shell policy")
	}
}

func TestAntigravityHarnessPayloadRequiresKnownCwd(t *testing.T) {
	h := &AntigravityHarness{}
	input := `{"toolCall":{"name":"run_command","args":{"CommandLine":"npm test"}},"workspacePaths":["/project"]}`
	if p, err := h.ParseHookInput([]byte(input)); err != nil || p.Cwd != "/project" {
		t.Fatalf("single workspace fallback failed: %+v %v", p, err)
	}
	input = strings.ReplaceAll(input, `["/project"]`, `["/project","/other"]`)
	if _, err := h.ParseHookInput([]byte(input)); err == nil {
		t.Fatal("multiple workspaces must not guess the command directory")
	}
}

func TestAntigravityHarnessInstallPreservesOtherHooksAndIsIdempotent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	h := &AntigravityHarness{}
	path := h.SettingsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	other := map[string]interface{}{"PreInvocation": []interface{}{map[string]interface{}{"command": "other-command"}}, "enabled": false}
	before, _ := json.Marshal(map[string]interface{}{"other": other})
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := h.Install("/scratch/path with ' quotes/yolonot"); err != nil {
			t.Fatal(err)
		}
	}
	if !h.IsInstalled() {
		t.Fatal("installed hook not detected")
	}
	config, err := h.loadHooks()
	if err != nil {
		t.Fatal(err)
	}
	otherAfter, _ := json.Marshal(config["other"])
	otherBefore, _ := json.Marshal(other)
	if !bytes.Equal(otherAfter, otherBefore) || len(config) != 2 {
		t.Fatalf("unrelated hooks changed: %s", otherAfter)
	}
	definition := config[antigravityHookName].(map[string]interface{})
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		groups := definition[event].([]interface{})
		if len(groups) != 1 {
			t.Fatalf("duplicate %s handlers: %#v", event, groups)
		}
		group := groups[0].(map[string]interface{})
		handlers := group["hooks"].([]interface{})
		handler := handlers[0].(map[string]interface{})
		if group["matcher"] != "^run_command$" || handler["timeout"] != float64(60) || !strings.Contains(handler["command"].(string), "--hook-event "+event) {
			t.Fatalf("invalid installed hook: %#v", group)
		}
	}
	if err := h.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if h.IsInstalled() {
		t.Fatal("uninstall left the shell gate registered")
	}
	config, _ = h.loadHooks()
	if len(config) != 1 || config["other"] == nil {
		t.Fatal("uninstall removed another named hook")
	}
	if err := h.Uninstall(); err != nil {
		t.Fatal(err)
	}
}

func TestAntigravityInstallRejectsInvalidJSONAndSymlink(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	h := &AntigravityHarness{}
	path := h.SettingsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	invalid := []byte(`{"other":broken}`)
	if err := os.WriteFile(path, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.Install("/test/yolonot"); err == nil {
		t.Fatal("invalid JSON must not be silently replaced")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, invalid) {
		t.Fatal("failed install changed invalid config")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := h.Install("/test/yolonot"); err == nil {
		t.Fatal("install must report a rejected symlink write")
	}
}

func TestAntigravitySkillAndSessionOverride(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("YOLONOT_ANTIGRAVITY_SESSION_ID", "agy-session")
	h := &AntigravityHarness{}
	if h.SessionIDFromEnv() != "agy-session" {
		t.Fatal("explicit session override ignored")
	}
	path, err := h.InstallSkill()
	if err != nil || path == "" {
		t.Fatalf("skill installation failed: %v", err)
	}
	if content, err := os.ReadFile(filepath.Join(antigravitySkillDir(), "SKILL.md")); err != nil || !strings.Contains(string(content), "name: yolonot") {
		t.Fatalf("Antigravity skill missing: %v", err)
	}
	if err := h.UninstallSkill(); err != nil {
		t.Fatal(err)
	}
}

func TestAntigravityActualHookCommandUsesNativeDecisions(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	h := &AntigravityHarness{}
	SaveConfig(Config{Judges: JudgeList{{Use: judgeFastAllow}}})
	cwd := t.TempDir()
	input := func(command string) []byte {
		b, _ := json.Marshal(map[string]interface{}{"conversationId": "agy-test", "workspacePaths": []string{cwd},
			"toolCall": map[string]interface{}{"name": "run_command", "args": map[string]interface{}{"CommandLine": command, "Cwd": cwd}}})
		return b
	}
	for command, want := range map[string]string{"git status": "auto_approve", "test-dangerous": "deny", "test-review": "force_ask"} {
		if err := os.WriteFile(filepath.Join(YolonotDir(), "rules"), []byte("deny-cmd test-dangerous\nask-cmd test-review\n"), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestAntigravityHookHelperProcess$", "--", "hook", "--harness", h.Name(), "--hook-event", "PreToolUse")
		cmd.Env = append(os.Environ(), "YOLONOT_AGY_TEST_HOOK=1")
		cmd.Stdin = bytes.NewReader(input(command))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("actual hook process failed: %v", err)
		}
		var wire map[string]interface{}
		if err := json.Unmarshal(out, &wire); err != nil {
			t.Fatalf("invalid native decision: %s: %v", out, err)
		}
		if wire["decision"] != want {
			t.Fatalf("command %q got %s, want %s", command, out, want)
		}
	}
}

func TestAntigravityHookHelperProcess(t *testing.T) {
	if os.Getenv("YOLONOT_AGY_TEST_HOOK") != "1" {
		return
	}
	cmdHook()
	os.Exit(0)
}
