package yolonot

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexPermissionRequestDecisionWireFormat(t *testing.T) {
	for _, decision := range []string{"allow", "deny", "ask", ""} {
		t.Run(decision, func(t *testing.T) {
			r := buildHookResponse(decision, "rule", "reviewed policy", "echo safe")
			r.HookSpecificOutput.HookEventName = "PermissionRequest"
			out := (&CodexHarness{}).FormatHookResponse(r)
			if decision == "ask" || decision == "" {
				if out != "" {
					t.Fatalf("undecided request must leave native prompt alone: %s", out)
				}
				return
			}
			var payload struct {
				HookSpecificOutput struct {
					HookEventName      string            `json:"hookEventName"`
					Decision           map[string]string `json:"decision"`
					PermissionDecision string            `json:"permissionDecision"`
				} `json:"hookSpecificOutput"`
			}
			if err := json.Unmarshal([]byte(out), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.HookSpecificOutput.HookEventName != "PermissionRequest" || payload.HookSpecificOutput.Decision["behavior"] != decision || payload.HookSpecificOutput.PermissionDecision != "" {
				t.Fatalf("wrong permission request schema: %s", out)
			}
			if decision == "deny" && !strings.Contains(payload.HookSpecificOutput.Decision["message"], "reviewed policy") {
				t.Fatal(out)
			}
		})
	}
}

func TestCodexPairedPermissionPhaseDoesNotInferHumanRejection(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "codex")
	t.Setenv("YOLONOT_MOD", "")
	t.Cleanup(func() { currentHookEventName = "" })
	writeGlobalRules(t, home, "ask-cmd review-codex-ask\nallow-cmd review-codex-allow\ndeny-cmd review-codex-deny\n")
	for _, item := range []struct{ command, expected string }{{"review-codex-ask", ""}, {"review-codex-allow", "allow"}, {"review-codex-deny", "deny"}} {
		t.Run(item.command, func(t *testing.T) {
			pre := makePrePayload("paired-"+item.command, item.command, t.TempDir())
			runHookWithStruct(t, pre)
			request := pre
			request.HookEventName = "PermissionRequest"
			out := strings.TrimSpace(runHookWithStruct(t, request))
			if item.expected == "" {
				if out != "" {
					t.Fatalf("paired ask request was denied before the human could answer: %s", out)
				}
				if ContainsLine(ProjectSessionID(pre.SessionID, pre.Cwd), "denied", item.command) {
					t.Fatal("paired phase must not record a user rejection")
				}
			} else if !strings.Contains(out, `"behavior":"`+item.expected+`"`) || !strings.Contains(out, `"hookEventName":"PermissionRequest"`) {
				t.Fatalf("wrong permission decision: %s", out)
			}
		})
	}
}

func TestCodexPermissionRequestNormalizesExecJudgeInput(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "codex")
	t.Setenv("YOLONOT_MOD", "")
	t.Cleanup(func() { currentHookEventName = "" })
	judge := filepath.Join(t.TempDir(), "pre-only-judge")
	code := "#!/bin/sh\ninput=$(cat)\ncase \"$input\" in *'\"hook_event_name\":\"PreToolUse\"'*) printf '%s' '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}';; *) exit 1;; esac\n"
	if err := os.WriteFile(judge, []byte(code), 0700); err != nil {
		t.Fatal(err)
	}
	SaveConfig(Config{Judges: JudgeList{{Use: "exec:" + judge}}})
	request := makePrePayload("exec-permission-request", "review-exec-permission", t.TempDir())
	request.HookEventName = "PermissionRequest"
	if out := runHookWithStruct(t, request); !strings.Contains(out, `"behavior":"allow"`) {
		t.Fatalf("external PreToolUse judge saw wrong phase: %s", out)
	}
}

func TestCodexNoninteractivePermissionModeStillEnforcesRules(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "codex")
	t.Setenv("YOLONOT_MOD", "")
	t.Cleanup(func() { currentHookEventName = "" })
	writeGlobalRules(t, home, "deny-cmd touch *\n")
	payload := makePrePayload("codex-exec-never", "touch /tmp/safe-fixture-never-executed", t.TempDir())
	// Installed codex exec 0.162.1 reports this mode because it forces
	// approval_policy=Never, even with its workspace-write sandbox active.
	payload.PermissionMode = "bypassPermissions"
	out := parseResponse(t, runHookWithStruct(t, payload))
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("normal codex exec silently bypassed yolonot: %+v", out)
	}
}

func TestCurrentHarnessConfigDirectories(t *testing.T) {
	for _, harness := range []string{"claude", "codex"} {
		t.Run(harness, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			custom := t.TempDir()
			var h Harness = &ClaudeHarness{}
			t.Setenv("CLAUDE_CONFIG_DIR", custom)
			if harness == "codex" {
				h = &CodexHarness{}
				t.Setenv("CODEX_HOME", custom)
			}
			if err := h.Install("/example/yolonot"); err != nil {
				t.Fatal(err)
			}
			if filepath.Dir(h.SettingsPath()) != custom {
				t.Fatal(h.SettingsPath())
			}
			if _, err := os.Stat(h.SettingsPath()); err != nil {
				t.Fatal(err)
			}
			if err := h.Uninstall(); err != nil {
				t.Fatal(err)
			}
			if h.IsInstalled() {
				t.Fatal("custom-directory uninstall left hooks installed")
			}
		})
	}
}

func TestCurrentHarnessPreservesInvalidHostSettings(t *testing.T) {
	for _, harness := range []string{"claude", "codex"} {
		for _, content := range []string{"{bad", "null", `{"hooks":false}`} {
			t.Run(harness+content, func(t *testing.T) {
				t.Setenv("HOME", t.TempDir())
				t.Setenv("CLAUDE_CONFIG_DIR", "")
				t.Setenv("CODEX_HOME", "")
				var h Harness = &ClaudeHarness{}
				if harness == "codex" {
					h = &CodexHarness{}
				}
				if err := os.MkdirAll(filepath.Dir(h.SettingsPath()), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(h.SettingsPath(), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				if err := h.Install("/example/yolonot"); err == nil {
					t.Fatal("invalid host settings accepted during install")
				}
				if err := h.Uninstall(); err == nil {
					t.Fatal("invalid host settings accepted during uninstall")
				}
				got, _ := os.ReadFile(h.SettingsPath())
				if string(got) != content {
					t.Fatal("invalid host settings overwritten")
				}
			})
		}
	}
}

func TestHookCommandQuotesInstallationPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bin with 'quotes' $(exit 72)")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "yolonot")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, harness := range []string{"claude", "codex"} {
		out, err := exec.Command("/bin/sh", "-c", shellHookCommand(bin, harness)).CombinedOutput()
		if err != nil || string(out) != "hook\n--harness\n"+harness+"\n" {
			t.Fatalf("literal path execution failed: %s %v", out, err)
		}
	}
}

func stubClaudeExecHooks(t *testing.T, ok bool) {
	old := claudeSupportsExecHooks
	claudeSupportsExecHooks = func() bool { return ok }
	t.Cleanup(func() { claudeSupportsExecHooks = old })
}

func TestClaudeCurrentExecFormBlocksHookFailures(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	stubClaudeExecHooks(t, true)
	h := &ClaudeHarness{}
	const binary = "/example/a path with 'quotes' and $expansion/yolonot"
	if err := h.Install(binary); err != nil {
		t.Fatal(err)
	}
	settings := h.loadSettings()
	hooks := settings["hooks"].(map[string]interface{})
	pre := hooks["PreToolUse"].([]interface{})[0].(map[string]interface{})
	handler := pre["hooks"].([]interface{})[0].(map[string]interface{})
	if handler["command"] != binary || handler["onFailure"] != "block" {
		t.Fatalf("exec path or failure policy changed: %+v", handler)
	}
	args := handler["args"].([]interface{})
	if len(args) != 3 || args[0] != "hook" || args[1] != "--harness" || args[2] != "claude" {
		t.Fatal(args)
	}
	if pre["matcher"] != "Bash|PowerShell" {
		t.Fatal(pre)
	}
}

func TestClaudeOlderOrUnknownVersionGetsShellForm(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	stubClaudeExecHooks(t, false)
	h := &ClaudeHarness{}
	const binary = "/example/a path/yolonot"
	if err := h.Install(binary); err != nil {
		t.Fatal(err)
	}
	hooks := h.loadSettings()["hooks"].(map[string]interface{})
	pre := hooks["PreToolUse"].([]interface{})[0].(map[string]interface{})
	handler := pre["hooks"].([]interface{})[0].(map[string]interface{})
	if handler["command"] != shellHookCommand(binary, "claude") || handler["args"] != nil || handler["onFailure"] != "block" {
		t.Fatalf("fallback hook: %+v", handler)
	}
	if !h.IsInstalled() {
		t.Fatal("shell-form install not detected")
	}
}

func TestVersionAtLeast(t *testing.T) {
	for s, want := range map[string]bool{"2.1.300 (Claude Code)": true, "2.1.295": true, "2.1.294": false, "2.0.999": false, "3.0.0": true, "version unavailable": false} {
		if got := versionAtLeast(s, [3]int{2, 1, 295}); got != want {
			t.Errorf("%q: got %v", s, got)
		}
	}
}
