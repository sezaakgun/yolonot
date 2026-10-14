package yolonot

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCursorNativeAskOptInPreservesDefaultPassthrough(t *testing.T) {
	h := &CursorHarness{}
	r := buildHookResponse(ActionAsk, "rule", "review required", "example")
	for _, flag := range []string{"", "0", "true", "1"} {
		t.Run(flag, func(t *testing.T) {
			t.Setenv("YOLONOT_CURSOR_NATIVE_ASK", flag)
			if h.SupportsAsk() != (flag == "1") || harnessSupportsAsk(h) != (flag == "1") {
				t.Fatal("native ask must require explicit opt-in")
			}
			if flag != "1" {
				if h.FormatHookResponse(r) != "" || h.RiskMap()[RiskModerate] != ActionPassthrough {
					t.Fatal("compatibility mode must retain host passthrough")
				}
				return
			}
			var wire cursorResponse
			if err := json.Unmarshal([]byte(h.FormatHookResponse(r)), &wire); err != nil {
				t.Fatal(err)
			}
			if wire.Permission != ActionAsk || !strings.Contains(wire.UserMessage, "review required") {
				t.Fatalf("native ask not emitted: %+v", wire)
			}
			if h.RiskMap()[RiskModerate] != ActionAsk || TranslateProfile(GetBuiltinProfile("balanced").Map, h)[RiskModerate] != ActionAsk || TranslateProfile(GetBuiltinProfile("balanced").Map, h)[RiskHigh] != ActionDeny {
				t.Fatal("native ask capability not reflected in risk/profile mapping")
			}
		})
	}
}

func TestCursorCurrentToolCorrelationField(t *testing.T) {
	input := []byte(`{"conversation_id":"conv","tool_use_id":"call-123","hook_event_name":"beforeShellExecution","command":"git status","cwd":"/project"}`)
	payload, err := (&CursorHarness{}).ParseHookInput(input)
	if err != nil || payload.ToolUseID != "call-123" || payload.SessionID != "conv" {
		t.Fatalf("current Cursor tool correlation lost: %+v %v", payload, err)
	}
}

func TestGoogleCursorSettingsMutationsRejectMalformedFiles(t *testing.T) {
	for _, h := range []Harness{&GeminiHarness{}, &CursorHarness{}} {
		t.Run(h.Name(), func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			path := h.SettingsPath()
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			for _, content := range []string{`{broken`, `null`, `[]`, `{"hooks":false}`, `{"hooks":{},"hooks":{}}`} {
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				if err := h.Install("/scratch/yolonot"); err == nil {
					t.Fatalf("install accepted malformed settings: %s", content)
				}
				if err := h.Uninstall(); err == nil {
					t.Fatalf("uninstall accepted malformed settings: %s", content)
				}
				if got, _ := os.ReadFile(path); !bytes.Equal(got, []byte(content)) {
					t.Fatalf("mutation damaged malformed settings: %s", got)
				}
			}
		})
	}
}

func TestGoogleCursorSettingsWritesPreservePrivateMode(t *testing.T) {
	for _, h := range []Harness{&GeminiHarness{}, &CursorHarness{}} {
		t.Run(h.Name(), func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			path := h.SettingsPath()
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(`{"unrelated":"keep"}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := h.Install("/scratch/yolonot"); err != nil {
				t.Fatal(err)
			}
			if err := h.Uninstall(); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("private host settings permissions widened: %v", err)
			}
		})
	}
}

func TestInstalledGeminiDiscoversSkillWithoutModelCall(t *testing.T) {
	gemini, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("Gemini CLI is not installed")
	}
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	h := &GeminiHarness{}
	if _, err := h.InstallSkill(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, gemini, "skills", "list")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Gemini's own skill discovery failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "yolonot") {
		t.Fatalf("installed Gemini did not discover its skill: %s", out)
	}
}

func TestCursorWorkspaceScopeWithForeignHookDirectory(t *testing.T) {
	productControlHome(t)
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, ".yolonot"), []byte("deny-cmd cursor-denied\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"beforeShellExecution", "afterShellExecution"} {
		for _, explicit := range []string{"", project, "."} {
			input, _ := json.Marshal(map[string]any{"hook_event_name": event, "command": "cursor-denied", "cwd": explicit, "workspace_roots": []string{project, "/other-workspace"}})
			payload, err := (&CursorHarness{}).ParseHookInput(input)
			if err != nil || payload.Cwd != project {
				t.Fatalf("scope lost: %+v %v", payload, err)
			}
			// Resolve real project rules without changing the test process cwd.
			decision := MatchRule("cursor-denied", LoadRules(payload.Cwd))
			if decision == nil || decision.Action != ActionDeny {
				t.Fatalf("project deny missed from foreign cwd: %+v", decision)
			}
		}
	}
}

func TestCursorAfterShellCannotInventHumanApproval(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "cursor")
	t.Setenv("YOLONOT_MOD", "")
	t.Cleanup(func() { currentHookEventName = "" })
	cwd := t.TempDir()
	sid, command := "cursor-ambiguous-post", "cursor-review-command"
	project := ProjectSessionID(sid, cwd)
	AppendLine(project, "asked", command)
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "afterShellExecution", "conversation_id": sid, "workspace_roots": []string{cwd}, "command": command, "output": "", "tool_use_id": "skipped-call"})
	runHookWithPayload(t, string(raw))
	if ContainsLine(project, "approved", command) || ContainsLine(project, "asked", command) {
		t.Fatal("ambiguous completion minted approval or retained stale pending ask")
	}
	for _, entry := range ReadRecentDecisions(100) {
		if entry.SessionID == sid && entry.Layer == "human" {
			t.Fatalf("invented human verdict: %+v", entry)
		}
	}
}
