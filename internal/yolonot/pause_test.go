package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBypassReasonPrecedence(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// A session with an on-disk pause marker, used by the "session" cases.
	paused := "int-bypass-paused"
	os.WriteFile(filepath.Join(home, ".yolonot", "sessions", paused+".paused"), []byte{}, 0644)

	tests := []struct {
		name    string
		env     string
		cfg     Config
		payload HookPayload
		want    string
	}{
		{"active", "", Config{}, HookPayload{SessionID: "int-bypass-live"}, ""},
		{"env alone", "1", Config{}, HookPayload{}, "env"},
		{"bypass-permissions alone", "", Config{}, HookPayload{PermissionMode: "bypassPermissions"}, "bypass-permissions"},
		{"global alone", "", Config{Disabled: true}, HookPayload{}, "global"},
		{"session alone", "", Config{}, HookPayload{SessionID: paused}, "session"},
		{"env beats bypass-permissions", "1", Config{}, HookPayload{PermissionMode: "bypassPermissions"}, "env"},
		{"bypass-permissions beats global", "", Config{Disabled: true}, HookPayload{PermissionMode: "bypassPermissions"}, "bypass-permissions"},
		{"global beats session", "", Config{Disabled: true}, HookPayload{SessionID: paused}, "global"},
		{"global needs no session id", "", Config{Disabled: true}, HookPayload{}, "global"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("YOLONOT_DISABLED", tt.env)
			if got := bypassReason(tt.cfg, tt.payload); got != tt.want {
				t.Errorf("bypassReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBypassReasonFailsSafeOnCorruptConfig(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_DISABLED", "")

	// A config yolonot cannot parse must leave the safety layer ON.
	os.WriteFile(filepath.Join(home, ".yolonot", "config.json"), []byte("{not json"), 0644)

	if got := bypassReason(LoadConfig(), HookPayload{}); got != "" {
		t.Errorf("corrupt config must leave yolonot active, got %q", got)
	}
}

func TestConfigDisabledRoundTrip(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	if LoadConfig().Disabled {
		t.Fatal("a fresh config must not be disabled")
	}

	cfg := LoadConfig()
	cfg.Disabled = true
	SaveConfig(cfg)
	if !LoadConfig().Disabled {
		t.Error("Disabled=true did not survive save/load")
	}

	cfg.Disabled = false
	SaveConfig(cfg)
	if LoadConfig().Disabled {
		t.Error("Disabled=false did not survive save/load")
	}
}

func TestConfigOmitsDisabledWhenFalse(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{})

	data, err := os.ReadFile(filepath.Join(home, ".yolonot", "config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(data), "disabled") {
		t.Errorf("a default config must not serialize a disabled key, got:\n%s", data)
	}
}

// readDecisionLayers returns the (layer, decision) pairs recorded in
// decisions.jsonl, so tests can assert on the audit trail.
func readDecisionLayers(t *testing.T, home string) [][2]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".yolonot", "decisions.jsonl"))
	if err != nil {
		return nil
	}
	var out [][2]string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e DecisionEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad decision line %q: %v", line, err)
		}
		out = append(out, [2]string{e.Layer, e.Decision})
	}
	return out
}

func TestGlobalPauseRequiresConfirmBypass(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	out := captureStdout(func() { cmdPause([]string{"--global"}) })

	if LoadConfig().Disabled {
		t.Error("pause --global without --confirm-bypass must not disable yolonot")
	}
	if !strings.Contains(out, "--confirm-bypass") {
		t.Errorf("guidance should name the opt-in flag, got:\n%s", out)
	}
	if len(readDecisionLayers(t, home)) != 0 {
		t.Error("a refused pause must not write an audit entry")
	}
}

func TestGlobalPauseSetsFlagAndLogs(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	captureStdout(func() { cmdPause([]string{"--global", "--confirm-bypass"}) })

	if !LoadConfig().Disabled {
		t.Fatal("pause --global --confirm-bypass should set Disabled")
	}
	got := readDecisionLayers(t, home)
	if len(got) != 1 || got[0] != [2]string{"pause", "bypass_enabled"} {
		t.Errorf("expected one pause/bypass_enabled entry, got %v", got)
	}
}

func TestGlobalPauseIsIdempotent(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	captureStdout(func() { cmdPause([]string{"--global", "--confirm-bypass"}) })
	out := captureStdout(func() { cmdPause([]string{"--global", "--confirm-bypass"}) })

	if !LoadConfig().Disabled {
		t.Error("second pause --global must leave yolonot disabled")
	}
	if got := readDecisionLayers(t, home); len(got) != 1 {
		t.Errorf("a redundant pause must not add an audit entry, got %v", got)
	}
	if !strings.Contains(out, "already") {
		t.Errorf("second call should say it is already disabled, got:\n%s", out)
	}
}

func TestGlobalResumeClearsFlagAndLogs(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	captureStdout(func() { cmdPause([]string{"--global", "--confirm-bypass"}) })
	captureStdout(func() { cmdResume([]string{"--global"}) })

	if LoadConfig().Disabled {
		t.Fatal("resume --global should clear Disabled")
	}
	got := readDecisionLayers(t, home)
	if len(got) != 2 || got[1] != [2]string{"pause", "bypass_disabled"} {
		t.Errorf("expected a trailing pause/bypass_disabled entry, got %v", got)
	}
}

func TestGlobalResumeWhenNotDisabled(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	out := captureStdout(func() { cmdResume([]string{"--global"}) })

	if !strings.Contains(out, "not globally disabled") {
		t.Errorf("expected a not-disabled message, got:\n%s", out)
	}
	if len(readDecisionLayers(t, home)) != 0 {
		t.Error("a no-op resume must not write an audit entry")
	}
}

func TestSessionResumeHintsAtGlobalPause(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	sid := "int-hint-session"
	os.WriteFile(filepath.Join(home, ".yolonot", "sessions", sid+".paused"), []byte{}, 0644)
	captureStdout(func() { cmdPause([]string{"--global", "--confirm-bypass"}) })

	out := captureStdout(func() { cmdResume([]string{"--session-id", sid}) })

	if !strings.Contains(out, "resume --global") {
		t.Errorf("a session resume under a global pause must point at resume --global, got:\n%s", out)
	}
	if isPaused(sid) {
		t.Error("the session marker should still have been removed")
	}
}

func TestGlobalFlagIgnoresSessionFlags(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	sid := "int-global-with-session"
	out := captureStdout(func() {
		cmdPause([]string{"--global", "--session-id", sid, "--confirm-bypass"})
	})

	if !LoadConfig().Disabled {
		t.Error("--global should win and disable globally")
	}
	if isPaused(sid) {
		t.Error("--global must not also write a session marker")
	}
	if !strings.Contains(out, "ignored") {
		t.Errorf("should note that the session flag was ignored, got:\n%s", out)
	}
}

func TestDefaultOutputWarnsWhenGloballyDisabled(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_DISABLED", "")

	SaveConfig(Config{Disabled: true})
	out := captureStdout(cmdDefault)
	if !strings.Contains(out, "GLOBALLY DISABLED") {
		t.Errorf("cmdDefault should warn when globally disabled, got:\n%s", out)
	}

	SaveConfig(Config{Disabled: false})
	out = captureStdout(cmdDefault)
	if strings.Contains(out, "GLOBALLY DISABLED") {
		t.Errorf("cmdDefault must not warn when enabled, got:\n%s", out)
	}
}

func TestStatusWarnsWhenGloballyDisabledWithNoSession(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_DISABLED", "")
	t.Setenv("CLAUDE_SESSION_ID", "")

	SaveConfig(Config{Disabled: true})

	// No session files exist, so cmdStatus takes its early return — the
	// warning has to print above it or it is invisible exactly when the
	// user is most likely to be confused.
	out := captureStdout(cmdStatus)
	if !strings.Contains(out, "GLOBALLY DISABLED") {
		t.Errorf("cmdStatus should warn even with no session, got:\n%s", out)
	}
}

func TestCheckNotesGlobalPauseOnEarlyReturn(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_DISABLED", "")

	// A deny rule makes cmdCheck return at its very first exit point.
	writeGlobalRules(t, home, "deny-cmd *\n")
	SaveConfig(Config{Disabled: true})

	out := captureStdout(func() { cmdCheck("rm -rf /") })

	if !strings.Contains(out, "globally disabled") {
		t.Errorf("check should lead with the bypass notice, got:\n%s", out)
	}
	if !strings.Contains(out, "NOT APPLIED") {
		t.Errorf("check should trail with NOT APPLIED even on an early return, got:\n%s", out)
	}
}

func TestCheckSilentWhenEnabled(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_DISABLED", "")

	writeGlobalRules(t, home, "deny-cmd *\n")
	SaveConfig(Config{Disabled: false})

	out := captureStdout(func() { cmdCheck("rm -rf /") })
	if strings.Contains(out, "NOT APPLIED") {
		t.Errorf("check must not claim a bypass when yolonot is active, got:\n%s", out)
	}
}
