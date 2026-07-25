package yolonot

import (
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
