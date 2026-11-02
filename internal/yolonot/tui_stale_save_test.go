package yolonot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingsSaveRefusesExternalConfigChange(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	settingsTestState(t)
	SaveConfig(Config{})
	snap, err := readConfigSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	tuiConfigSnapshot = snap
	t.Cleanup(func() { tuiConfigSnapshot = nil })

	SaveConfig(Config{QuietOnAllow: true})
	external, _ := os.ReadFile(configPath())
	if saveConfigWithBackup(Config{HookTimeout: 20}) {
		t.Fatal("overwrote config edits made outside settings")
	}
	if got, _ := os.ReadFile(configPath()); string(got) != string(external) {
		t.Fatalf("external config overwritten: %s", got)
	}
	if !strings.Contains(tuiNotice, "changed outside settings") {
		t.Fatalf("conflict not explained: %s", tuiNotice)
	}

	tuiConfigSnapshot, _ = readConfigSnapshot()
	if !saveConfigWithBackup(Config{HookTimeout: 20}) {
		t.Fatalf("unchanged config must save: %s", tuiNotice)
	}
}

func TestRunEditorReentersAltScreenInPage(t *testing.T) {
	settingsTestState(t)
	t.Setenv("VISUAL", "true")
	path := filepath.Join(t.TempDir(), "f")
	out := captureStdout(func() {
		if err := runEditor(path); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "\x1b[?1049h") {
		t.Fatalf("editor exit must re-enter the alternate screen, got %q", out)
	}
	t.Setenv("VISUAL", "false")
	out = captureStdout(func() { runEditor(path) })
	if !strings.Contains(out, "\x1b[?1049h") {
		t.Fatalf("failed editor must still re-enter the alternate screen, got %q", out)
	}
	tuiInPage = false
	if out := captureStdout(func() { runEditor(path) }); strings.Contains(out, "\x1b[?1049h") {
		t.Fatalf("outside the page the editor must not switch screens, got %q", out)
	}
}
