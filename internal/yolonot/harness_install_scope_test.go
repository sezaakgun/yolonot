package yolonot

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTargetedHarnessInstallAndUninstallPreserveClaudeMod(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	if _, err := modInstall("/old/yolonot"); err != nil {
		t.Fatal(err)
	}
	// A distinctive file catches an unintended refresh as well as removal.
	registerPath := filepath.Join(modDir(), "hooks", "register.tsx")
	const sentinel = "// user-installed Claude mod, retain until Claude is targeted\n"
	if err := os.WriteFile(registerPath, []byte(sentinel), 0644); err != nil {
		t.Fatal(err)
	}
	claudeSettings, err := os.ReadFile((&ClaudeHarness{}).SettingsPath())
	if err != nil {
		t.Fatal(err)
	}
	assertClaudeUnchanged := func() {
		t.Helper()
		got, err := os.ReadFile(registerPath)
		if err != nil || string(got) != sentinel {
			t.Fatalf("unrelated harness operation changed the Claude mod: %q, %v", got, err)
		}
		got, err = os.ReadFile((&ClaudeHarness{}).SettingsPath())
		if err != nil || !bytes.Equal(got, claudeSettings) {
			t.Fatalf("unrelated harness operation changed Claude settings: %q, %v", got, err)
		}
	}
	os.Args = []string{"yolonot", "install", "--harness", "opencode", "--mod"}
	captureStdout(cmdInstall)
	if !(&OpencodeHarness{}).IsInstalled() {
		t.Fatal("target harness was not installed")
	}
	assertClaudeUnchanged()
	os.Args = []string{"yolonot", "uninstall", "--harness", "opencode"}
	captureStdout(cmdUninstall)
	if (&OpencodeHarness{}).IsInstalled() {
		t.Fatal("target harness was not removed")
	}
	assertClaudeUnchanged()

	// Default uninstall must still find a mod-only Claude installation.
	if (&ClaudeHarness{}).IsInstalled() {
		t.Fatal("fixture unexpectedly contains classic Claude hooks")
	}
	os.Args = []string{"yolonot", "uninstall"}
	captureStdout(cmdUninstall)
	if _, err := os.Stat(modDir()); !os.IsNotExist(err) {
		t.Fatalf("default uninstall left the mod-only installation: %v", err)
	}
	data, err := os.ReadFile((&ClaudeHarness{}).SettingsPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(modDir())) {
		t.Fatal("default uninstall left Claude's mod registration")
	}
}
