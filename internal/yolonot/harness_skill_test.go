package yolonot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharedSkillRefreshPreservesUserFiles(t *testing.T) {
	for _, name := range []string{"claude", "codex", "opencode", "antigravity", "cursor"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "yolonot")
			if _, err := installHarnessSkill(name, dir); err != nil {
				t.Fatal(err)
			}
			unrelated := filepath.Join(dir, "notes.txt")
			if err := os.WriteFile(unrelated, []byte("user notes"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := installHarnessSkill(name, dir); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dir, "SKILL.md"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "{{HARNESS}}") {
				t.Fatal("unresolved harness template")
			}
			if err := uninstallHarnessSkill(dir); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(unrelated)
			if err != nil || string(got) != "user notes" {
				t.Fatalf("unrelated file changed: %q %v", got, err)
			}
		})
	}
}

func TestClaudeSkillProtectsCustomizedInstallation(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	dir := filepath.Join(claudeConfigDir(), "skills", "yolonot")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "SKILL.md")
	original := []byte("custom Claude skill")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	h := &ClaudeHarness{}
	if _, err := h.InstallSkill(); err == nil {
		t.Fatal("overwrote customized Claude skill")
	}
	if err := h.UninstallSkill(); err == nil {
		t.Fatal("removed customized Claude skill")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(original) {
		t.Fatalf("custom skill changed: %q %v", got, err)
	}
}
