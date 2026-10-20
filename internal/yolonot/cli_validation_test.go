package yolonot

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestListAliasesReadLegacyConfigWithoutMigration(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	legacy := []byte(`{"provider":{"url":"claude-cli","model":"chat"},"pre_check":["fast-allow"]}`)
	if err := os.WriteFile(configPath(), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []struct {
		name string
		run  func([]string)
	}{{"Models", cmdModels}, {"Judges", cmdJudges}} {
		out := captureStdout(func() { command.run([]string{"list"}) })
		if !strings.Contains(out, command.name) || !strings.Contains(out, "chat") {
			t.Fatalf("list alias did not display normalized legacy %s: %s", command.name, out)
		}
	}
	data, err := os.ReadFile(configPath())
	if err != nil || !bytes.Equal(data, legacy) {
		t.Fatalf("read-only aliases must not migrate config: data=%s err=%v", data, err)
	}
}

func TestJudgesRejectsEmptyExecWithoutSaving(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	SaveConfig(Config{Judges: JudgeList{{Use: judgeFastAllow}}})
	before, _ := os.ReadFile(configPath())
	cmd := exec.Command(os.Args[0], "-test.run=^TestJudgesEmptyExecSubprocess$")
	cmd.Env = append(os.Environ(), "YOLONOT_TEST_EMPTY_EXEC=1")
	out, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 || !strings.Contains(string(out), "non-empty executable") {
		t.Fatalf("empty exec must exit 2 with clear validation: output=%s err=%v", out, err)
	}
	after, _ := os.ReadFile(configPath())
	if !bytes.Equal(before, after) {
		t.Fatalf("invalid exec mutated config: %s", after)
	}
}

func TestJudgesEmptyExecSubprocess(t *testing.T) {
	if os.Getenv("YOLONOT_TEST_EMPTY_EXEC") != "1" {
		return
	}
	cmdJudges([]string{"add", "exec:"})
	t.Fatal("invalid exec unexpectedly accepted")
}

func TestValidateJudgeSpec(t *testing.T) {
	cfg := Config{Models: map[string]ModelConfig{"chat": {URL: "claude-cli", Model: "chat"}}}
	for _, use := range []string{"exec:", "exec: \t", "unknown"} {
		if validateJudgeSpec(cfg, JudgeSpec{Use: use}) == nil {
			t.Errorf("invalid entry accepted: %q", use)
		}
	}
	for _, use := range []string{judgeFastAllow, "chat", "exec:/path/to/hook --strict"} {
		if err := validateJudgeSpec(cfg, JudgeSpec{Use: use}); err != nil {
			t.Errorf("valid entry %q rejected: %v", use, err)
		}
	}
	if validateJudgeSpec(cfg, JudgeSpec{Use: "chat", May: []string{"alow"}}) == nil {
		t.Error("invalid may decision accepted")
	}
}
