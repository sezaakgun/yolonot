package yolonot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cmdCheck dry-run: when the assembled classifier prompt exceeds the budget,
// the LLM step is skipped and the result reports the oversize layer with the
// profile's abstain action — mirroring what the real hook would do, without
// calling the provider.
func TestCheckOversizePromptDryRun(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "claude") // abstain → ASK

	// A provider URL is required for cmdCheck to reach the LLM-analysis step
	// that houses the oversize guard. The guard trips before any request, so
	// the dummy endpoint is never contacted.
	SaveConfig(Config{Provider: ProviderConfig{URL: "https://example.com", Model: "test"}})

	projectDir := t.TempDir()
	big := []byte(strings.Repeat("echo x\n", 7*1024)) // ~49 KB each, under maxAttachBytes
	var parts []string
	for _, name := range []string{"a.sh", "b.sh", "c.sh"} {
		p := filepath.Join(projectDir, name)
		if err := os.WriteFile(p, big, 0644); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, "bash "+p)
	}
	command := strings.Join(parts, " && ") // absolute paths → all three attach

	// cmdCheck resolves scripts against its own working directory; chdir so the
	// in-root absolute scripts fall inside the attach root.
	origCwd, _ := os.Getwd()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origCwd)

	out := captureStdout(func() { cmdCheck(command) })

	if !strings.Contains(out, "exceeds") || !strings.Contains(out, "budget") {
		t.Errorf("expected an oversize skip line naming the budget, got:\n%s", out)
	}
	if !strings.Contains(out, "oversize") {
		t.Errorf("expected the oversize layer in the result line, got:\n%s", out)
	}
	if !strings.Contains(out, "ASK") {
		t.Errorf("expected the abstain action ASK in the result, got:\n%s", out)
	}
}
