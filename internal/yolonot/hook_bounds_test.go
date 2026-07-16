package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeOversizeScripts writes three near-cap scripts into dir and returns a
// command that runs all three by absolute path, so every one attaches and the
// assembled classifier prompt exceeds maxClassifierPromptBytes.
func writeOversizeScripts(t *testing.T, dir string) string {
	t.Helper()
	big := []byte(strings.Repeat("echo x\n", 7*1024)) // ~49 KB each, under maxAttachBytes
	var parts []string
	for _, name := range []string{"a.sh", "b.sh", "c.sh"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, big, 0644); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, "bash "+p)
	}
	return strings.Join(parts, " && ") // absolute paths → all three attach
}

// chdirForRules points the process cwd at dir for the duration of the test so
// LoadRules' walk-up starts from a throwaway directory instead of this repo.
// The project's own .yolonot carries `deny-path /var/*`, and macOS t.TempDir()
// paths live under /var/folders — without this, that deny rule matches the
// oversize script paths and short-circuits before the oversize guard runs.
func chdirForRules(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })
}

// assertOversizeLogged fails unless a decision with layer=oversize and the
// given decision was written to the log.
func assertOversizeLogged(t *testing.T, wantDecision string) {
	t.Helper()
	for _, e := range ReadRecentDecisions(20) {
		if e.Layer == "oversize" && e.Decision == wantDecision {
			return
		}
	}
	t.Errorf("expected a logged decision with layer=oversize decision=%s, none found", wantDecision)
}

// End-to-end: an oversize assembled prompt is never shipped to the LLM. On an
// ask-capable harness (Claude default), the profile's abstain action is ask,
// so the hook returns an ask response citing the oversize/budget cause and
// logs the decision.
func TestCmdHookOversizePromptAsks(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "claude") // default risk map: critical → ask

	projectDir := t.TempDir()
	command := writeOversizeScripts(t, projectDir)
	chdirForRules(t, projectDir)

	out := runHookWithStruct(t, makePrePayload("oversize-ask", command, projectDir))
	resp := parseResponse(t, out)

	if resp.HookSpecificOutput.PermissionDecision != "ask" {
		t.Fatalf("oversize prompt on an ask-capable harness should ASK, got %q\nraw: %s",
			resp.HookSpecificOutput.PermissionDecision, out)
	}
	reason := resp.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(reason, "oversize") {
		t.Errorf("ask banner should carry the oversize layer, got: %q", reason)
	}
	if !strings.Contains(reason, "budget") {
		t.Errorf("ask reason should name the budget overflow, got: %q", reason)
	}
	assertOversizeLogged(t, "ask")
}

// End-to-end: when the resolved critical policy is deny, the abstain action is
// deny, exercising the oversize deny branch (the classifier still never sees
// the content).
func TestCmdHookOversizePromptDeniesWhenCriticalDenies(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "claude")
	SaveConfig(Config{RiskMaps: map[string]map[string]string{
		"claude": {RiskCritical: ActionDeny},
	}})

	projectDir := t.TempDir()
	command := writeOversizeScripts(t, projectDir)
	chdirForRules(t, projectDir)

	out := runHookWithStruct(t, makePrePayload("oversize-deny", command, projectDir))
	resp := parseResponse(t, out)

	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("oversize prompt with critical→deny should DENY, got %q\nraw: %s",
			resp.HookSpecificOutput.PermissionDecision, out)
	}
	if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "budget") {
		t.Errorf("deny reason should explain the budget overflow, got: %q",
			resp.HookSpecificOutput.PermissionDecisionReason)
	}
	assertOversizeLogged(t, "deny")
}

// The hook stdin read is bounded by maxHookInputBytes: a payload larger than
// the cap is truncated (io.LimitReader), so ParseHookInput sees invalid JSON
// and cmdHook returns promptly instead of reading unboundedly or hanging.
func TestCmdHookBoundsOversizeStdin(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "claude")

	// A single command field larger than the 4 MB stdin cap.
	huge := strings.Repeat("a", 5<<20) // 5 MiB > maxHookInputBytes (4 MiB)
	payload := makePrePayload("bounds-sess", huge, t.TempDir())
	data, _ := json.Marshal(payload)
	if len(data) <= maxHookInputBytes {
		t.Fatalf("test payload %d bytes must exceed the %d byte cap", len(data), maxHookInputBytes)
	}

	// Back stdin with a regular file so the bounded read reaches EOF without a
	// concurrent writer that could itself block.
	path := filepath.Join(t.TempDir(), "stdin.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	oldStdin := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = oldStdin }()

	done := make(chan string, 1)
	go func() { done <- captureStdout(func() { cmdHook() }) }()

	select {
	case out := <-done:
		if strings.TrimSpace(out) != "" {
			t.Errorf("truncated over-limit payload should emit nothing, got: %q", out)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("cmdHook did not return on a >4 MB stdin payload — read is not bounded")
	}
}
