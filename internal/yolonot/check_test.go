package yolonot

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// Dry-run parity: `yolonot check` must honor attach_outside_root exactly like
// the hook path, or its preview lies about what the classifier will see.
func TestCheckHonorsAttachOutsideRoot(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": `{"decision":"allow","confidence":0.9,"short":"probe","reasoning":"probe"}`}},
			},
		})
	}))
	defer server.Close()

	outside := t.TempDir()
	scriptPath := filepath.Join(outside, "tool.py")
	if err := os.WriteFile(scriptPath, []byte("print('OUTSIDE-CHECK-MARKER')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	projectDir := t.TempDir()
	origCwd, _ := os.Getwd()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origCwd)
	command := "python3 " + scriptPath

	SaveConfig(Config{Provider: ProviderConfig{URL: server.URL, Model: "test"}, AttachOutsideRoot: true})
	attachOutsideRoot = false // fresh-process simulation; only cmdCheck's config load may open it
	captureStdout(func() { cmdCheck(command) })
	if len(bodies) != 1 {
		t.Fatalf("expected one provider call, got %d", len(bodies))
	}
	if !strings.Contains(bodies[0], "OUTSIDE-CHECK-MARKER") {
		t.Error("check with attach_outside_root=true should attach the outside script")
	}

	SaveConfig(Config{Provider: ProviderConfig{URL: server.URL, Model: "test"}})
	captureStdout(func() { cmdCheck(command) })
	if len(bodies) != 2 {
		t.Fatalf("expected a second provider call, got %d", len(bodies))
	}
	if strings.Contains(bodies[1], "OUTSIDE-CHECK-MARKER") {
		t.Error("check without the flag must withhold the outside script (and reset the open state from the prior run)")
	}
}

func TestCheckAndHookReceiveSameWalkupHints(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "claude")
	projectDir := t.TempDir()
	os.MkdirAll(filepath.Join(projectDir, ".git"), 0755)
	os.WriteFile(filepath.Join(projectDir, ".yolonot"), []byte("allow-hint \"unfamiliar-tool --probe is safe in this repo\"\n"), 0600)
	t.Chdir(projectDir)
	const command = "unfamiliar-tool --probe"
	bodies := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- string(body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": `{"decision":"allow","confidence":0.9,"short":"probe","reasoning":"probe"}`}},
			},
		})
	}))
	defer server.Close()
	SaveConfig(Config{Provider: ProviderConfig{URL: server.URL, Model: "test"}})
	awaitBody := func() string {
		t.Helper()
		select {
		case body := <-bodies:
			return body
		case <-time.After(5 * time.Second):
			t.Fatal("expected a model request")
			return ""
		}
	}
	captureStdout(func() { cmdCheck(command) })
	checkBody := awaitBody()
	runHookWithStruct(t, makePrePayload("hint-parity", command, projectDir))
	hookBody := awaitBody()
	for label, body := range map[string]string{"check": checkBody, "hook": hookBody} {
		if !strings.Contains(body, "unfamiliar-tool --probe is safe in this repo") {
			t.Errorf("%s did not receive the current project's walk-up hint: %s", label, body)
		}
	}
	if checkBody != hookBody {
		t.Errorf("check and hook sent different model requests:\ncheck: %s\nhook:  %s", checkBody, hookBody)
	}
}

func TestParseCheckArgsAndCheckCwd(t *testing.T) {
	cmdArgs, cwd, err := parseCheckArgs([]string{"--cwd", "/tmp/proj", "git", "status"})
	if err != nil || cwd != "/tmp/proj" || strings.Join(cmdArgs, " ") != "git status" {
		t.Fatalf("parseCheckArgs(--cwd dir): cmdArgs=%v cwd=%q err=%v", cmdArgs, cwd, err)
	}
	cmdArgs, cwd, err = parseCheckArgs([]string{"--cwd=/tmp/proj2", "--", "-v", "--flag"})
	if err != nil || cwd != "/tmp/proj2" || strings.Join(cmdArgs, " ") != "-v --flag" {
		t.Fatalf("parseCheckArgs(--cwd=dir --): cmdArgs=%v cwd=%q err=%v", cmdArgs, cwd, err)
	}
	if _, _, err := parseCheckArgs([]string{"--unknown-flag", "ls"}); err == nil {
		t.Error("parseCheckArgs should reject unknown leading flag")
	}

	// Verify cmdCheckIn loads .yolonot rules from the explicit --cwd directory.
	_, cleanup := withFakeHome(t)
	defer cleanup()
	otherDir := t.TempDir()
	projDir := t.TempDir()
	os.MkdirAll(filepath.Join(projDir, ".git"), 0755)
	os.WriteFile(filepath.Join(projDir, ".yolonot"), []byte("allow-cmd custom-cwd-tool *\n"), 0644)

	t.Chdir(otherDir)
	out := captureStdout(func() { cmdCheckIn("custom-cwd-tool --run", projDir) })
	if !strings.Contains(out, "ALLOW (layer: rule)") {
		t.Errorf("cmdCheckIn with explicit cwd should match project .yolonot rule, got:\n%s", out)
	}
}

func TestForceAllowOverridesRawAskExceptCritical(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{
		RiskMaps: map[string]map[string]string{
			"claude": {
				RiskLow:      ActionAllow,
				RiskModerate: ActionForceAllow,
				RiskHigh:     "override_allow",
			},
		},
	})
	h := GetHarness("claude")

	// Raw "ask" at moderate or high with force_allow becomes "allow".
	decMod, passMod := applyRiskMap(h, "ask", RiskModerate)
	if passMod || decMod != "allow" {
		t.Errorf("force_allow on moderate should override raw ask to allow, got dec=%q pass=%v", decMod, passMod)
	}
	if fire, skip := escalationTrigger(h, &Decision{Decision: "ask", Risk: RiskModerate}); fire || skip != "" {
		t.Errorf("force_allow resolved to allow must not trigger escalation, got fire=%v skip=%q", fire, skip)
	}

	decHigh, passHigh := applyRiskMap(h, "ask", RiskHigh)
	if passHigh || decHigh != "allow" {
		t.Errorf("override_allow alias on high should override raw ask to allow, got dec=%q pass=%v", decHigh, passHigh)
	}

	// Raw "ask" with standard ActionAllow stays "ask" (escalate-only).
	decLow, _ := applyRiskMap(h, "ask", RiskLow)
	if decLow != "ask" {
		t.Errorf("standard allow on low must keep raw ask as ask, got %q", decLow)
	}

	// Critical may never use force_allow.
	if err := ValidateCustomProfile("bad", map[string]string{
		RiskSafe:     ActionAllow,
		RiskLow:      ActionAllow,
		RiskModerate: ActionAllow,
		RiskHigh:     ActionAsk,
		RiskCritical: ActionForceAllow,
	}); err == nil {
		t.Error("ValidateCustomProfile must reject force_allow on critical tier")
	}
}

func TestEscalationRescuesModerateWhenRiskMapAllows(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	h := GetHarness("claude")

	// Under fast profile (RiskModerate -> allow), escalation rescues allow/moderate.
	SaveConfig(Config{Profile: "fast"})
	d := &Decision{Decision: "ask", Risk: RiskModerate, Reasoning: "unsure"}
	d2 := &Decision{Decision: "allow", Risk: RiskModerate, Reasoning: "reviewed safe"}
	outcome, _ := escalationAdopt(h, d, d2)
	if outcome != "rescued" || d.Decision != "allow" || !d.Escalated {
		t.Errorf("expected allow/moderate to be rescued under fast profile, got outcome=%q decision=%q", outcome, d.Decision)
	}

	// Under balanced profile (RiskModerate -> ask), allow/moderate is not adoptable and stays kept.
	SaveConfig(Config{Profile: "balanced"})
	dBal := &Decision{Decision: "ask", Risk: RiskModerate, Reasoning: "unsure"}
	outcome2, _ := escalationAdopt(h, dBal, d2)
	if outcome2 != "kept" || dBal.Decision != "ask" {
		t.Errorf("expected allow/moderate under balanced profile to stay ask/kept, got outcome=%q decision=%q", outcome2, dBal.Decision)
	}
}

func TestCmdRiskResetBothWordOrdersAndPausedDiagnostics(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{Provider: ProviderConfig{URL: "https://example.com", Model: "m"}})
	captureStdout(func() { cmdRisk([]string{"claude", "moderate", "force_allow"}) })
	if got := LoadConfig().harnessPolicy("claude").RiskMap[RiskModerate]; got != ActionForceAllow {
		t.Fatalf("after set force_allow: got %q", got)
	}
	// Reset via `<harness> <tier> reset` (reversed order from Bug #6a).
	captureStdout(func() { cmdRisk([]string{"claude", "moderate", "reset"}) })
	if got := LoadConfig().harnessPolicy("claude").RiskMap[RiskModerate]; got != "" {
		t.Fatalf("after <harness> <tier> reset: expected empty override, got %q", got)
	}

	// Pause session and verify pausedSessions, cmdStatus, and doctorChecks report it.
	t.Setenv("CLAUDE_SESSION_ID", "sess-pause-check")
	captureStdout(func() { cmdPause([]string{"--confirm-bypass"}) })
	if paused := pausedSessions(); len(paused) != 1 || paused[0] != "sess-pause-check" {
		t.Fatalf("pausedSessions: got %v, want [sess-pause-check]", paused)
	}
	statusOut := captureStdout(func() { cmdStatus() })
	if !strings.Contains(statusOut, "PAUSED") {
		t.Errorf("cmdStatus should warn when session is paused, got:\n%s", statusOut)
	}
	checks := doctorChecks(LoadConfig(), nil, false)
	foundPauseWarn := false
	for _, c := range checks {
		if c.Name == "paused_sessions" && c.Status == "warning" && strings.Contains(c.Detail, "sess-pause-check") {
			foundPauseWarn = true
		}
	}
	if !foundPauseWarn {
		t.Errorf("doctorChecks should include paused_sessions warning, got %+v", checks)
	}
	captureStdout(func() { cmdResume(nil) })
}

