package yolonot

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mockLLMRisk returns an httptest server emitting a modern
// {decision, risk, reasoning} classifier response and counting hits.
func mockLLMRisk(decision, risk, reasoning string, hits *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		content := fmt.Sprintf(`{"decision":%q,"risk":%q,"reasoning":%q}`, decision, risk, reasoning)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{{
				"message": map[string]interface{}{"content": content},
			}},
		})
	}))
}

// mockLLMFail returns a server that always 500s, counting hits.
func mockLLMFail(hits *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
	}))
}

// swapEscalationLLM replaces the escalation call seam for a unit test.
func swapEscalationLLM(t *testing.T, fn func(cfg LLMConfig, sys, user string, maxTokens int) (string, error)) {
	t.Helper()
	orig := escalationCallLLM
	escalationCallLLM = fn
	t.Cleanup(func() { escalationCallLLM = orig })
}

func riskJSON(decision, risk string) string {
	return fmt.Sprintf(`{"decision":%q,"risk":%q,"reasoning":"escalation verdict"}`, decision, risk)
}

// escalationTestConfig writes a config with primary + escalation providers
// pointing at the given URLs and returns the loaded Config.
func escalationTestConfig(t *testing.T, primaryURL, escURL string, mutate func(*Config)) Config {
	t.Helper()
	cfg := Config{
		Provider: ProviderConfig{URL: primaryURL, Model: "small-model", Timeout: 5},
	}
	if escURL != "" {
		cfg.Escalation = &EscalationConfig{
			Provider: ProviderConfig{URL: escURL, Model: "big-model", Timeout: 5},
		}
	}
	if mutate != nil {
		mutate(&cfg)
	}
	SaveConfig(cfg)
	return LoadConfig()
}

// --- maybeEscalate unit tests (adoption matrix) ---

func claudeHarness(t *testing.T) Harness {
	t.Helper()
	h := GetHarness("claude")
	if h == nil {
		t.Fatal("claude harness not registered")
	}
	return h
}

// The adoption matrix: which escalation verdicts change the primary d.
func TestMaybeEscalateAdoptionMatrix(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	cfg := escalationTestConfig(t, "http://localhost:1/v1", "http://localhost:2/v1", nil)
	h := claudeHarness(t)

	cases := []struct {
		name        string
		primary     Decision
		escResponse string
		escErr      error
		wantOutcome string
		wantRisk    string // final d.Risk
		wantDec     string // final d.Decision
		wantCacheOK bool
	}{
		{"rescue_allow_safe", Decision{Decision: "ask", Risk: RiskModerate}, riskJSON("allow", "safe"), nil, "rescued", RiskSafe, "allow", true},
		{"rescue_allow_low", Decision{Decision: "ask", Risk: RiskModerate}, riskJSON("allow", "low"), nil, "rescued", RiskLow, "allow", true},
		{"no_adopt_ask_low", Decision{Decision: "ask", Risk: RiskModerate}, riskJSON("ask", "low"), nil, "kept", RiskModerate, "ask", true},
		{"no_adopt_allow_moderate", Decision{Decision: "ask", Risk: RiskModerate}, riskJSON("allow", "moderate"), nil, "kept", RiskModerate, "ask", true},
		{"harden_to_critical", Decision{Decision: "ask", Risk: RiskModerate}, riskJSON("ask", "critical"), nil, "hardened", RiskCritical, "ask", true},
		{"transport_error", Decision{Decision: "ask", Risk: RiskModerate}, "", errors.New("connection refused"), "error", RiskModerate, "ask", false},
		{"timeout_error", Decision{Decision: "ask", Risk: RiskModerate}, "", errors.New("context deadline exceeded"), "error", RiskModerate, "ask", false},
		{"parse_error", Decision{Decision: "ask", Risk: RiskModerate}, "not json at all", nil, "error", RiskModerate, "ask", false},
		// (allow, moderate) resolves to ask on claude/balanced — must also escalate.
		{"tightened_allow_moderate", Decision{Decision: "allow", Risk: RiskModerate}, riskJSON("allow", "safe"), nil, "rescued", RiskSafe, "allow", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			swapEscalationLLM(t, func(_ LLMConfig, _, _ string, _ int) (string, error) {
				return tc.escResponse, tc.escErr
			})
			d := tc.primary
			out, cacheOK := maybeEscalate(h, cfg, &d, "sys", "user", time.Now())
			if !out.Fired {
				t.Fatalf("escalation should fire, outcome=%q", out.Outcome)
			}
			if out.Outcome != tc.wantOutcome {
				t.Errorf("outcome: got %q, want %q", out.Outcome, tc.wantOutcome)
			}
			if d.Risk != tc.wantRisk || d.Decision != tc.wantDec {
				t.Errorf("final d: got %s/%s, want %s/%s", d.Decision, d.Risk, tc.wantDec, tc.wantRisk)
			}
			if cacheOK != tc.wantCacheOK {
				t.Errorf("cacheOK: got %v, want %v", cacheOK, tc.wantCacheOK)
			}
			adopted := tc.wantOutcome == "rescued" || tc.wantOutcome == "hardened"
			if d.Escalated != adopted {
				t.Errorf("d.Escalated: got %v, want %v", d.Escalated, adopted)
			}
			if adopted && out.PrimaryRisk != tc.primary.Risk {
				t.Errorf("PrimaryRisk: got %q, want %q", out.PrimaryRisk, tc.primary.Risk)
			}
		})
	}
}

// Trigger exclusions: critical never escalates; confident allows never
// escalate; paranoid profile (no adoptable tier, no harden window) skips.
func TestMaybeEscalateTriggerExclusions(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	h := claudeHarness(t)

	called := false
	swapEscalationLLM(t, func(_ LLMConfig, _, _ string, _ int) (string, error) {
		called = true
		return riskJSON("allow", "safe"), nil
	})

	cfg := escalationTestConfig(t, "http://localhost:1/v1", "http://localhost:2/v1", nil)

	d := Decision{Decision: "ask", Risk: RiskCritical}
	out, _ := maybeEscalate(h, cfg, &d, "sys", "user", time.Now())
	if called || out.Fired || out.Outcome != "" {
		t.Errorf("critical must not escalate: called=%v out=%+v", called, out)
	}

	d = Decision{Decision: "allow", Risk: RiskSafe}
	out, _ = maybeEscalate(h, cfg, &d, "sys", "user", time.Now())
	if called || out.Fired || out.Outcome != "" {
		t.Errorf("confident allow must not escalate: called=%v out=%+v", called, out)
	}

	// Paranoid: safe/low→ask so nothing is adoptable, moderate→deny so no
	// harden window either — pure tax, must skip before calling.
	cfg = escalationTestConfig(t, "http://localhost:1/v1", "http://localhost:2/v1", func(c *Config) {
		c.Profile = "paranoid"
	})
	d = Decision{Decision: "ask", Risk: RiskModerate}
	out, _ = maybeEscalate(h, cfg, &d, "sys", "user", time.Now())
	if called || out.Fired {
		t.Errorf("paranoid should never reach the escalation call")
	}
	if out.Outcome != "skipped:no-effect" {
		t.Errorf("paranoid skip reason: got %q, want skipped:no-effect", out.Outcome)
	}
}

// Gate skips carry their reason; budget exhaustion skips the call.
func TestMaybeEscalateGatesAndBudget(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	h := claudeHarness(t)

	called := false
	swapEscalationLLM(t, func(_ LLMConfig, _, _ string, _ int) (string, error) {
		called = true
		return riskJSON("allow", "safe"), nil
	})

	// Unconfigured → totally silent.
	cfg := escalationTestConfig(t, "http://localhost:1/v1", "", nil)
	d := Decision{Decision: "ask", Risk: RiskModerate}
	out, cacheOK := maybeEscalate(h, cfg, &d, "sys", "user", time.Now())
	if called || out.Outcome != "" || !cacheOK {
		t.Errorf("unconfigured should be silent: %+v", out)
	}

	// Disabled → skipped:disabled.
	cfg = escalationTestConfig(t, "http://localhost:1/v1", "http://localhost:2/v1", func(c *Config) {
		c.Escalation.Disabled = true
	})
	out, _ = maybeEscalate(h, cfg, &d, "sys", "user", time.Now())
	if called || out.Outcome != "skipped:disabled" {
		t.Errorf("disabled: got %q, want skipped:disabled", out.Outcome)
	}

	// Env kill switch → skipped:env-off.
	cfg = escalationTestConfig(t, "http://localhost:1/v1", "http://localhost:2/v1", nil)
	t.Setenv("YOLONOT_ESCALATION", "off")
	out, _ = maybeEscalate(h, cfg, &d, "sys", "user", time.Now())
	if called || out.Outcome != "skipped:env-off" {
		t.Errorf("env-off: got %q, want skipped:env-off", out.Outcome)
	}
	t.Setenv("YOLONOT_ESCALATION", "")

	// Budget: hook already ran past the budget → skipped:budget.
	out, _ = maybeEscalate(h, cfg, &d, "sys", "user", time.Now().Add(-escalationHookBudget-time.Second))
	if called || out.Outcome != "skipped:budget" {
		t.Errorf("budget: got %q, want skipped:budget", out.Outcome)
	}
}

// --- Hook integration tests ---

// Primary allow: the escalation server must receive zero requests — the
// hot path pays nothing for the feature.
func TestIntegration_Escalation_HotPathUntouched(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	var escHits int32
	primary := mockLLMRisk("allow", "safe", "routine", nil)
	defer primary.Close()
	esc := mockLLMRisk("allow", "safe", "unused", &escHits)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, nil)

	out := runHookWithStruct(t, makePrePayload("esc-hotpath", "some-novel-tool --flag", "/tmp"))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("expected allow, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if atomic.LoadInt32(&escHits) != 0 {
		t.Errorf("escalation server hit %d times on a primary allow", escHits)
	}
}

// Primary ask + escalation allow/safe: rescued into allow, approval saved,
// log carries the full escalation record.
func TestIntegration_Escalation_Rescue(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	var escHits int32
	primary := mockLLMRisk("ask", "moderate", "unsure about this", nil)
	defer primary.Close()
	esc := mockLLMRisk("allow", "safe", "read-only maintenance command", &escHits)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, nil)

	cwd := t.TempDir()
	out := runHookWithStruct(t, makePrePayload("esc-rescue", "some-novel-tool --flag", cwd))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("expected rescued allow, got %q (%s)", resp.HookSpecificOutput.PermissionDecision, out)
	}
	if atomic.LoadInt32(&escHits) != 1 {
		t.Errorf("escalation server hits: got %d, want 1", escHits)
	}
	projSID := ProjectSessionID("esc-rescue", cwd)
	if !ContainsLine(projSID, "approved", "some-novel-tool --flag") {
		t.Errorf("rescued allow should be session-approved")
	}

	entries := ReadRecentDecisions(1)
	if len(entries) != 1 {
		t.Fatal("no decision logged")
	}
	e := entries[0]
	if !e.Escalated || e.EscalationOutcome != "rescued" {
		t.Errorf("log: escalated=%v outcome=%q, want true/rescued", e.Escalated, e.EscalationOutcome)
	}
	if e.EscalationModel != "big-model" || e.EscalationRisk != "safe" || e.EscalationDecision != "allow" {
		t.Errorf("log escalation verdict fields wrong: %+v", e)
	}
	if e.PrimaryRisk != "moderate" || e.Risk != "safe" {
		t.Errorf("log tier attribution: primary_risk=%q risk=%q", e.PrimaryRisk, e.Risk)
	}
}

// Escalation says (ask, low): passes the tier band but not the decision
// check — must NOT be adopted (it would resolve to ask and poison the
// cache as a permanent ask).
func TestIntegration_Escalation_AskLowNotAdopted(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	primary := mockLLMRisk("ask", "moderate", "unsure", nil)
	defer primary.Close()
	esc := mockLLMRisk("ask", "low", "still slightly unsure", nil)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, nil)

	out := runHookWithStruct(t, makePrePayload("esc-asklow", "some-novel-tool --flag", "/tmp"))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("expected ask to stand, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	e := ReadRecentDecisions(1)[0]
	if e.EscalationOutcome != "kept" || e.Risk != "moderate" {
		t.Errorf("outcome=%q risk=%q, want kept/moderate", e.EscalationOutcome, e.Risk)
	}
}

// Escalation error: the primary ask stands, the error class is logged, and
// the script cache is NOT written (a transient outage must not freeze the
// one-shot rescue out of the cross-session cache).
func TestIntegration_Escalation_ErrorKeepsAskAndSkipsCache(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	primary := mockLLMRisk("ask", "moderate", "unsure", nil)
	defer primary.Close()
	esc := mockLLMFail(nil)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, nil)

	// Script-attached command so the cache path is exercised.
	cwd := t.TempDir()
	os.WriteFile(filepath.Join(cwd, "job.sh"), []byte("#!/bin/sh\necho hi\n"), 0755)

	out := runHookWithStruct(t, makePrePayload("esc-err", "bash job.sh", cwd))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("expected ask on escalation error, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	e := ReadRecentDecisions(1)[0]
	if e.EscalationError != "api" && e.EscalationError != "transport" {
		t.Errorf("escalation_error: got %q, want api/transport", e.EscalationError)
	}
	if e.EscalationOutcome != "error" {
		t.Errorf("outcome: got %q, want error", e.EscalationOutcome)
	}

	cacheFiles, _ := os.ReadDir(filepath.Join(home, ".yolonot", "cache"))
	if len(cacheFiles) != 0 {
		t.Errorf("cache must not be written on escalation error, found %d files", len(cacheFiles))
	}
}

// Successful escalation on a script command writes the post-adoption
// verdict to the cache; the replay logs provenance and never re-fires the
// escalation model.
func TestIntegration_Escalation_CacheProvenance(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	var escHits int32
	primary := mockLLMRisk("ask", "moderate", "unsure", nil)
	defer primary.Close()
	esc := mockLLMRisk("allow", "safe", "fine", &escHits)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, nil)

	cwd := t.TempDir()
	os.WriteFile(filepath.Join(cwd, "job.sh"), []byte("#!/bin/sh\necho hi\n"), 0755)

	out := runHookWithStruct(t, makePrePayload("esc-cache-a", "bash job.sh", cwd))
	if got := parseResponse(t, out).HookSpecificOutput.PermissionDecision; got != "allow" {
		t.Fatalf("first run: expected allow, got %q", got)
	}

	// Different session so the session-approved shortcut can't mask the cache.
	out = runHookWithStruct(t, makePrePayload("esc-cache-b", "bash job.sh", cwd))
	if got := parseResponse(t, out).HookSpecificOutput.PermissionDecision; got != "allow" {
		t.Fatalf("cache replay: expected allow, got %q", got)
	}
	if atomic.LoadInt32(&escHits) != 1 {
		t.Errorf("escalation must fire once, not per replay: hits=%d", escHits)
	}
	e := ReadRecentDecisions(1)[0]
	if e.Layer != "cache" || !e.Escalated {
		t.Errorf("cache replay should carry escalation provenance: layer=%q escalated=%v", e.Layer, e.Escalated)
	}
}

// unresolved:"deny" degrades a post-escalation residual ask into a deny
// that names both verdicts.
func TestIntegration_Escalation_UnresolvedDeny(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	primary := mockLLMRisk("ask", "moderate", "unsure", nil)
	defer primary.Close()
	esc := mockLLMRisk("ask", "moderate", "also unsure", nil)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, func(c *Config) {
		c.Escalation.Unresolved = "deny"
	})

	out := runHookWithStruct(t, makePrePayload("esc-unresolved", "some-novel-tool --flag", "/tmp"))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("expected unresolved deny, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "unresolved after escalation") {
		t.Errorf("reason should explain the unresolved policy, got %q", resp.HookSpecificOutput.PermissionDecisionReason)
	}

	// But a skipped escalation (not fired) must NOT deny.
	t.Setenv("YOLONOT_ESCALATION", "off")
	out = runHookWithStruct(t, makePrePayload("esc-unresolved-2", "some-other-tool --flag", "/tmp"))
	if got := parseResponse(t, out).HookSpecificOutput.PermissionDecision; got != "ask" {
		t.Errorf("unfired escalation must keep ask, got %q", got)
	}
}

// Rules-layer denies resolve before Step 5 — never escalated.
func TestIntegration_Escalation_RuleDenyNeverEscalates(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	var escHits, primHits int32
	primary := mockLLMRisk("ask", "moderate", "unsure", &primHits)
	defer primary.Close()
	esc := mockLLMRisk("allow", "safe", "would rescue", &escHits)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, nil)
	writeGlobalRules(t, home, "deny-cmd *dangerous-tool*\n")

	out := runHookWithStruct(t, makePrePayload("esc-ruledeny", "dangerous-tool --run", "/tmp"))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("expected rule deny, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if atomic.LoadInt32(&primHits) != 0 || atomic.LoadInt32(&escHits) != 0 {
		t.Errorf("rule deny must not reach any LLM: primary=%d escalation=%d", primHits, escHits)
	}
}

// Harden-upward: primary (ask, moderate) + escalation critical raises the
// tier, and a critical→deny risk map turns it into a deny.
func TestIntegration_Escalation_HardenUpward(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	primary := mockLLMRisk("ask", "moderate", "unsure", nil)
	defer primary.Close()
	esc := mockLLMRisk("ask", "critical", "wipes data", nil)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, func(c *Config) {
		c.RiskMaps = map[string]map[string]string{
			"claude": {"critical": "deny"},
		}
	})

	out := runHookWithStruct(t, makePrePayload("esc-harden", "some-novel-tool --flag", "/tmp"))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("hardened critical should deny under a critical→deny map, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	e := ReadRecentDecisions(1)[0]
	if e.EscalationOutcome != "hardened" || e.Risk != "critical" || e.PrimaryRisk != "moderate" {
		t.Errorf("harden log: outcome=%q risk=%q primary=%q", e.EscalationOutcome, e.Risk, e.PrimaryRisk)
	}
}

// --- cmdEscalation CLI tests ---

// on/off flip Disabled without touching the provider block; off before
// setup explains itself instead of writing an empty block.
func TestCmdEscalationOnOff(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	// Not configured: on/off must not create a block.
	out := captureStdout(func() { cmdEscalation([]string{"off"}) })
	if !strings.Contains(out, "not configured") {
		t.Errorf("off before setup should explain, got %q", out)
	}
	if LoadConfig().Escalation != nil {
		t.Errorf("off before setup must not create an escalation block")
	}

	escalationTestConfig(t, "http://localhost:1/v1", "http://localhost:2/v1", nil)

	captureStdout(func() { cmdEscalation([]string{"off"}) })
	cfg := LoadConfig()
	if cfg.Escalation == nil || !cfg.Escalation.Disabled {
		t.Fatalf("off should set Disabled, got %+v", cfg.Escalation)
	}
	if cfg.Escalation.Provider.Model != "big-model" {
		t.Errorf("off must keep the provider config, got %+v", cfg.Escalation.Provider)
	}

	captureStdout(func() { cmdEscalation([]string{"on"}) })
	cfg = LoadConfig()
	if cfg.Escalation.Disabled {
		t.Errorf("on should clear Disabled")
	}
}

// Bare `yolonot escalation` renders state without mutating anything, and
// warns when escalation resolves to the same provider+model as the primary.
func TestCmdEscalationStatus(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	out := captureStdout(func() { cmdEscalation(nil) })
	if !strings.Contains(out, "not configured") {
		t.Errorf("unconfigured status should say so, got %q", out)
	}

	escalationTestConfig(t, "http://localhost:1/v1", "http://localhost:2/v1", nil)
	out = captureStdout(func() { cmdEscalation(nil) })
	if !strings.Contains(out, "Escalation: ON") || !strings.Contains(out, "big-model") {
		t.Errorf("configured status should show ON + model, got %q", out)
	}
	if strings.Contains(out, "SAME provider+model") {
		t.Errorf("distinct providers must not warn, got %q", out)
	}

	// Same URL + same model → placebo warning.
	SaveConfig(Config{
		Provider:   ProviderConfig{URL: "http://localhost:1/v1", Model: "small-model"},
		Escalation: &EscalationConfig{Provider: ProviderConfig{URL: "http://localhost:1/v1", Model: "small-model"}},
	})
	out = captureStdout(func() { cmdEscalation(nil) })
	if !strings.Contains(out, "SAME provider+model") {
		t.Errorf("same-model config should warn, got %q", out)
	}
}

// Stats must surface escalation counters; log lines must carry the marker.
func TestStatsAndLogEscalationSurfacing(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	LogDecision(DecisionEntry{Command: "cmd-a", Decision: "allow", Layer: "llm",
		Escalated: true, EscalationOutcome: "rescued", EscalationMs: 1200})
	LogDecision(DecisionEntry{Command: "cmd-b", Decision: "ask", Layer: "llm",
		Escalated: true, EscalationOutcome: "kept", EscalationMs: 800})
	LogDecision(DecisionEntry{Command: "cmd-c", Decision: "allow", Layer: "cache",
		Escalated: true}) // replay: provenance only, no outcome → not a fire

	out := captureStdout(cmdStats)
	if !strings.Contains(out, "Escalation:") {
		t.Fatalf("stats missing escalation section:\n%s", out)
	}
	if !strings.Contains(out, "2 fired, 1 rescued (50%)") {
		t.Errorf("stats counters wrong:\n%s", out)
	}

	out = captureStdout(func() { cmdLog(10) })
	if !strings.Contains(out, "⤴esc") {
		t.Errorf("log lines missing escalation marker:\n%s", out)
	}
}

// Eval cascade: primary raw responses are re-judged through the shared
// trigger/adopt helpers; primary calls are never repeated; escalation
// errors keep the primary verdict.
func TestRunCascade(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	origEval := evalCallLLM
	t.Cleanup(func() { evalCallLLM = origEval })

	escCalls := 0
	evalCallLLM = func(cfg LLMConfig, sys, user string, maxTokens int) (string, error) {
		escCalls++
		if strings.Contains(user, "wipe-everything") {
			return riskJSON("ask", "critical"), nil
		}
		return riskJSON("allow", "safe"), nil
	}

	cases := []EvalCase{
		{ID: "c1", Command: "novel-tool run", Expected: "allow"},
		{ID: "c2", Command: "cat file.txt", Expected: "allow"},
		{ID: "c3", Command: "wipe-everything now", Expected: "ask"},
	}
	primary := []CaseResult{
		// c1: primary asked (moderate) → cascade rescues to allow.
		{CaseID: "c1", Expected: "allow", RawResponses: []string{`{"decision":"ask","risk":"moderate","reasoning":"unsure"}`}},
		// c2: primary allowed (safe) → no escalation, prediction unchanged.
		{CaseID: "c2", Expected: "allow", RawResponses: []string{`{"decision":"allow","risk":"safe","reasoning":"read"}`}},
		// c3: primary asked (moderate) → escalation hardens to critical, ask stands.
		{CaseID: "c3", Expected: "ask", RawResponses: []string{`{"decision":"ask","risk":"moderate","reasoning":"hmm"}`}},
	}

	results, fired, calls := runCascade(cases, primary, LLMConfig{URL: "http://localhost:9/v1", Model: "big"}, "sys", EvalOptions{Runs: 1, MaxTokens: 256})

	if fired != 2 || calls != 2 {
		t.Errorf("fired/calls: got %d/%d, want 2/2 (c2 must not escalate)", fired, calls)
	}
	if got := results[0].Predictions[0]; got != "allow" {
		t.Errorf("c1 cascade prediction: got %q, want allow (rescued)", got)
	}
	if got := results[1].Predictions[0]; got != "allow" {
		t.Errorf("c2 prediction should pass through, got %q", got)
	}
	if got := results[2].Predictions[0]; got != "ask" {
		t.Errorf("c3 hardened prediction should stay ask, got %q", got)
	}

	// Escalation error → primary verdict stands.
	evalCallLLM = func(cfg LLMConfig, sys, user string, maxTokens int) (string, error) {
		return "", errIntentional
	}
	results, _, _ = runCascade(cases[:1], primary[:1], LLMConfig{URL: "http://localhost:9/v1", Model: "big"}, "sys", EvalOptions{Runs: 1, MaxTokens: 256})
	if got := results[0].Predictions[0]; got != "ask" {
		t.Errorf("escalation error should keep primary ask, got %q", got)
	}
}

var errIntentional = errors.New("intentional test failure")

// REVIEW FIX REGRESSION: a resolved DENY cell (strict profile: high→deny)
// is the user's explicit policy, not classifier uncertainty. Escalation
// must not fire on it, and can never rescue it into an allow.
func TestMaybeEscalateNeverRescuesResolvedDeny(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	h := claudeHarness(t)

	called := false
	swapEscalationLLM(t, func(_ LLMConfig, _, _ string, _ int) (string, error) {
		called = true
		return riskJSON("allow", "safe"), nil
	})

	cfg := escalationTestConfig(t, "http://localhost:1/v1", "http://localhost:2/v1", func(c *Config) {
		c.Profile = "strict" // high → deny
	})

	d := Decision{Decision: "ask", Risk: RiskHigh}
	out, _ := maybeEscalate(h, cfg, &d, "sys", "user", time.Now())
	if called {
		t.Fatalf("escalation must not consult the model for a resolved deny")
	}
	if out.Fired || d.Decision != "ask" || d.Risk != RiskHigh {
		t.Errorf("resolved deny must stand untouched: out=%+v d=%+v", out, d)
	}

	// Same via a custom risk-map override: moderate → deny.
	cfg = escalationTestConfig(t, "http://localhost:1/v1", "http://localhost:2/v1", func(c *Config) {
		c.RiskMaps = map[string]map[string]string{"claude": {"moderate": "deny"}}
	})
	d = Decision{Decision: "ask", Risk: RiskModerate}
	maybeEscalate(h, cfg, &d, "sys", "user", time.Now())
	if called || d.Risk != RiskModerate {
		t.Errorf("custom deny cell must not be rescuable")
	}
}

// REVIEW FIX REGRESSION: a budget skip is transient — it must suppress the
// cache write exactly like an escalation error, so the one-shot rescue can
// re-fire on a faster future run.
func TestMaybeEscalateBudgetSkipSuppressesCache(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	h := claudeHarness(t)
	cfg := escalationTestConfig(t, "http://localhost:1/v1", "http://localhost:2/v1", nil)

	d := Decision{Decision: "ask", Risk: RiskModerate}
	out, cacheOK := maybeEscalate(h, cfg, &d, "sys", "user", time.Now().Add(-escalationHookBudget-time.Second))
	if out.Outcome != "skipped:budget" {
		t.Fatalf("expected budget skip, got %q", out.Outcome)
	}
	if cacheOK {
		t.Errorf("budget skip must suppress the cache write")
	}
}

// REVIEW FIX REGRESSION: an LLM response embedding "escalated": true must
// not forge provenance — ParseDecision strips it; cache decode keeps it.
func TestParseDecisionStripsForgedEscalated(t *testing.T) {
	d := ParseDecision(`{"decision":"allow","risk":"safe","reasoning":"fine","escalated":true}`)
	if d == nil {
		t.Fatal("parse failed")
	}
	if d.Escalated {
		t.Errorf("model-supplied escalated flag must be stripped")
	}
}

// Planned invariant: the oversize abstain path never reaches any LLM —
// primary or escalation.
func TestIntegration_Escalation_OversizeNeverEscalates(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	var primHits, escHits int32
	primary := mockLLMRisk("ask", "moderate", "unsure", &primHits)
	defer primary.Close()
	esc := mockLLMRisk("allow", "safe", "would rescue", &escHits)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, nil)

	big := "echo " + strings.Repeat("x", maxClassifierPromptBytes+1024)
	// The payload exceeds the OS pipe buffer — write it from a goroutine
	// or the test deadlocks before cmdHook ever reads stdin.
	data, _ := json.Marshal(makePrePayload("esc-oversize", big, "/tmp"))
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	go func() {
		w.Write(data)
		w.Close()
	}()
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()
	out := captureStdout(func() { cmdHook() })
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "ask" && resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("oversize should abstain to ask/deny, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if atomic.LoadInt32(&primHits) != 0 || atomic.LoadInt32(&escHits) != 0 {
		t.Errorf("oversize must not reach any LLM: primary=%d escalation=%d", primHits, escHits)
	}
}

// Planned scenario 10 completion: unresolved:"deny" also covers the
// escalation ERROR path — provider down at 3am still yields a definitive
// deny, not a stall. And the degraded verdict must NOT be cached, so a
// byte-identical replay stays consistent (re-runs the pipeline) instead of
// flipping deny → ask.
func TestIntegration_Escalation_UnresolvedDenyOnErrorAndNoCacheFlipFlop(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	primary := mockLLMRisk("ask", "moderate", "unsure", nil)
	defer primary.Close()
	esc := mockLLMFail(nil)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, func(c *Config) {
		c.Escalation.Unresolved = "deny"
	})

	cwd := t.TempDir()
	os.WriteFile(filepath.Join(cwd, "job.sh"), []byte("#!/bin/sh\necho hi\n"), 0755)

	out := runHookWithStruct(t, makePrePayload("esc-unres-err", "bash job.sh", cwd))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("escalation error + unresolved:deny should deny, got %q", resp.HookSpecificOutput.PermissionDecision)
	}

	// Nothing cached → replay re-runs the pipeline and denies again.
	cacheFiles, _ := os.ReadDir(filepath.Join(home, ".yolonot", "cache"))
	if len(cacheFiles) != 0 {
		t.Fatalf("degraded verdict must not be cached, found %d files", len(cacheFiles))
	}
	out = runHookWithStruct(t, makePrePayload("esc-unres-err-2", "bash job.sh", cwd))
	if got := parseResponse(t, out).HookSpecificOutput.PermissionDecision; got != "deny" {
		t.Errorf("replay must stay deny (no cached ask flip-flop), got %q", got)
	}
}

// cmdCheck parity: the dry-run shows the escalation step and the same
// final verdict the hook produces.
func TestCmdCheckEscalationParity(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)

	primary := mockLLMRisk("ask", "moderate", "unsure", nil)
	defer primary.Close()
	esc := mockLLMRisk("allow", "safe", "routine read", nil)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, nil)

	out := captureStdout(func() { cmdCheck("some-novel-tool --flag") })
	if !strings.Contains(out, "Escalation:") {
		t.Fatalf("check output missing escalation step:\n%s", out)
	}
	if !strings.Contains(out, "rescued") {
		t.Errorf("check should show the rescued outcome:\n%s", out)
	}
	if !strings.Contains(out, "Result: ALLOW") || !strings.Contains(out, "llm+esc") {
		t.Errorf("check final verdict should be ALLOW via llm+esc:\n%s", out)
	}
}

// Harden on the opencode harness: its map denies critical, so a big-model
// critical verdict must surface as deny through the opencode adapter path.
func TestIntegration_Escalation_HardenOnOpencode(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	t.Setenv("YOLONOT_HARNESS", "opencode")
	defer os.Unsetenv("YOLONOT_HARNESS")

	primary := mockLLMRisk("ask", "moderate", "unsure", nil)
	defer primary.Close()
	esc := mockLLMRisk("ask", "critical", "destroys data", nil)
	defer esc.Close()
	escalationTestConfig(t, primary.URL, esc.URL, nil)

	runHookWithStruct(t, makePrePayload("esc-oc-harden", "some-novel-tool --flag", "/tmp"))
	e := ReadRecentDecisions(1)[0]
	if e.EscalationOutcome != "hardened" || e.Risk != "critical" {
		t.Errorf("opencode harden log: outcome=%q risk=%q", e.EscalationOutcome, e.Risk)
	}
	if e.Decision != "deny" {
		t.Errorf("opencode critical→deny map should deny the hardened verdict, got %q", e.Decision)
	}
}
