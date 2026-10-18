package yolonot

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFastProfile_NoAsk locks the user-stated invariant: `fast` profile
// has no ask cells. Regression guard — if someone "softens" fast with an
// ask later it changes its meaning ("go fast, only block prod-breaking").
func TestFastProfile_NoAsk(t *testing.T) {
	p := GetBuiltinProfile("fast")
	if p == nil {
		t.Fatal("fast profile missing")
	}
	for tier, action := range p.Map {
		if action == ActionAsk {
			t.Errorf("fast/%s = ask; fast must have no ask cells (allow|deny only)", tier)
		}
	}
	// Tighter spec: critical+high must deny, rest must allow.
	if p.Map[RiskHigh] != ActionDeny || p.Map[RiskCritical] != ActionDeny {
		t.Errorf("fast: high/critical must deny, got %s/%s", p.Map[RiskHigh], p.Map[RiskCritical])
	}
	for _, t2 := range []string{RiskSafe, RiskLow, RiskModerate} {
		if p.Map[t2] != ActionAllow {
			t.Errorf("fast/%s = %s, want allow", t2, p.Map[t2])
		}
	}
}

func TestBuiltinProfilesAllPresent(t *testing.T) {
	want := []string{"fast", "balanced", "strict", "paranoid"}
	for _, n := range want {
		if GetBuiltinProfile(n) == nil {
			t.Errorf("missing built-in profile %q", n)
		}
	}
}

func TestTranslateProfile_ClaudePreservesAsk(t *testing.T) {
	p := GetBuiltinProfile("balanced")
	out := TranslateProfile(p.Map, &ClaudeHarness{})
	if out[RiskModerate] != ActionAsk {
		t.Errorf("claude balanced moderate = %q, want ask", out[RiskModerate])
	}
	if out[RiskHigh] != ActionAsk {
		t.Errorf("claude balanced high = %q, want ask", out[RiskHigh])
	}
}

func TestTranslateProfile_CodexAskCollapse(t *testing.T) {
	p := GetBuiltinProfile("balanced")
	out := TranslateProfile(p.Map, &CodexHarness{})
	if out[RiskModerate] != ActionPassthrough {
		t.Errorf("codex balanced moderate = %q, want passthrough", out[RiskModerate])
	}
	if out[RiskHigh] != ActionDeny {
		t.Errorf("codex balanced high = %q, want deny", out[RiskHigh])
	}
}

func TestTranslateProfile_OpencodeAskCollapse(t *testing.T) {
	p := GetBuiltinProfile("paranoid")
	out := TranslateProfile(p.Map, &OpencodeHarness{})
	// safe=ask in paranoid → opencode has no passthrough → allow
	if out[RiskSafe] != ActionAllow {
		t.Errorf("opencode paranoid safe = %q, want allow (no passthrough/ask)", out[RiskSafe])
	}
	if out[RiskCritical] != ActionDeny {
		t.Errorf("opencode paranoid critical = %q, want deny", out[RiskCritical])
	}
}

func TestResolveRiskMap_ProfileBeneathConfigOverride(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	cfg := Config{
		Profile: "fast",
		RiskMaps: map[string]map[string]string{
			"claude": {RiskHigh: ActionAsk}, // user pinned ask on top of fast=deny
		},
	}
	SaveConfig(cfg)
	m := ResolveRiskMap(&ClaudeHarness{})
	if m[RiskHigh] != ActionAsk {
		t.Errorf("config override should beat profile: got %q, want ask", m[RiskHigh])
	}
	// fast still applies on tiers without an explicit override:
	if m[RiskCritical] != ActionDeny {
		t.Errorf("fast/critical should resolve to deny, got %q", m[RiskCritical])
	}
}

func TestResolveRiskMap_PerHarnessProfileOverride(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	cfg := Config{
		Profile:         "fast",
		ProfileOverride: map[string]string{"claude": "strict"},
	}
	SaveConfig(cfg)

	// Codex still on global fast → high=deny
	mc := ResolveRiskMap(&CodexHarness{})
	if mc[RiskHigh] != ActionDeny {
		t.Errorf("codex global fast: high=%q, want deny", mc[RiskHigh])
	}
	// Claude switched to strict → high=deny too, but moderate=ask
	mClaude := ResolveRiskMap(&ClaudeHarness{})
	if mClaude[RiskHigh] != ActionDeny {
		t.Errorf("claude override strict: high=%q, want deny", mClaude[RiskHigh])
	}
	if mClaude[RiskModerate] != ActionAsk {
		t.Errorf("claude override strict: moderate=%q, want ask", mClaude[RiskModerate])
	}
}

func TestResolveRiskMap_DefaultProfileBalanced(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	SaveConfig(Config{}) // empty → DefaultProfileName=balanced
	m := ResolveRiskMap(&ClaudeHarness{})
	// balanced matches Claude's shipped default for backward compat.
	if m[RiskModerate] != ActionAsk {
		t.Errorf("default profile claude moderate=%q, want ask", m[RiskModerate])
	}
	if m[RiskCritical] != ActionAsk {
		t.Errorf("default profile claude critical=%q, want ask (no regression on upgrade)", m[RiskCritical])
	}
}

// TestBalancedProfile_MatchesClaudeGeminiDefaults locks the no-regression
// invariant: applying the default profile to a fresh Claude/Gemini install
// must reproduce the harness's shipped RiskMap exactly. Without this guard
// we silently tighten policy on upgrade.
func TestBalancedProfile_MatchesClaudeGeminiDefaults(t *testing.T) {
	for _, h := range []Harness{&ClaudeHarness{}, &GeminiHarness{}} {
		shipped := h.RiskMap()
		balanced := GetBuiltinProfile("balanced")
		translated := TranslateProfile(balanced.Map, h)
		for tier, want := range shipped {
			if translated[tier] != want {
				t.Errorf("%s/%s: shipped=%q balanced(translated)=%q — balanced must match shipped defaults", h.Name(), tier, want, translated[tier])
			}
		}
	}
}

func TestValidateCustomProfile_RejectBuiltinName(t *testing.T) {
	err := ValidateCustomProfile("fast", map[string]string{
		RiskSafe: "allow", RiskLow: "allow", RiskModerate: "allow", RiskHigh: "deny", RiskCritical: "deny",
	})
	if err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Errorf("expected built-in collision error, got %v", err)
	}
}

func TestValidateCustomProfile_RejectMissingTier(t *testing.T) {
	err := ValidateCustomProfile("my-prof", map[string]string{RiskSafe: "allow"})
	if err == nil {
		t.Error("expected error for missing tiers")
	}
}

func TestValidateCustomProfile_RejectBadName(t *testing.T) {
	err := ValidateCustomProfile("Bad Name", map[string]string{
		RiskSafe: "allow", RiskLow: "allow", RiskModerate: "allow", RiskHigh: "deny", RiskCritical: "deny",
	})
	if err == nil {
		t.Error("expected name validation error")
	}
}

func TestValidateCustomProfile_RejectPassthroughInProfile(t *testing.T) {
	// Custom profiles use the canonical action set {allow, ask, deny}.
	// passthrough is a per-harness translation result, not a profile-author
	// concept — disallow it at validation.
	err := ValidateCustomProfile("my-prof", map[string]string{
		RiskSafe: "allow", RiskLow: "allow", RiskModerate: "passthrough",
		RiskHigh: "deny", RiskCritical: "deny",
	})
	if err == nil {
		t.Error("expected error for passthrough in custom profile")
	}
}

func TestCustomProfile_LookupAndUse(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	cfg := Config{
		Profile: "my-prof",
		Policy: PolicyConfig{Profiles: map[string]map[string]string{
			"my-prof": {
				RiskSafe:     ActionAllow,
				RiskLow:      ActionAllow,
				RiskModerate: ActionAllow,
				RiskHigh:     ActionAsk,
				RiskCritical: ActionDeny,
			},
		}},
	}
	SaveConfig(cfg)

	p := LookupProfile(cfg, "my-prof")
	if p == nil {
		t.Fatal("custom profile not found")
	}
	if p.Builtin {
		t.Error("custom profile incorrectly marked builtin")
	}
	m := ResolveRiskMap(&ClaudeHarness{})
	if m[RiskHigh] != ActionAsk {
		t.Errorf("custom profile claude high=%q, want ask", m[RiskHigh])
	}
}

func TestResolveActiveProfile_EnvGlobalBeatsConfig(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	SaveConfig(Config{Profile: "balanced"})
	t.Setenv("YOLONOT_PROFILE", "fast")

	m := ResolveRiskMap(&ClaudeHarness{})
	if m[RiskHigh] != ActionDeny {
		t.Errorf("YOLONOT_PROFILE=fast should pin claude/high=deny, got %q", m[RiskHigh])
	}
}

// TestResolveActiveProfile_PerHarnessConfigBeatsGlobalEnv exercises the
// "more specific beats more general" rule across config/env scope tiers.
// Without this, YOLONOT_PROFILE=fast in a shell would silently nuke a
// long-standing per-harness config override.
func TestResolveActiveProfile_PerHarnessConfigBeatsGlobalEnv(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	SaveConfig(Config{
		Profile:         "balanced",
		ProfileOverride: map[string]string{"claude": "strict"},
	})
	t.Setenv("YOLONOT_PROFILE", "fast")

	mClaude := ResolveRiskMap(&ClaudeHarness{})
	if mClaude[RiskHigh] != ActionDeny {
		t.Errorf("per-harness config strict should beat global env fast: claude high=%q, want deny", mClaude[RiskHigh])
	}
	// Other harnesses still pick up the global env pin.
	mCodex := ResolveRiskMap(&CodexHarness{})
	if mCodex[RiskModerate] != ActionAllow {
		t.Errorf("codex still on env-global fast: moderate=%q, want allow", mCodex[RiskModerate])
	}
}

func TestResolveActiveProfile_EnvHarnessBeatsEnvGlobal(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	SaveConfig(Config{})
	t.Setenv("YOLONOT_PROFILE", "fast")
	t.Setenv("YOLONOT_CLAUDE_PROFILE", "strict")

	mc := ResolveRiskMap(&ClaudeHarness{})
	if mc[RiskLow] != ActionAsk {
		t.Errorf("claude env override strict: low=%q, want ask", mc[RiskLow])
	}
	mCodex := ResolveRiskMap(&CodexHarness{})
	if mCodex[RiskHigh] != ActionDeny {
		t.Errorf("codex env global fast: high=%q, want deny", mCodex[RiskHigh])
	}
	if mCodex[RiskModerate] != ActionAllow {
		t.Errorf("codex env global fast: moderate=%q, want allow (translated)", mCodex[RiskModerate])
	}
}

func TestResolveActiveProfile_SessionPinBeatsEnv(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	SaveConfig(Config{Profile: "balanced"})
	t.Setenv("YOLONOT_PROFILE", "fast")
	t.Setenv("CLAUDE_SESSION_ID", "test-sess-001")

	if err := writeSessionProfile("test-sess-001", "strict"); err != nil {
		t.Fatal(err)
	}

	m := ResolveRiskMap(&ClaudeHarness{})
	// strict claude: low=ask, high=deny, critical=deny
	if m[RiskLow] != ActionAsk {
		t.Errorf("session-pinned strict: low=%q, want ask", m[RiskLow])
	}
	if m[RiskHigh] != ActionDeny {
		t.Errorf("session-pinned strict: high=%q, want deny", m[RiskHigh])
	}
}

func TestSessionProfile_ClearRemovesPin(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	SaveConfig(Config{Profile: "balanced"})
	t.Setenv("CLAUDE_SESSION_ID", "test-sess-002")

	if err := writeSessionProfile("test-sess-002", "fast"); err != nil {
		t.Fatal(err)
	}
	if got := readSessionProfile("test-sess-002"); got != "fast" {
		t.Fatalf("readSessionProfile = %q, want fast", got)
	}
	if err := clearSessionProfile("test-sess-002"); err != nil {
		t.Fatal(err)
	}
	if got := readSessionProfile("test-sess-002"); got != "" {
		t.Errorf("after clear: readSessionProfile = %q, want empty", got)
	}
	// clear is idempotent
	if err := clearSessionProfile("test-sess-002"); err != nil {
		t.Errorf("clear should be idempotent, got %v", err)
	}
}

// TestSessionProfile_RejectsPathTraversal locks the security invariant
// that a hostile session ID cannot escape the sessions/ dir via
// path components. Same defence applies to pauseFile and sessionPath.
func TestSessionProfile_RejectsPathTraversal(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	bad := []string{
		"../etc/passwd",
		"../../tmp/pwn",
		"a/b",
		"foo\\bar",
		"a..b",                   // contains '..'
		"",                       // empty
		strings.Repeat("a", 200), // too long
	}
	for _, sid := range bad {
		if got := sessionProfilePath(sid); got != "" {
			t.Errorf("sessionProfilePath(%q) = %q, want empty (rejected)", sid, got)
		}
		if err := writeSessionProfile(sid, "fast"); err == nil {
			t.Errorf("writeSessionProfile(%q) returned nil, want error", sid)
		}
	}
	good := []string{"abc123", "uuid-1234-5678", "session_id.with.dots"}
	for _, sid := range good {
		if got := sessionProfilePath(sid); got == "" {
			t.Errorf("sessionProfilePath(%q) = empty, want non-empty (valid)", sid)
		}
	}
}

// TestLookupProfile_DropsInvalidHandEditedActions verifies hand-edited
// custom profiles with bad action values fall back to safe defaults
// per-cell rather than letting a typo land at runtime as an unknown
// action that would later misroute in applyRiskMap.
func TestLookupProfile_DropsInvalidHandEditedActions(t *testing.T) {
	cfg := Config{
		Policy: PolicyConfig{Profiles: map[string]map[string]string{
			"hand-edited": {
				RiskSafe:     ActionAllow,
				RiskLow:      "passthrough", // invalid in profile
				RiskModerate: "yolo",        // typo
				RiskHigh:     ActionDeny,
				RiskCritical: ActionDeny,
			},
		}},
	}
	p := LookupProfile(cfg, "hand-edited")
	if p == nil {
		t.Fatal("custom profile not found")
	}
	balanced := GetBuiltinProfile(DefaultProfileName).Map
	if p.Map[RiskLow] != balanced[RiskLow] {
		t.Errorf("invalid action passthrough: low=%q, want fallback %q", p.Map[RiskLow], balanced[RiskLow])
	}
	if p.Map[RiskModerate] != balanced[RiskModerate] {
		t.Errorf("typo action: moderate=%q, want fallback %q", p.Map[RiskModerate], balanced[RiskModerate])
	}
	if p.Map[RiskHigh] != ActionDeny {
		t.Errorf("valid action high should pass through: got %q, want deny", p.Map[RiskHigh])
	}
}

func TestResolveActiveProfile_UnknownNameFallsBack(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	cfg := Config{Profile: "does-not-exist"}
	SaveConfig(cfg)
	p := ResolveActiveProfile(LoadConfig(), &ClaudeHarness{})
	if p == nil || p.Name != DefaultProfileName {
		t.Errorf("unknown profile should fall back to %s, got %v", DefaultProfileName, p)
	}
}

func TestProfileCLILifecycleAndFlags(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{ConfigVersion: 1})

	if _, err := parseProfileFlags([]string{"positional"}); err == nil {
		t.Fatal("expected error on positional arg in parseProfileFlags")
	}
	if _, err := parseProfileFlags([]string{"--base"}); err == nil {
		t.Fatal("expected error on flag without '=' in parseProfileFlags")
	}
	if _, err := parseProfileFlags([]string{"--unknown=allow"}); err == nil {
		t.Fatal("expected error on unknown flag in parseProfileFlags")
	}
	flags, err := parseProfileFlags([]string{"--base=strict", "--low=allow"})
	if err != nil || flags["base"] != "strict" || flags["low"] != "allow" {
		t.Fatalf("unexpected parseProfileFlags result: %v, err=%v", flags, err)
	}

	out := captureStdout(func() {
		cmdProfile([]string{"create", "ci-mode", "--base=strict", "--low=allow"})
	})
	if !strings.Contains(out, `Created custom profile "ci-mode"`) {
		t.Fatalf("expected custom profile creation output, got:\n%s", out)
	}

	out = captureStdout(func() { cmdProfile([]string{"list"}) })
	if !strings.Contains(out, "ci-mode") || !strings.Contains(out, "[custom]") || !strings.Contains(out, "[built-in]") {
		t.Fatalf("expected profile list to include built-in and custom profiles, got:\n%s", out)
	}

	out = captureStdout(func() { cmdProfile([]string{"show", "ci-mode"}) })
	if !strings.Contains(out, `Profile "ci-mode" [custom]`) {
		t.Fatalf("expected custom profile show output, got:\n%s", out)
	}
	out = captureStdout(func() { cmdProfile([]string{"show", "fast"}) })
	if !strings.Contains(out, `Profile "fast" [built-in]`) {
		t.Fatalf("expected built-in profile show output, got:\n%s", out)
	}

	// Global, per-harness, and session profile pins + active status output.
	captureStdout(func() { cmdProfile([]string{"use", "fast"}) })
	captureStdout(func() { cmdProfile([]string{"use", "ci-mode", "--harness=claude"}) })
	captureStdout(func() { cmdProfile([]string{"use", "strict", "--session", "--session-id=sess-1234567890"}) })

	t.Setenv("YOLONOT_PROFILE", "balanced")
	t.Setenv("YOLONOT_CLAUDE_PROFILE", "strict")
	t.Setenv("CLAUDE_SESSION_ID", "sess-1234567890")
	out = captureStdout(func() { cmdProfile(nil) })
	for _, want := range []string{
		"Active profile: fast (global)",
		"claude     → ci-mode",
		"YOLONOT_PROFILE=balanced",
		"YOLONOT_CLAUDE_PROFILE=strict",
		"Session pin (sess-123, mid-session): strict",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in active profile output, got:\n%s", want, out)
		}
	}

	// Reset session, per-harness, and global overrides, then delete custom profile.
	out = captureStdout(func() { cmdProfile([]string{"reset", "--session", "--session-id=sess-1234567890"}) })
	if !strings.Contains(out, "Cleared session profile pin for sess-123.") {
		t.Fatalf("unexpected session reset output: %s", out)
	}
	out = captureStdout(func() { cmdProfile([]string{"reset", "--harness=claude"}) })
	if !strings.Contains(out, "Cleared profile override for claude.") {
		t.Fatalf("unexpected harness reset output: %s", out)
	}
	out = captureStdout(func() { cmdProfile([]string{"reset", "--harness=claude"}) })
	if !strings.Contains(out, "No override for claude.") {
		t.Fatalf("unexpected second harness reset output: %s", out)
	}
	out = captureStdout(func() { cmdProfile([]string{"reset"}) })
	if !strings.Contains(out, "Global profile reset") {
		t.Fatalf("unexpected global reset output: %s", out)
	}
	out = captureStdout(func() { cmdProfile([]string{"reset"}) })
	if !strings.Contains(out, "Global profile already at default") {
		t.Fatalf("unexpected second global reset output: %s", out)
	}

	// Per-harness tier dispatch via cmdProfile ("set", "<harness>", "reset <harness>").
	captureStdout(func() { cmdProfile([]string{"set", "claude", "low", "ask"}) })
	captureStdout(func() { cmdProfile([]string{"claude"}) })
	captureStdout(func() { cmdProfile([]string{"reset", "claude", "low"}) })

	out = captureStdout(func() { cmdProfile([]string{"delete", "ci-mode"}) })
	if !strings.Contains(out, `Deleted custom profile "ci-mode".`) {
		t.Fatalf("unexpected delete output: %s", out)
	}
}

func TestCLISubcommandsEndToEndInProcess(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	repo := filepath.Join(home, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)

	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok — safe explanation"}}]}`))
	}))
	defer llmSrv.Close()

	// 1. Models & Escalation CLI lifecycle.
	out := captureStdout(func() { cmdModels(nil) })
	if !strings.Contains(out, "Models: none") {
		t.Fatalf("expected empty models output, got: %s", out)
	}
	out = captureStdout(func() { cmdEscalation(nil) })
	if !strings.Contains(out, "Escalation: not configured") {
		t.Fatalf("expected unconfigured escalation output, got: %s", out)
	}
	captureStdout(func() { cmdEscalation([]string{"on"}) })
	captureStdout(func() { cmdEscalation([]string{"off"}) })

	cfg := Config{
		ConfigVersion: 1,
		Models: map[string]ModelConfig{
			"primary-chat": {URL: llmSrv.URL + "/v1/chat/completions", Model: "gpt-test", Protocol: "chat", EnvKey: "OPENAI_API_KEY"},
			"esc-chat":     {URL: llmSrv.URL + "/v1/chat/completions", Model: "gpt-esc", Protocol: "chat", EnvKey: "OPENAI_API_KEY"},
			"unused-model": {URL: llmSrv.URL + "/v1/chat/completions", Model: "gpt-unused", Protocol: "chat"},
		},
		Judges:     []JudgeSpec{{Use: "primary-chat"}},
		Escalation: &EscalationConfig{Model: "esc-chat"},
	}
	t.Setenv("OPENAI_API_KEY", "test-key")
	SaveConfig(cfg)

	out = captureStdout(func() { cmdModels([]string{"list"}) })
	if !strings.Contains(out, "primary-chat") || !strings.Contains(out, "judge #1") || !strings.Contains(out, "escalation") {
		t.Fatalf("unexpected models list output:\n%s", out)
	}
	out = captureStdout(func() { cmdModels([]string{"test", "primary-chat"}) })
	if !strings.Contains(out, "ok") {
		t.Fatalf("expected models test ok, got: %s", out)
	}
	out = captureStdout(func() { cmdModels([]string{"remove", "unused-model"}) })
	if !strings.Contains(out, "Removed unused-model.") {
		t.Fatalf("expected model removal output, got: %s", out)
	}

	LogDecision(DecisionEntry{
		Command:           "kubectl apply -f x.yaml",
		Decision:          "allow",
		Layer:             "llm",
		Escalated:         true,
		EscalationOutcome: "rescued",
		EscalationMs:      120,
	})
	out = captureStdout(func() { cmdEscalation(nil) })
	if !strings.Contains(out, "Escalation: ON") || !strings.Contains(out, "1 fired, 1 rescued") {
		t.Fatalf("unexpected escalation status output:\n%s", out)
	}
	out = captureStdout(func() { cmdEscalation([]string{"off"}) })
	if !strings.Contains(out, "Escalation: OFF") {
		t.Fatalf("unexpected escalation off output: %s", out)
	}
	out = captureStdout(func() { cmdEscalation([]string{"on"}) })
	if !strings.Contains(out, "Escalation: ON") {
		t.Fatalf("unexpected escalation on output: %s", out)
	}
	out = captureStdout(func() { cmdEscalation([]string{"test"}) })
	if !strings.Contains(out, "ok (") {
		t.Fatalf("unexpected escalation test output: %s", out)
	}

	// 2. Pause & Resume CLI (global and session-scoped).
	out = captureStdout(func() { cmdPause([]string{"--global"}) })
	if !strings.Contains(out, "total safety-layer bypass") {
		t.Fatalf("expected global pause confirmation prompt, got: %s", out)
	}
	out = captureStdout(func() { cmdPause([]string{"--global", "--confirm-bypass"}) })
	if !strings.Contains(out, "paused globally") {
		t.Fatalf("expected global pause activation, got: %s", out)
	}
	out = captureStdout(func() { cmdResume([]string{"--global"}) })
	if !strings.Contains(out, "resumed globally") {
		t.Fatalf("expected global resume, got: %s", out)
	}
	out = captureStdout(func() { cmdResume([]string{"--global"}) })
	if !strings.Contains(out, "not paused globally") {
		t.Fatalf("expected not paused globally message, got: %s", out)
	}

	captureStdout(func() { cmdPause([]string{"--session-id=sess-p1", "--confirm-bypass"}) })
	out = captureStdout(func() { cmdResume([]string{"--session-id=sess-p1"}) })
	if !strings.Contains(out, "resumed") {
		t.Fatalf("expected session resume, got: %s", out)
	}
	out = captureStdout(func() { cmdResume([]string{"--session-id=sess-p1"}) })
	if !strings.Contains(out, "not paused") {
		t.Fatalf("expected not paused message on second resume, got: %s", out)
	}

	// 3. Session decisions (approve/deny/reset) & cmdExplain.
	out = captureStdout(func() {
		cmdSessionDecision("approve", []string{"--session-id=sess-p1", "--cwd=" + repo, "npm run deploy"})
	})
	if !strings.Contains(out, "approve in") {
		t.Fatalf("unexpected cmdSessionDecision approve output: %s", out)
	}
	out = captureStdout(func() {
		cmdSessionDecision("deny", []string{"--session-id=sess-p1", "--cwd=" + repo, "rm -rf dist"})
	})
	if !strings.Contains(out, "deny in") {
		t.Fatalf("unexpected cmdSessionDecision deny output: %s", out)
	}
	captureStdout(func() {
		cmdSessionDecision("reset", []string{"--session-id=sess-p1", "--cwd=" + repo})
	})

	out = captureStdout(func() { cmdExplain([]string{"rm", "-rf", "dist"}) })
	if !strings.Contains(out, "safe explanation") {
		t.Fatalf("unexpected cmdExplain output: %s", out)
	}

	// 4. Skill refresh, update error explanation, and provider connection helpers.
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0755); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(func() { cmdInstallSkillOnly(Harnesses()) })
	if !strings.Contains(out, "Skill bundle refreshed.") {
		t.Fatalf("unexpected cmdInstallSkillOnly output: %s", out)
	}
	_ = (&ClaudeHarness{}).Install("/usr/local/bin/yolonot")
	refreshed := refreshSkillsForInstalled()
	if len(refreshed) == 0 {
		t.Fatalf("expected refreshSkillsForInstalled to refresh installed claude skill")
	}

	if got := explainFetchError(nil); got != "" {
		t.Fatalf("expected empty explainFetchError(nil), got %q", got)
	}
	if got := explainFetchError(context.DeadlineExceeded); !strings.Contains(got, "timeout") {
		t.Fatalf("expected timeout explanation, got %q", got)
	}
	if got := explainFetchError(&net.DNSError{Err: "no such host", Name: "api.github.com"}); !strings.Contains(got, "DNS") {
		t.Fatalf("expected DNS explanation, got %q", got)
	}
	if got := explainFetchError(errors.New("github api returned status 403")); !strings.Contains(got, "rate-limited") {
		t.Fatalf("expected 403 explanation, got %q", got)
	}
	if got := explainFetchError(errors.New("github api returned status 404")); !strings.Contains(got, "not found") {
		t.Fatalf("expected 404 explanation, got %q", got)
	}

	// 5. Top-level Run() CLI dispatch across non-interactive subcommands.
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	for _, argv := range [][]string{
		{"yolonot", "version"},
		{"yolonot", "help"},
		{"yolonot", "init"},
		{"yolonot", "status", "--all"},
		{"yolonot", "status", "--json"},
		{"yolonot", "log", "-n", "3"},
		{"yolonot", "stats"},
		{"yolonot", "profile", "list"},
		{"yolonot", "profile", "claude", "low", "allow"},
		{"yolonot", "profile", "claude", "reset"},
		{"yolonot", "models", "list"},
		{"yolonot", "judges", "list"},
		{"yolonot", "judges", "add", "fast_allow"},
		{"yolonot", "judges", "move", "1", "down"},
		{"yolonot", "judges", "move", "2", "up"},
		{"yolonot", "judges", "remove", "fast_allow"},
		{"yolonot", "judges", "escalation"},
		{"yolonot", "migrate", "--dry-run"},
		{"yolonot", "rules"},
		{"yolonot", "rules", "--trace"},
		{"yolonot", "rules", "discover"},
		{"yolonot", "suggest", "--list"},
		{"yolonot", "suggest", "--json"},
		{"yolonot", "doctor", "--harness=claude", "--json"},
		{"yolonot", "audit", "--all"},
		{"yolonot", "audit", "--json"},
		{"yolonot", "config", "quiet", "on"},
		{"yolonot", "config", "quiet", "off"},
		{"yolonot", "check", "--cwd", repo, "ls -la"},
		{"yolonot", "explain", "git status"},
		{"yolonot", "uninstall"},
	} {
		os.Args = argv
		_ = captureStdout(func() { Run() })
	}
}
