package yolonot

import (
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
		CustomProfiles: map[string]map[string]string{
			"my-prof": {
				RiskSafe:     ActionAllow,
				RiskLow:      ActionAllow,
				RiskModerate: ActionAllow,
				RiskHigh:     ActionAsk,
				RiskCritical: ActionDeny,
			},
		},
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
		"a..b",         // contains '..'
		"",             // empty
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
		CustomProfiles: map[string]map[string]string{
			"hand-edited": {
				RiskSafe:     ActionAllow,
				RiskLow:      "passthrough", // invalid in profile
				RiskModerate: "yolo",        // typo
				RiskHigh:     ActionDeny,
				RiskCritical: ActionDeny,
			},
		},
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
