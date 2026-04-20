package yolonot

import (
	"os"
	"testing"
)

func TestApplyRiskMap_EscalateOnly(t *testing.T) {
	// Synthetic harness with a permissive map: safe→allow across the board.
	// Classifier says "ask" — risk map must NOT relax it to "allow".
	h := &fakeHarness{riskMap: map[string]string{
		RiskSafe: ActionAllow, RiskLow: ActionAllow, RiskModerate: ActionAllow,
		RiskHigh: ActionAllow, RiskCritical: ActionAllow,
	}}
	RegisterHarness(h)
	defer unregisterHarness(h)

	final, pass := applyRiskMap(h, "ask", RiskSafe)
	if pass {
		t.Fatal("ask + safe+allow should not passthrough")
	}
	if final != "ask" {
		t.Errorf("escalate-only invariant broken: allow action downgraded ask to %q", final)
	}
}

func TestApplyRiskMap_Passthrough(t *testing.T) {
	h := &fakeHarness{riskMap: map[string]string{RiskModerate: ActionPassthrough}}
	final, pass := applyRiskMap(h, "allow", RiskModerate)
	if !pass {
		t.Fatal("passthrough action should set pass=true")
	}
	if final != "" {
		t.Errorf("passthrough final = %q, want empty", final)
	}
}

func TestApplyRiskMap_DenyEscalatesAllow(t *testing.T) {
	h := &fakeHarness{riskMap: map[string]string{RiskCritical: ActionDeny}}
	final, _ := applyRiskMap(h, "allow", RiskCritical)
	if final != "deny" {
		t.Errorf("deny action should escalate allow → deny, got %q", final)
	}
}

func TestClaudeHarnessDefaultRiskMap(t *testing.T) {
	m := (&ClaudeHarness{}).RiskMap()
	cases := map[string]string{
		RiskSafe: ActionAllow, RiskLow: ActionAllow, RiskModerate: ActionAsk,
		RiskHigh: ActionAsk, RiskCritical: ActionAsk,
	}
	for tier, want := range cases {
		if m[tier] != want {
			t.Errorf("claude[%s]=%q want %q", tier, m[tier], want)
		}
	}
}

func TestGeminiHarnessDefaultRiskMap(t *testing.T) {
	m := (&GeminiHarness{}).RiskMap()
	cases := map[string]string{
		RiskSafe: ActionAllow, RiskLow: ActionAllow, RiskModerate: ActionAsk,
		RiskHigh: ActionAsk, RiskCritical: ActionAsk,
	}
	for tier, want := range cases {
		if m[tier] != want {
			t.Errorf("gemini[%s]=%q want %q", tier, m[tier], want)
		}
	}
}

// Ask-capable harnesses (Claude, Gemini) must never have ActionDeny in
// their default RiskMap — deny stays rule-origin only. Regression guard
// for the "LLM never denies on ask-capable harnesses" invariant.
func TestAskCapableHarnessesNeverDefaultDeny(t *testing.T) {
	for _, h := range []Harness{&ClaudeHarness{}, &GeminiHarness{}} {
		for tier, action := range h.RiskMap() {
			if action == ActionDeny {
				t.Errorf("%s default RiskMap[%s]=deny — ask-capable harnesses must not deny from LLM", h.Name(), tier)
			}
		}
	}
}

func TestCodexHarnessDefaultRiskMap(t *testing.T) {
	m := (&CodexHarness{}).RiskMap()
	cases := map[string]string{
		RiskSafe: ActionAllow, RiskLow: ActionAllow, RiskModerate: ActionPassthrough,
		RiskHigh: ActionDeny, RiskCritical: ActionDeny,
	}
	for tier, want := range cases {
		if m[tier] != want {
			t.Errorf("codex[%s]=%q want %q", tier, m[tier], want)
		}
	}
}

func TestResolveRiskMap_EnvOverridesConfig(t *testing.T) {
	dir, cleanup := withFakeHome(t)
	defer cleanup()
	_ = dir

	SaveConfig(Config{RiskMaps: map[string]map[string]string{
		"claude": {RiskModerate: ActionDeny},
	}})

	t.Setenv("YOLONOT_CLAUDE_RISK_MODERATE", "allow")
	m := ResolveRiskMap(&ClaudeHarness{})
	if m[RiskModerate] != ActionAllow {
		t.Errorf("env should win: got %q, want %q", m[RiskModerate], ActionAllow)
	}
}

func TestActiveClassifier_HonoursEnvOverride(t *testing.T) {
	// LLM classifier is registered via llm.go's init(). An unknown env
	// value must fall back rather than returning nil.
	orig := os.Getenv("YOLONOT_CLASSIFIER")
	defer os.Setenv("YOLONOT_CLASSIFIER", orig)

	os.Setenv("YOLONOT_CLASSIFIER", "does-not-exist")
	c := ActiveClassifier()
	if c == nil {
		t.Fatal("unknown classifier name should fall back to default, got nil")
	}
	if c.Name() != "llm" {
		t.Errorf("fallback classifier = %q, want llm", c.Name())
	}
}

func TestClassifierRegistry_RegistersLLM(t *testing.T) {
	if c := GetClassifier("llm"); c == nil {
		t.Fatal("LLMClassifier must be registered at init")
	}
}

func TestParseDecision_ConfidenceFallback(t *testing.T) {
	// Legacy LLM output with only confidence — ParseDecision should map
	// it to a risk tier so downstream code keeps working through the
	// migration window.
	d := ParseDecision(`{"decision":"ask","confidence":0.95,"reasoning":"DANGEROUS"}`)
	if d == nil {
		t.Fatal("parse failed")
	}
	if d.Risk != RiskCritical {
		t.Errorf("ask + conf 0.95 should map to critical, got %q", d.Risk)
	}
	d = ParseDecision(`{"decision":"allow","confidence":0.95,"reasoning":"read-only"}`)
	if d == nil || d.Risk != RiskSafe {
		t.Errorf("allow + conf 0.95 should map to safe, got %v", d)
	}
}

// --- test plumbing ---

type fakeHarness struct {
	riskMap map[string]string
}

func (f *fakeHarness) Name() string                              { return "fake-harness-for-tests" }
func (f *fakeHarness) SettingsPath() string                      { return "" }
func (f *fakeHarness) SessionIDFromEnv() string                  { return "" }
func (f *fakeHarness) ParseHookInput([]byte) (HookPayload, error) { return HookPayload{}, nil }
func (f *fakeHarness) FormatHookResponse(HookResponse) string    { return "" }
func (f *fakeHarness) IsInstalled() bool                         { return false }
func (f *fakeHarness) Install(string) error                      { return nil }
func (f *fakeHarness) Uninstall() error                          { return nil }
func (f *fakeHarness) InstallSkill() (string, error)             { return "", nil }
func (f *fakeHarness) UninstallSkill() error                     { return nil }
func (f *fakeHarness) IsDetected() bool                          { return false }
func (f *fakeHarness) RiskMap() map[string]string                { return f.riskMap }
func (f *fakeHarness) PostInstallNotes() []string                 { return nil }

func unregisterHarness(h Harness) {
	harnessMu.Lock()
	defer harnessMu.Unlock()
	out := make([]Harness, 0, len(registeredHarnesses))
	for _, r := range registeredHarnesses {
		if r != h {
			out = append(out, r)
		}
	}
	registeredHarnesses = out
}
