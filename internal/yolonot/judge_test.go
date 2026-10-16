package yolonot

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeLegacyChain(t *testing.T) {
	cfg := Config{
		PreCheck: PreCheckList{FastAllowSentinel, "/opt/dippy"},
		Provider: ProviderConfig{URL: "https://x/v1/chat/completions", Model: "google/gemini-2.5-flash-lite", EnvKey: "K"},
	}
	cfg.normalize()
	if !cfg.Legacy || cfg.PreCheck != nil || cfg.Provider.URL != "" {
		t.Fatalf("legacy fields must be cleared: %+v", cfg)
	}
	if got := judgeNames(cfg.Judges); got != "fast_allow → exec:/opt/dippy → gemini-2.5-flash-lite" {
		t.Fatalf("got %q", got)
	}
	if cfg.kindOf(cfg.Judges[2]) != judgeChat || cfg.ChatModelName() != "gemini-2.5-flash-lite" {
		t.Fatalf("chat model not resolved: %+v", cfg.Models)
	}
	before, _ := json.Marshal(cfg)
	cfg.normalize()
	after, _ := json.Marshal(cfg)
	if string(before) != string(after) {
		t.Fatal("normalize must be idempotent")
	}
}

func TestNormalizeTypedBeforeChat(t *testing.T) {
	cfg := Config{
		PreCheck: PreCheckList{FastAllowSentinel},
		Provider: ProviderConfig{URL: "https://x/v1/chat/completions", Model: "chat-model"},
		Decision: ProviderConfig{URL: decisionDefaultURL, Model: "jev-latest"},
	}
	cfg.normalize()
	if got := judgeNames(cfg.Judges); got != "fast_allow → jev-latest → chat-model" {
		t.Fatalf("got %q", got)
	}
	if cfg.kindOf(cfg.Judges[1]) != judgeTyped {
		t.Fatal("jev-latest must be typed")
	}
}

func TestNormalizeMapsLegacyJudgeKeywords(t *testing.T) {
	cfg := Config{
		Provider: ProviderConfig{URL: "https://x/v1/chat/completions", Model: "chat-model"},
		Decision: ProviderConfig{URL: decisionDefaultURL, Model: "jev-latest"},
		Judges:   JudgeList{{Use: "fast_allow"}, {Use: "jev", May: []string{"allow"}}, {Use: "llm"}, {Use: "escalation"}},
	}
	cfg.normalize()
	if got := judgeNames(cfg.Judges); got != "fast_allow → jev-latest → chat-model" {
		t.Fatalf("got %q", got)
	}
	if len(cfg.Judges[1].May) != 1 {
		t.Fatal("may must survive the keyword mapping")
	}
}

func TestJudgeListJSONStringAndObjectForms(t *testing.T) {
	var l JudgeList
	if err := json.Unmarshal([]byte(`["fast_allow", {"use":"jev","may":["allow"]}, "exec:/x"]`), &l); err != nil {
		t.Fatal(err)
	}
	if judgeNames(l) != "fast_allow → jev → exec:/x" || len(l[1].May) != 1 {
		t.Fatalf("got %+v", l)
	}
	out, _ := json.Marshal(l)
	if string(out) != `["fast_allow",{"use":"jev","may":["allow"]},"exec:/x"]` {
		t.Fatalf("marshal: %s", out)
	}
}

func TestJudgeSpecMayDefaultsAndOverride(t *testing.T) {
	if !(JudgeSpec{Use: "fast_allow"}).may("allow") || (JudgeSpec{Use: "fast_allow"}).may("ask") {
		t.Fatal("fast_allow default must be allow-only")
	}
	cfg := Config{Models: map[string]ModelConfig{"m": {URL: "https://x/v1/chat/completions", Model: "m"}}, Judges: JudgeList{{Use: "m"}, {Use: "m", May: []string{"allow"}}}}
	specs := cfg.JudgeSpecs()
	if !specs[0].may("ask") {
		t.Fatal("chat default must include ask")
	}
	if specs[1].may("ask") {
		t.Fatal("explicit may must restrict")
	}
	if (JudgeSpec{Use: "nope"}).may("allow") {
		t.Fatal("unknown judge may decide nothing")
	}
}

// decisionOK serves a typed answer set that folds to (decision, risk).
func decisionOK(t *testing.T, risk string, ask bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answers := map[string]decisionAnswer{"risk": {Type: "choice", Choice: risk, Confidence: 0.9, Probabilities: map[string]float64{risk: 0.9}}}
		for _, c := range decisionAskConditions {
			answers[c.id] = decisionAnswer{Type: "noul", Noul: 0.05}
		}
		if ask {
			answers["prod_mutation"] = decisionAnswer{Type: "noul", Noul: 0.9}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"model": "jev-1.13.0", "answers": answers})
	}))
}

func decisionChainConfig(t *testing.T, decURL, llmURL string, judges []JudgeSpec) {
	t.Helper()
	t.Setenv("TYPESAFE_API_KEY", "k")
	SaveConfig(Config{
		Provider: ProviderConfig{URL: llmURL, Model: "chat", Timeout: 5},
		Decision: ProviderConfig{URL: decURL + "/v1/systemone", Model: "jev-latest", EnvKey: "TYPESAFE_API_KEY", Timeout: 5},
		Judges:   judges,
	})
}

func TestIntegration_Judges_DecisionFirstDecides(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	dec := decisionOK(t, RiskSafe, false)
	defer dec.Close()
	var llmHits int32
	llm := mockLLMRisk("ask", "moderate", "should not be reached", &llmHits)
	defer llm.Close()
	decisionChainConfig(t, dec.URL, llm.URL, []JudgeSpec{{Use: "decision"}, {Use: "llm"}})

	out := runHookWithStruct(t, makePrePayload("judges-1", "some-novel-tool --flag", t.TempDir()))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("expected allow from decision, got %q (%s)", resp.HookSpecificOutput.PermissionDecision, out)
	}
	if llmHits != 0 {
		t.Fatalf("llm must not run once decision decided, hits=%d", llmHits)
	}
}

func TestIntegration_Judges_DecisionFailsThenLLM(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	dec := mockLLMFail(nil)
	defer dec.Close()
	llm := mockLLMRisk("ask", "moderate", "chat fallback", nil)
	defer llm.Close()
	decisionChainConfig(t, dec.URL, llm.URL, []JudgeSpec{{Use: "decision"}, {Use: "llm"}})

	out := runHookWithStruct(t, makePrePayload("judges-2", "some-novel-tool --flag", t.TempDir()))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "ask" {
		t.Fatalf("expected ask from llm fallback, got %q (%s)", resp.HookSpecificOutput.PermissionDecision, out)
	}
	if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "chat fallback") {
		t.Fatalf("reason should come from the llm judge: %q", resp.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestIntegration_Judges_MayFilterFallsThrough(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	dec := decisionOK(t, RiskHigh, true) // folds to ask
	defer dec.Close()
	llm := mockLLMRisk("allow", "low", "chat said fine", nil)
	defer llm.Close()
	// decision may only allow: its ask is dropped and the llm decides.
	decisionChainConfig(t, dec.URL, llm.URL, []JudgeSpec{{Use: "decision", May: []string{"allow"}}, {Use: "llm"}})

	out := runHookWithStruct(t, makePrePayload("judges-3", "some-novel-tool --flag", t.TempDir()))
	resp := parseResponse(t, out)
	// Allow banners carry the layer and command, not the reason.
	if resp.HookSpecificOutput.PermissionDecision != "allow" || !strings.Contains(resp.SystemMessage, "chat ->") {
		t.Fatalf("expected llm allow after decision filtered, got %+v / %q", resp.HookSpecificOutput, resp.SystemMessage)
	}
}

func TestIntegration_Judges_NoneDecidesPassesThrough(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	llm := mockLLMRisk("ask", "moderate", "unsure", nil)
	defer llm.Close()
	SaveConfig(Config{Provider: ProviderConfig{URL: llm.URL, Model: "chat", Timeout: 5}, Judges: []JudgeSpec{{Use: "llm", May: []string{"allow"}}}})

	out := runHookWithStruct(t, makePrePayload("judges-4", "some-novel-tool --flag", t.TempDir()))
	if strings.TrimSpace(out) != "" {
		t.Fatalf("no permitted verdict must be transparent (empty response), got %q", out)
	}
}

func TestCmdJudgesListing(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}, Provider: ProviderConfig{URL: "https://x/v1/chat/completions", Model: "chat-model"}, Judges: JudgeList{{Use: "typo"}}})
	out := captureStdout(func() { cmdJudges(nil) })
	for _, want := range []string{"typo", "unknown", "escalation and the risk map run once after it"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestIntegration_Judges_DenyOutsideMayBecomesAsk(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	llm := mockLLMRisk("deny", "critical", "custom prompt said deny", nil)
	defer llm.Close()
	SaveConfig(Config{Provider: ProviderConfig{URL: llm.URL, Model: "chat", Timeout: 5}, Judges: []JudgeSpec{{Use: "llm"}}})

	out := runHookWithStruct(t, makePrePayload("judges-5", "some-novel-tool --flag", t.TempDir()))
	if got := parseResponse(t, out).HookSpecificOutput.PermissionDecision; got != "ask" {
		t.Fatalf("deny from a judge that may ask must not pass through, got %q (%s)", got, out)
	}
}
