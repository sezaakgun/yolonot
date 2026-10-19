package yolonot

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func decisionFakeServer(t *testing.T, risk string, conf, noul float64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model     string                      `json:"model"`
			State     string                      `json:"state"`
			Questions map[string]decisionQuestion `json:"questions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad request body: %v", err)
		}
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("missing bearer, got %q", r.Header.Get("Authorization"))
		}
		if req.Questions["risk"].Type != "choice" || len(req.Questions) != 1+len(decisionAskConditions) {
			t.Errorf("unexpected questions: %+v", req.Questions)
		}
		if req.State == "" {
			t.Errorf("empty state")
		}
		answers := map[string]decisionAnswer{
			"risk": {Type: "choice", Choice: risk, Confidence: conf, Probabilities: map[string]float64{risk: conf}},
		}
		for _, c := range decisionAskConditions {
			answers[c.id] = decisionAnswer{Type: "noul", Noul: 0.05}
		}
		answers["secrets_read"] = decisionAnswer{Type: "noul", Noul: noul}
		json.NewEncoder(w).Encode(map[string]interface{}{"model": "jev-1.13.0", "answers": answers})
	}))
}

func TestCallLLMRoutesToDecision(t *testing.T) {
	srv := decisionFakeServer(t, RiskModerate, 0.9, 0.8)
	defer srv.Close()
	// Loopback http is accepted by validateLLMURL; the /systemone marker
	// is what selects the decision path.
	cfg := LLMConfig{URL: srv.URL + "/v1/systemone", Model: "jev-latest", APIKey: "k"}

	raw, err := CallLLM(cfg, SystemPrompt, "Command: kubectl delete pod x --context prod", 300)
	if err != nil {
		t.Fatal(err)
	}
	d := ParseDecision(raw)
	if d == nil {
		t.Fatalf("unparseable: %s", raw)
	}
	if d.Decision != "ask" || d.Risk != RiskModerate || d.Short != "decision: secrets_read" {
		t.Errorf("got %+v", d)
	}
}

func TestCallDecisionHighTierAsksWithoutCondition(t *testing.T) {
	srv := decisionFakeServer(t, RiskHigh, 0.9, 0.1)
	defer srv.Close()
	cfg := LLMConfig{URL: srv.URL + "/systemone", Model: "jev-latest", APIKey: "k"}
	if d := ParseDecision(mustCallDecision(t, cfg)); d.Decision != "ask" {
		t.Errorf("got %+v", d)
	}
}

func TestCallDecisionAllowBelowHalf(t *testing.T) {
	srv := decisionFakeServer(t, RiskSafe, 0.97, 0.1)
	defer srv.Close()
	cfg := LLMConfig{URL: srv.URL + "/systemone", Model: "jev-latest", APIKey: "k"}
	d := ParseDecision(mustCallDecision(t, cfg))
	if d.Decision != "allow" || d.Risk != RiskSafe {
		t.Errorf("got %+v", d)
	}
}

func TestCallDecisionRejectsBadTier(t *testing.T) {
	srv := decisionFakeServer(t, "bogus", 0.5, 0.5)
	defer srv.Close()
	cfg := LLMConfig{URL: srv.URL + "/systemone", Model: "jev-latest", APIKey: "k"}
	if _, err := callDecision(cfg, "Command: ls"); err == nil {
		t.Fatal("expected error for invalid tier")
	}
}

func TestResolveLLMConfigJevAlias(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "abc")
	cfg := resolveLLMConfig("jev-latest")
	if cfg.URL != decisionDefaultURL || cfg.APIKey != "abc" || cfg.Model != "jev-latest" {
		t.Errorf("got %+v", cfg)
	}
}

func mustCallDecision(t *testing.T, cfg LLMConfig) string {
	t.Helper()
	raw, err := callDecision(cfg, "Command: ls")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRequireChatModel(t *testing.T) {
	if err := requireChatModel(LLMConfig{URL: decisionDefaultURL}); err == nil {
		t.Fatal("decision endpoint must be rejected for generation")
	}
	if err := requireChatModel(LLMConfig{URL: "https://api.openai.com/v1/chat/completions"}); err != nil {
		t.Fatal(err)
	}
}

func TestEscalationDoesNotInheritDecisionEndpoint(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	isolateEscalationEnv(t)
	SaveConfig(Config{
		Provider:   ProviderConfig{URL: decisionDefaultURL, Model: "jev-latest"},
		Escalation: &EscalationConfig{Provider: ProviderConfig{Model: "big-chat-model"}},
	})
	esc := GetEscalationConfig()
	if esc.URL != "" {
		t.Fatalf("escalation inherited decision endpoint: %+v", esc)
	}
}

func TestCallDecisionOpenAIShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model     string                   `json:"model"`
			Input     string                   `json:"input"`
			Questions []map[string]interface{} `json:"questions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Input == "" || len(req.Questions) != 1+len(decisionAskConditions) {
			t.Errorf("bad request: %v %+v", err, req)
		}
		if req.Questions[0]["type"] != "choice" || req.Questions[1]["type"] != "predicate" {
			t.Errorf("question types: %+v", req.Questions[:2])
		}
		answers := []map[string]interface{}{{"type": "choice", "name": "risk", "choice": RiskModerate, "confidence": 0.8,
			"probabilities": []map[string]interface{}{{"value": RiskModerate, "probability": 0.8}}}}
		for _, c := range decisionAskConditions {
			p := 0.02
			if c.id == "exfil" {
				p = 0.91
			}
			answers = append(answers, map[string]interface{}{"type": "predicate", "name": c.id, "probability": p})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"model": "gpt-6-luna", "answers": answers})
	}))
	defer srv.Close()
	cfg := LLMConfig{URL: srv.URL + "/v1/decisions", Model: "gpt-6-luna", APIKey: "k"}
	d := ParseDecision(mustCallDecision(t, cfg))
	if d.Decision != "ask" || d.Risk != RiskModerate || d.Short != "decision: exfil" {
		t.Errorf("got %+v", d)
	}
}

func TestCallDecisionOpenAIRefusalAsks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"answers": []map[string]interface{}{{"type": "refusal", "name": "risk"}}})
	}))
	defer srv.Close()
	d := ParseDecision(mustCallDecision(t, LLMConfig{URL: srv.URL + "/v1/decisions", Model: "gpt-6-luna"}))
	if d.Decision != "ask" || d.Short != "decision: refused" {
		t.Errorf("got %+v", d)
	}
}

func TestCallDecisionWorkersAIEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model string `json:"model"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Model != "clef-flash" {
			t.Errorf("body model = %q", req.Model)
		}
		answers := map[string]decisionAnswer{"risk": {Type: "choice", Choice: RiskLow, Confidence: 0.9, Probabilities: map[string]float64{RiskLow: 0.9}}}
		for _, c := range decisionAskConditions {
			answers[c.id] = decisionAnswer{Type: "noul", Noul: 0.02}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"result": map[string]interface{}{"model": "clef-flash", "answers": answers}, "success": true, "errors": []string{}})
	}))
	defer srv.Close()
	url := srv.URL + "/client/v4/accounts/abc/ai/run/@cf/cloudflare/clef-flash"
	if !isDecisionURL(url) {
		t.Fatal("Workers AI Clef URL must be typed")
	}
	d := ParseDecision(mustCallDecision(t, LLMConfig{URL: url, Model: "clef-flash", APIKey: "k"}))
	if d.Decision != "allow" || d.Risk != RiskLow {
		t.Errorf("got %+v", d)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"result": nil, "success": false, "errors": []map[string]interface{}{{"code": 10000, "message": "Authentication error"}}})
	}))
	defer bad.Close()
	if _, err := callDecision(LLMConfig{URL: bad.URL + "/ai/run/@cf/cloudflare/clef", Model: "clef"}, "Command: ls"); err == nil {
		t.Fatal("Workers AI error envelope must surface as an error")
	}
}

func TestDecisionHints(t *testing.T) {
	if got := DecisionHints(PromptConfig{}, WalkupHints{}); got != "" {
		t.Fatalf("no hints should render nothing, got %q", got)
	}
	got := DecisionHints(PromptConfig{AskHints: []string{"$defaults", "", "touching billing/ asks"}}, WalkupHints{Context: []string{"monorepo"}})
	for _, want := range []string{"\n\nProject context:\n- monorepo\n", "\n\nAsk when:\n- Granting", "- Force-pushing", "- touching billing/ asks\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "Allow when") {
		t.Errorf("empty allow list rendered: %q", got)
	}
	if strings.Contains(got, "- \n") {
		t.Errorf("blank entry rendered: %q", got)
	}
}

func TestCallDecisionMissingKeyIsNotParseError(t *testing.T) {
	_, err := callDecision(LLMConfig{URL: "https://decisions.example.com/v1/systemone", Model: "jev-latest", APIKeyEnv: "TYPESAFE_API_KEY"}, "ls")
	if err == nil || errors.Is(err, errDecisionResponse) {
		t.Fatalf("missing key must surface as unavailable, not a parse error: %v", err)
	}
}

func TestSystemPromptMatchesDecisionCriteria(t *testing.T) {
	for _, tier := range allRiskTiers {
		if !strings.Contains(SystemPrompt, decisionTierCriteria[tier]) {
			t.Errorf("SystemPrompt missing decisionTierCriteria[%q]", tier)
		}
	}
	for _, c := range decisionAskConditions {
		if c.id == "project_ask" {
			continue
		}
		for _, want := range []string{c.id, c.question, c.yes, c.no} {
			if !strings.Contains(SystemPrompt, want) {
				t.Errorf("SystemPrompt missing %s fragment %q", c.id, want)
			}
		}
	}
}

