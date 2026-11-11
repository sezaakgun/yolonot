package yolonot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

// Decision-model backend (System One API: TypeSafe Jev and compatible
// endpoints). Unlike chat models it does not generate text: it answers
// typed questions with calibrated probabilities. The "decision" judge
// calls it directly; CallLLM also routes here when a provider URL points
// at a System One endpoint (eval --model jev-latest). It returns the same
// JSON verdict shape the chat prompt asks for, so ParseDecision, the hook,
// check, eval and escalation need no changes.
//
// Shared risk-tier criteria, ask-condition principles, and hint rendering
// (decisionTierCriteria, decisionAskConditions, decisionPreamble, DecisionHints)
// live in llm.go alongside the chat classifier prompt and $defaults lists.

const decisionDefaultURL = "https://api.typesafe.ai/v1/systemone"

var errDecisionResponse = errors.New("invalid typed response")

func isDecisionURL(u string) bool {
	return strings.Contains(u, "typesafe.ai") || strings.Contains(u, "/systemone") || isOpenAIDecisionsURL(u) || isWorkersAIClefURL(u)
}

// isWorkersAIClefURL: Cloudflare Workers AI serves Clef at
// /accounts/<id>/ai/run/@cf/cloudflare/clef[-flash] with the System One
// body inside the Workers AI {result, success, errors} envelope.
func isWorkersAIClefURL(u string) bool { return strings.Contains(u, "/ai/run/@cf/cloudflare/clef") }

const workersAIClefURL = "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/@cf/cloudflare/"

// isOpenAIDecisionsURL: OpenAI's Decisions API speaks a different schema
// (questions array, predicate instead of noul, "input" instead of "state").
func isOpenAIDecisionsURL(u string) bool {
	return strings.HasSuffix(strings.TrimRight(u, "/"), "/decisions")
}

const openAIDecisionsURL = "https://api.openai.com/v1/decisions"
const openRouterSystemOneURL = "https://openrouter.ai/api/v1/systemone"

// errDecisionNoGeneration is returned by text-generating features (similarity
// compare, smart-suggest, classifier review) when the primary is a decision model.
var errDecisionNoGeneration = fmt.Errorf("decision models return typed judgments and cannot generate text; configure a chat model for this feature")

func requireChatModel(cfg LLMConfig) error {
	if isDecisionConfig(cfg) {
		return errDecisionNoGeneration
	}
	return nil
}

type decisionQuestion struct {
	Type         string      `json:"type"`
	Instructions interface{} `json:"instructions"`
	Criteria     interface{} `json:"criteria,omitempty"`
}

type decisionAnswer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Confidence    float64            `json:"confidence,omitempty"`
	Noul          float64            `json:"noul,omitempty"`
	hasNoul       bool
}

func decisionProbability(raw json.RawMessage, name string, required bool) (*float64, error) {
	if len(raw) == 0 {
		if required {
			return nil, fmt.Errorf("decision: missing %s", name)
		}
		return nil, nil
	}
	var value *float64
	if err := json.Unmarshal(raw, &value); err != nil || value == nil || math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 1 {
		return nil, fmt.Errorf("decision: %s must be a number in [0,1]", name)
	}
	return value, nil
}

// Numeric zero is a valid probability, while a missing/null probability is
// not. Preserve that distinction instead of accepting Go's zero value.
func (a *decisionAnswer) UnmarshalJSON(data []byte) error {
	fields, err := decisionAnswerFields(data)
	if err != nil {
		return err
	}
	var decoded decisionAnswer
	if err := json.Unmarshal(fields["type"], &decoded.Type); err != nil {
		return fmt.Errorf("decision: missing or invalid answer type")
	}
	if raw, present := fields["choice"]; present {
		if err := json.Unmarshal(raw, &decoded.Choice); err != nil {
			return fmt.Errorf("decision: invalid choice")
		}
	}
	noul, err := decisionProbability(fields["noul"], "noul", false)
	if err != nil {
		return err
	}
	if noul != nil {
		decoded.Noul, decoded.hasNoul = *noul, true
	}
	confidence, err := decisionProbability(fields["confidence"], "confidence", false)
	if err != nil {
		return err
	}
	if confidence != nil {
		decoded.Confidence = *confidence
	}
	if probabilities, ok := fields["probabilities"]; ok {
		var values map[string]json.RawMessage
		if err := json.Unmarshal(probabilities, &values); err != nil || values == nil {
			return fmt.Errorf("decision: probabilities must be an object")
		}
		decoded.Probabilities = make(map[string]float64, len(values))
		for name, raw := range values {
			value, err := decisionProbability(raw, "probabilities."+name, true)
			if err != nil {
				return err
			}
			decoded.Probabilities[name] = *value
		}
	}
	*a = decoded
	return nil
}

// Decode answer fields once, rejecting ambiguous duplicates/case aliases.
// encoding/json's case-insensitive struct matching must not give a value
// different from the exact field whose presence and range we validated.
func decisionAnswerFields(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, fmt.Errorf("decision: answer must be an object")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("decision: invalid answer field")
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, fmt.Errorf("decision: duplicate answer field %q", name)
		}
		switch canonical := strings.ToLower(name); canonical {
		case "type", "name", "choice", "noul", "probability", "confidence", "probabilities":
			if name != canonical {
				return nil, fmt.Errorf("decision: answer field %q must be lowercase", name)
			}
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		fields[name] = raw
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	return fields, nil
}

func decisionQuestions() map[string]decisionQuestion {
	qs := map[string]decisionQuestion{
		"risk": {
			Type:         "choice",
			Instructions: decisionPreamble + "Classify the risk tier of running it, judged by reversibility and blast radius, not by how unusual it looks.",
			Criteria:     decisionTierCriteria,
		},
	}
	for _, c := range decisionAskConditions {
		qs[c.id] = decisionQuestion{
			Type:         "noul",
			Instructions: decisionPreamble + c.question,
			Criteria:     map[string]string{"true": c.yes, "false": c.no},
		}
	}
	return qs
}

// openAIDecisionsBody translates the same questions into OpenAI's shape:
// an array with names, "predicate" for yes/no (criteria folded into the
// instructions since predicates take none), choices as value/description.
func openAIDecisionsBody(model, userPrompt string) map[string]interface{} {
	choices := make([]map[string]string, 0, len(allRiskTiers))
	for _, t := range allRiskTiers {
		choices = append(choices, map[string]string{"value": t, "description": decisionTierCriteria[t]})
	}
	qs := []map[string]interface{}{{
		"type": "choice", "name": "risk",
		"instructions": decisionPreamble + "Classify the risk tier of running it, judged by reversibility and blast radius, not by how unusual it looks.",
		"choices":      choices,
	}}
	for _, c := range decisionAskConditions {
		qs = append(qs, map[string]interface{}{
			"type": "predicate", "name": c.id,
			"instructions": decisionPreamble + c.question + " Yes if: " + c.yes + " No if: " + c.no,
		})
	}
	return map[string]interface{}{"model": model, "input": userPrompt, "questions": qs}
}

// decisionPost sends the request and returns the answers keyed by question
// name, normalised to the System One answer shape.
func decisionPost(cfg LLMConfig, userPrompt string) (map[string]decisionAnswer, error) {
	if err := cfg.credentialError(); err != nil {
		return nil, err
	}
	openai := isOpenAIDecisionsConfig(cfg)
	var payload interface{} = map[string]interface{}{"model": cfg.Model, "state": userPrompt, "questions": decisionQuestions()}
	if openai {
		payload = openAIDecisionsBody(cfg.Model, userPrompt)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(cfg.requestContext(), "POST", cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	client := &http.Client{Timeout: time.Duration(resolveTimeoutSeconds(cfg, 10)) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, cfg.authenticationError(resp.StatusCode)
		}
		return nil, fmt.Errorf("decision error (HTTP %d)", resp.StatusCode)
	}
	var out struct {
		Answers json.RawMessage `json:"answers"`
		Error   interface{}     `json:"error"`
		Detail  interface{}     `json:"detail"` // TypeSafe error envelope
		Result  json.RawMessage `json:"result"` // Workers AI envelope
		Success *bool           `json:"success"`
		Errors  []interface{}   `json:"errors"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}
	if out.Error != nil || out.Detail != nil || (out.Success != nil && !*out.Success) || len(out.Errors) > 0 {
		return nil, fmt.Errorf("decision error (HTTP %d): %s", resp.StatusCode, truncateStr(strings.TrimSpace(string(raw)), 300))
	}
	if len(out.Answers) == 0 && len(out.Result) > 0 {
		var inner struct {
			Answers json.RawMessage `json:"answers"`
		}
		if err := json.Unmarshal(out.Result, &inner); err != nil {
			return nil, fmt.Errorf("invalid JSON response: %w", err)
		}
		out.Answers = inner.Answers
	}
	answers := map[string]decisionAnswer{}
	if !openai {
		fields, err := decisionAnswerFields(out.Answers)
		if err != nil {
			return nil, err
		}
		for name, raw := range fields {
			var answer decisionAnswer
			if err := json.Unmarshal(raw, &answer); err != nil {
				return nil, fmt.Errorf("invalid %s answer: %w", name, err)
			}
			answers[name] = answer
		}
		return answers, nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(out.Answers, &list); err != nil {
		return nil, fmt.Errorf("invalid answers: %w", err)
	}
	for _, raw := range list {
		fields, err := decisionAnswerFields(raw)
		if err != nil {
			return nil, err
		}
		var a struct {
			Name          string          `json:"name"`
			Type          string          `json:"type"`
			Probability   json.RawMessage `json:"probability"`
			Choice        string          `json:"choice"`
			Confidence    json.RawMessage `json:"confidence"`
			Probabilities []struct {
				Value       string          `json:"value"`
				Probability json.RawMessage `json:"probability"`
			} `json:"probabilities"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Errorf("invalid answer: %w", err)
		}
		if probabilities, present := fields["probabilities"]; present && string(bytes.TrimSpace(probabilities)) == "null" {
			return nil, fmt.Errorf("decision: probabilities must be an array")
		}
		if a.Name == "" {
			return nil, fmt.Errorf("decision: missing answer name")
		}
		if _, duplicate := answers[a.Name]; duplicate {
			return nil, fmt.Errorf("decision: duplicate %s answer", a.Name)
		}
		if a.Type == "refusal" {
			// A refusal to judge is itself a signal (seen on obfuscated
			// payloads): surface it as an ask rather than an outage.
			return map[string]decisionAnswer{"refusal": {Type: "refusal", Choice: a.Name}}, nil
		}
		probability, err := decisionProbability(a.Probability, a.Name+".probability", a.Type == "predicate")
		if err != nil {
			return nil, err
		}
		confidence, err := decisionProbability(a.Confidence, a.Name+".confidence", false)
		if err != nil {
			return nil, err
		}
		da := decisionAnswer{Type: a.Type, Choice: a.Choice}
		if probability != nil {
			da.Noul, da.hasNoul = *probability, true
		}
		if confidence != nil {
			da.Confidence = *confidence
		}
		if len(a.Probabilities) > 0 {
			da.Probabilities = map[string]float64{}
			for _, p := range a.Probabilities {
				if _, duplicate := da.Probabilities[p.Value]; duplicate {
					return nil, fmt.Errorf("decision: duplicate %s probability", p.Value)
				}
				value, err := decisionProbability(p.Probability, a.Name+".probabilities."+p.Value, true)
				if err != nil {
					return nil, err
				}
				da.Probabilities[p.Value] = *value
			}
		}
		answers[a.Name] = da
	}
	return answers, nil
}

// callDecision sends one request with every question and folds the answers into
// the chat-classifier verdict JSON. Decision = ask when any ask-condition
// Noul is >= 0.5 or the tier is high/critical.
func callDecision(cfg LLMConfig, userPrompt string) (string, error) {
	if err := validateLLMURL(cfg.URL); err != nil {
		return "", err
	}
	answers, err := decisionPost(cfg, userPrompt)
	if err != nil {
		var transport interface{ Timeout() bool }
		var cred credentialFailure
		if !errors.As(err, &transport) && !errors.As(err, &cred) && !strings.HasPrefix(err.Error(), "decision error (HTTP") {
			return "", fmt.Errorf("%w: %v", errDecisionResponse, err)
		}
		return "", err
	}
	if r, refused := answers["refusal"]; refused {
		b, _ := json.Marshal(Decision{Decision: "ask", Risk: RiskHigh, Short: "decision: refused",
			Reasoning: "decision: the model refused to judge question " + r.Choice})
		return string(b), nil
	}
	risk, ok := answers["risk"]
	if !ok || risk.Type != "choice" || !isValidRisk(risk.Choice) {
		return "", fmt.Errorf("%w: missing or invalid risk answer", errDecisionResponse)
	}
	var fired []string
	for _, c := range decisionAskConditions {
		a, ok := answers[c.id]
		wantType := "noul"
		if isOpenAIDecisionsConfig(cfg) {
			wantType = "predicate"
		}
		if !ok || a.Type != wantType || !a.hasNoul {
			return "", fmt.Errorf("%w: missing or invalid %s answer", errDecisionResponse, c.id)
		}
		if a.Noul >= 0.5 {
			fired = append(fired, fmt.Sprintf("%s=%.2f", c.id, a.Noul))
		}
	}

	decision := "allow"
	short := "decision: " + risk.Choice
	if len(fired) > 0 || risk.Choice == RiskHigh || risk.Choice == RiskCritical {
		decision = "ask"
		if len(fired) > 0 {
			short = "decision: " + strings.SplitN(fired[0], "=", 2)[0]
		}
	}
	d := Decision{
		Decision:  decision,
		Risk:      risk.Choice,
		Short:     short,
		Reasoning: fmt.Sprintf("decision: risk=%s conf=%.2f [%s] fired=[%s]", risk.Choice, risk.Confidence, decisionProbs(risk.Probabilities), strings.Join(fired, " ")),
	}
	b, _ := json.Marshal(d)
	return string(b), nil
}

func decisionProbs(p map[string]float64) string {
	parts := make([]string, 0, len(p))
	for _, t := range allRiskTiers {
		if v, ok := p[t]; ok {
			parts = append(parts, fmt.Sprintf("%s=%.2f", t, v))
		}
	}
	return strings.Join(parts, " ")
}
