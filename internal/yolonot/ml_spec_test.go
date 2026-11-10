package yolonot

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// mlSpecPath is the question/state contract the ml/ fine-tuning pipeline
// trains against. A local System One model only works if it is trained on
// the exact questions and state layout the typed judge sends at run time.
var mlSpecPath = filepath.Join("..", "..", "ml", "spec", "yolonot_systemone.json")

const mlSpecExampleCommand = "git status --short"

// cwd must be outside any repository so the example has no auto-detected
// project line (which would make the fixture depend on where tests run).
func buildMLSpec(cwd string) ([]byte, error) {
	defaults := PromptConfig{
		Context:    []string{DefaultsSentinel},
		AllowHints: []string{DefaultsSentinel},
		AskHints:   []string{DefaultsSentinel},
	}
	spec := map[string]interface{}{
		"_comment": "Generated from internal/yolonot/decision.go by TestMLSpecInSync. " +
			"Regenerate with: YOLONOT_UPDATE_ML_SPEC=1 go test ./internal/yolonot -run TestMLSpecInSync",
		"questions":      decisionQuestions(),
		"risk_tiers":     allRiskTiers,
		"ask_tiers":      []string{RiskHigh, RiskCritical},
		"ask_threshold":  0.5,
		"command_prefix": "Command: ",
		"analyze_suffix": "\n\nAnalyze: is this safe to execute?",
		"default_hints": map[string][]string{
			"context":    builtinClassifierContext,
			"allow_when": builtinClassifierAllowHints,
			"ask_when":   builtinClassifierAskHints,
		},
		"default_hints_state": DecisionHints(defaults, WalkupHints{}),
		// A rendered state for a plain command with default hints, exactly as
		// runClassifierJudge builds it; the Python renderer is tested against it.
		"example": map[string]string{
			"command": mlSpecExampleCommand,
			"state":   buildPromptFromCollectedWithSensitive(mlSpecExampleCommand, cwd, nil, nil, nil) + DecisionHints(defaults, WalkupHints{}),
		},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(spec); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestMLSpecInSync(t *testing.T) {
	want, err := buildMLSpec(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("YOLONOT_UPDATE_ML_SPEC") == "1" {
		if err := os.WriteFile(mlSpecPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(mlSpecPath)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with YOLONOT_UPDATE_ML_SPEC=1)", mlSpecPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is out of date with decision.go; regenerate with YOLONOT_UPDATE_ML_SPEC=1 go test ./internal/yolonot -run TestMLSpecInSync, then retrain the local model", mlSpecPath)
	}
}
