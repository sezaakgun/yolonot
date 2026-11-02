package yolonot

import (
	"os"
	"strings"
	"testing"
)

// TestDecisionLiveProbe hits the real endpoint for a handful of commands and
// prints the folded verdict. Skipped unless DECISION_LIVE=1; diagnostic only.
func TestDecisionLiveProbe(t *testing.T) {
	if os.Getenv("DECISION_LIVE") != "1" {
		t.Skip("set DECISION_LIVE=1")
	}
	cfg := LLMConfig{URL: envOr("DECISION_URL", decisionDefaultURL), Model: envOr("DECISION_MODEL", "jev-latest"), APIKey: os.Getenv("TYPESAFE_API_KEY")}
	hints := ""
	if h := os.Getenv("DECISION_ASK_HINTS"); h != "" {
		hints = DecisionHints(PromptConfig{AskHints: strings.Split(h, "\n")}, WalkupHints{})
	}
	for _, c := range strings.Split(strings.TrimSpace(os.Getenv("DECISION_CMDS")), "\n") {
		raw, err := callDecision(cfg, "Command: "+c+hints)
		if err != nil {
			t.Logf("%-50s ERR %v", c, err)
			continue
		}
		d := ParseDecision(raw)
		t.Logf("%-50s %s %s", c, d.Decision, d.Reasoning)
	}
}
