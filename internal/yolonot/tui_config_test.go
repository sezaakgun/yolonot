package yolonot

import (
	"strings"
	"testing"
)

func TestWithModelSlots(t *testing.T) {
	cfg := Config{Models: map[string]ModelConfig{"jev": {URL: decisionDefaultURL, Model: "jev-latest"}, "chat": {URL: "https://x/v1/chat/completions", Model: "m"}}}
	in := []JudgeSpec{{Use: "fast_allow"}, {Use: "chat"}, {Use: "exec:/x"}}
	if got := judgeNames(withModelSlots(cfg, in, []JudgeSpec{{Use: "jev"}, {Use: "chat"}})); got != "fast_allow → jev → chat → exec:/x" {
		t.Fatalf("got %q", got)
	}
	if got := judgeNames(withModelSlots(cfg, []JudgeSpec{{Use: "fast_allow"}}, []JudgeSpec{{Use: "chat"}})); got != "fast_allow → chat" {
		t.Fatalf("append when no model slot, got %q", got)
	}
}

func TestApplyJudgeMove(t *testing.T) {
	base := func() []JudgeSpec { return []JudgeSpec{{Use: "a"}, {Use: "b"}, {Use: "c"}} }
	if got := judgeNames(applyJudgeMove(base(), 0, 0)); got != "a → b → c" {
		t.Errorf("first up is a no-op: %q", got)
	}
	if got := judgeNames(applyJudgeMove(base(), 2, 1)); got != "a → b → c" {
		t.Errorf("last down is a no-op: %q", got)
	}
	if got := judgeNames(applyJudgeMove(base(), 1, 0)); got != "b → a → c" {
		t.Errorf("up: %q", got)
	}
	if got := judgeNames(applyJudgeMove(base(), 1, 2)); got != "a → c" {
		t.Errorf("remove: %q", got)
	}
	if got := judgeNames(applyJudgeMove([]JudgeSpec{{Use: "a"}}, 0, 2)); got != "a" {
		t.Errorf("never below one judge: %q", got)
	}
}

func TestConfigRowsReflectState(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("OPENROUTER_API_KEY", "")
	t.Setenv("TYPESAFE_API_KEY", "")
	cfg := Config{
		Models: map[string]ModelConfig{
			"gemini": {URL: "https://openrouter.ai/x", Model: "m", EnvKey: "OPENROUTER_API_KEY"},
			"jev":    {URL: decisionDefaultURL, Model: "jev-latest", EnvKey: "TYPESAFE_API_KEY"},
			"big":    {URL: "https://openrouter.ai/x", Model: "big", EnvKey: "OPENROUTER_API_KEY"},
		},
		Judges:     JudgeList{{Use: "fast_allow"}, {Use: "exec:/definitely/missing/hook"}, {Use: "jev"}, {Use: "gemini", May: []string{"allow"}}},
		Escalation: &EscalationConfig{Model: "big", Disabled: true, Unresolved: "deny"},
	}
	rows := configRows(cfg)
	find := func(label string) configRow {
		for _, r := range rows {
			if r.Label == label {
				return r
			}
		}
		t.Fatalf("row %q missing", label)
		return configRow{}
	}
	if r := find("  1"); r.Value != "fast_allow" || r.Hint != "may allow" {
		t.Errorf("fast_allow row %+v", r)
	}
	if r := find("  2"); r.Value != "exec:hook" || r.Hint != hintNotFound {
		t.Errorf("exec row %+v", r)
	}
	if r := find("  3"); r.Hint != "may allow/ask" {
		t.Errorf("typed judge row shows its may set: %+v", r)
	}
	if r := find("  4"); r.Hint != "may allow" {
		t.Errorf("explicit may must show: %+v", r)
	}
	if r := find("jev"); r.Value != "jev-latest" || r.Hint != hintKeyMissing {
		t.Errorf("jev model row %+v", r)
	}
	if r := find("gemini"); r.Hint != hintKeyMissing {
		t.Errorf("gemini model row %+v", r)
	}
	if r := find("Escalation"); r.Value != "big" || r.Hint != hintOff {
		t.Errorf("escalation row %+v", r)
	}
	if r := find("If still unsure"); r.Value != "deny" {
		t.Errorf("unresolved row %+v", r)
	}
	for _, r := range rows {
		if strings.ContainsAny(r.Hint, "✓✗[]") {
			t.Errorf("hint vocabulary must be plain words: %q", r.Hint)
		}
	}
	editQuiet(&cfg)
	if !cfg.QuietOnAllow {
		t.Error("quiet toggle")
	}
}

func TestConfigRowsEmptyConfig(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	rows := configRows(Config{})
	var labels []string
	for _, r := range rows {
		labels = append(labels, r.Label)
	}
	for _, want := range []string{"  Add judge", "Add model", "Escalation", "Profile"} {
		if !strings.Contains(strings.Join(labels, "|"), want) {
			t.Fatalf("empty config missing row %q: %v", want, labels)
		}
	}
}

func TestPageViewNarrowDoesNotPanic(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	rows := configRows(Config{Judges: []JudgeSpec{{Use: "exec:/a/very/long/path/to/some/hook/binary/that/goes/on"}}})
	m := newPageModel(rows, true, "notice", 0)
	for _, w := range []int{120, 60, 40, 20, 5} {
		m.width = w
		if out := m.View(); out == "" {
			t.Fatalf("empty view at width %d", w)
		}
	}
}

func TestConfigRowsExecUnderModels(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	rows := configRows(Config{Judges: []JudgeSpec{{Use: "fast_allow"}, {Use: "exec:/no/such/hook"}}})
	for _, r := range rows {
		if r.Section == "MODELS" && r.Label == "exec:hook" {
			if r.Hint != hintNotFound {
				t.Fatalf("missing hook should read %q, got %q", hintNotFound, r.Hint)
			}
			return
		}
	}
	t.Fatalf("exec judge not listed under MODELS: %+v", rows)
}

func TestConfigRowsPolicyAndPromptSections(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	cfg := Config{Policy: PolicyConfig{Profile: "strict", Harness: map[string]HarnessPolicy{"codex": {Profile: "paranoid", RiskMap: map[string]string{"high": "deny"}}}},
		Prompt: PromptConfig{AskHints: []string{"$defaults", "", "x"}, SystemPrompt: "abc"}}
	got := map[string]configRow{}
	for _, r := range configRows(cfg) {
		got[r.Section+"/"+r.Label] = r
	}
	for label, want := range map[string]string{
		"POLICY/Profile": "strict", "POLICY/  low": "ask", "POLICY/  critical": "deny",
		"POLICY/Harness overrides": "codex: paranoid, high→deny",
		"PROMPT/Ask hints": "defaults + 1", "PROMPT/Context": "none", "PROMPT/System prompt": "custom (3 chars)",
	} {
		if got[label].Value != want {
			t.Errorf("%s = %q, want %q", label, got[label].Value, want)
		}
	}
	if got["POLICY/Profile"].Hint != "built-in" {
		t.Errorf("strict should read built-in, got %q", got["POLICY/Profile"].Hint)
	}
	if harnessOverridesSummary(Config{}) != "none" || hintListSummary(nil) != "none" || hintListSummary([]string{"a", "b"}) != "2 lines" {
		t.Error("summary helpers")
	}
}
