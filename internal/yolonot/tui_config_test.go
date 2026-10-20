package yolonot

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
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
		"PROMPT/Ask hints":         "defaults + 1", "PROMPT/Context": "none", "PROMPT/System prompt": "custom (3 chars)",
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

func TestPageClickMapsLinesToRows(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	rows := []configRow{
		{"A", "a1", "", "", func(*Config) {}},
		{"A", "a2", "", "", nil},
		{"B", "b1", "", "", func(*Config) {}},
	}
	m := newPageModel(rows, false, "", 0)
	// title, blank, A, a1, a2, blank, B, b1, blank, keys
	want := []int{-1, -1, -1, 0, 1, -1, -1, 2, -1, lineKeys}
	got := m.lineRows()
	if len(got) != len(want) {
		t.Fatalf("lines %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lines %v, want %v", got, want)
		}
	}
	out, _ := m.click(5, 7) // b1
	if pm := out.(pageModel); pm.action != pageEdit || pm.chosen != 2 || pm.cur != 1 {
		t.Fatalf("click on b1: action=%v chosen=%d cur=%d", pm.action, pm.chosen, pm.cur)
	}
	out, _ = m.click(5, 4) // a2 is display-only
	if pm := out.(pageModel); pm.chosen != 0 || pm.cur != 0 {
		t.Fatalf("click on display-only row changed state: %+v", pm)
	}
	col := 1 + ansi.StringWidth(keysMove+"  "+keysEdit+"  ")
	out, _ = m.click(col+1, 9)
	if pm := out.(pageModel); pm.action != pageSave {
		t.Fatalf("click on save word: action=%v", pm.action)
	}
	out, _ = m.click(col+ansi.StringWidth(keysSave+"  ")+1, 9)
	if pm := out.(pageModel); pm.action != pageQuit {
		t.Fatalf("click on quit word: action=%v", pm.action)
	}
}

func TestMenuMouseAndKeys(t *testing.T) {
	m := newMenu("Pick", "", []menuField{{Items: []string{"a", "b", "c"}, Cur: 0}})
	// layout: title, hint, a, b, c, blank, back
	out, _ := m.Update(tea.MouseMsg{Action: tea.MouseActionMotion, X: 4, Y: 3})
	if mm := out.(menuModel); mm.hoverLine != 3 {
		t.Fatalf("hover line = %d", mm.hoverLine)
	}
	out, _ = m.Update(tea.MouseMsg{Action: tea.MouseActionRelease, Button: tea.MouseButtonLeft, X: 4, Y: 4})
	if mm := out.(menuModel); !mm.done || mm.fields[0].Cur != 2 {
		t.Fatalf("click on c: done=%v cur=%d", mm.done, mm.fields[0].Cur)
	}
	out, _ = m.Update(tea.MouseMsg{Action: tea.MouseActionRelease, Button: tea.MouseButtonLeft, X: 3, Y: 6})
	if mm := out.(menuModel); !mm.cancelled {
		t.Fatal("click on back should cancel")
	}
	out, _ = m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	if mm := out.(menuModel); !mm.cancelled {
		t.Fatal("left should cancel")
	}
	// group: enter advances fields, last enter submits; click sets a field without submitting
	g := newMenu("G", "", []menuField{{Title: "x", Items: []string{"1", "2"}}, {Title: "y", Items: []string{"1", "2"}}})
	out, _ = g.Update(tea.KeyMsg{Type: tea.KeyEnter})
	g = out.(menuModel)
	if g.active != 1 || g.done {
		t.Fatalf("enter should move to field 2: active=%d done=%v", g.active, g.done)
	}
	// layout: title, hint, "x", 1, 2, "y", 1, 2, blank, back/done
	out, _ = g.Update(tea.MouseMsg{Action: tea.MouseActionRelease, Button: tea.MouseButtonLeft, X: 5, Y: 4})
	g = out.(menuModel)
	if g.done || g.fields[0].Cur != 1 || g.active != 0 {
		t.Fatalf("click on x/2: done=%v cur=%d active=%d", g.done, g.fields[0].Cur, g.active)
	}
	out, _ = g.Update(tea.MouseMsg{Action: tea.MouseActionRelease, Button: tea.MouseButtonLeft, X: 2 + lipgloss.Width(menuBack) + 4, Y: 9})
	if gg := out.(menuModel); !gg.done {
		t.Fatal("click on done should submit")
	}
	yn := newMenu("Sure?", "", []menuField{{Items: []string{"Yes", "No"}, Cur: 1}})
	out, _ = yn.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	if mm := out.(menuModel); !mm.done || mm.fields[0].Cur != 0 {
		t.Fatal("y should pick Yes")
	}
}

func TestPageHoverFollowsMouse(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	rows := []configRow{{"A", "a1", "", "", func(*Config) {}}, {"A", "a2", "", "", nil}}
	m := newPageModel(rows, false, "", 0)
	out, _ := m.Update(tea.MouseMsg{Action: tea.MouseActionMotion, X: 3, Y: 3})
	if pm := out.(pageModel); pm.hover != 0 {
		t.Fatalf("hover = %d, want row 0", pm.hover)
	}
	out, _ = m.Update(tea.MouseMsg{Action: tea.MouseActionMotion, X: 3, Y: 4})
	if pm := out.(pageModel); pm.hover != -1 {
		t.Fatalf("display-only row should not hover, got %d", pm.hover)
	}
}
