package yolonot

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

type settingsRendererProbe struct{ pageModel }

func (m settingsRendererProbe) Init() tea.Cmd {
	return tea.Sequence(func() tea.Msg { return tea.WindowSizeMsg{Width: 80, Height: 24} },
		tea.Tick(150*time.Millisecond, func(time.Time) tea.Msg { return tea.Quit() }))
}

func (m settingsRendererProbe) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	out, cmd := m.pageModel.Update(msg)
	m.pageModel = out.(pageModel)
	return m, cmd
}

func TestSettingsActualRendererKeepsJudgesVisibleAt80x24(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	var buf bytes.Buffer
	m := settingsRendererProbe{newPageModel(configRows(Config{}), false, "", 0)}
	_, err := tea.NewProgram(m, tea.WithInput(nil), tea.WithOutput(&buf), tea.WithoutSignalHandler(), tea.WithAltScreen()).Run()
	if err != nil {
		t.Fatal(err)
	}
	if view := ansi.Strip(buf.String()); !strings.Contains(view, "JUDGES") || !strings.Contains(view, "Add judge") {
		t.Fatalf("Bubble Tea clipped the first settings section: %q", view)
	}
}

func TestSettingsViewportResizeAndMouse(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	var rows []configRow
	for i := 0; i < 45; i++ {
		rows = append(rows, configRow{Section: fmt.Sprintf("SECTION %d", i/9), Label: fmt.Sprintf("row-%02d", i), Value: strings.Repeat("value", 20), Edit: func(*Config) {}})
	}
	m := newPageModel(rows, true, "changes staged", 0)
	out, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = out.(pageModel)
	if !strings.Contains(ansi.Strip(m.View()), "row-00") {
		t.Fatal("initial selection was hidden")
	}
	for i := 0; i < 44; i++ {
		out, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = out.(pageModel)
	}
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 40, Height: 12}, {Width: 100, Height: 45}, {Width: 80, Height: 24}} {
		out, _ = m.Update(size)
		m = out.(pageModel)
		view := ansi.Strip(m.View())
		lines := strings.Split(view, "\n")
		if len(lines) > size.Height {
			t.Fatalf("view has %d rows at %dx%d", len(lines), size.Width, size.Height)
		}
		for _, line := range lines {
			if ansi.StringWidth(line) > size.Width {
				t.Fatalf("line wraps at width %d: %q", size.Width, line)
			}
		}
		selectedY := -1
		for y, line := range lines {
			if strings.Contains(line, "row-44") {
				selectedY = y
			}
		}
		if selectedY < 0 {
			t.Fatalf("selection hidden after resize: %s", view)
		}
		clicked, cmd := m.Update(tea.MouseMsg{X: 5, Y: selectedY, Button: tea.MouseButtonLeft, Action: tea.MouseActionRelease})
		if pm := clicked.(pageModel); cmd == nil || pm.chosen != 44 || pm.action != pageEdit {
			t.Fatalf("visible row-44 click opened row %d", pm.chosen)
		}
		if !strings.Contains(lines[len(lines)-1], "s save") {
			t.Fatalf("save action bar hidden: %s", view)
		}
	}
	col := 1 + ansi.StringWidth(keysMove+"  "+keysEdit+"  ")
	clicked, _ := m.Update(tea.MouseMsg{X: col + 1, Y: 23, Button: tea.MouseButtonLeft, Action: tea.MouseActionRelease})
	if clicked.(pageModel).action != pageSave {
		t.Fatal("pinned save action click failed after scrolling")
	}
}

func TestMenuViewportResizeAndMouse(t *testing.T) {
	var fields []menuField
	for f := 0; f < 6; f++ {
		field := menuField{Title: fmt.Sprintf("Field %d", f)}
		for i := 0; i < 5; i++ {
			field.Items = append(field.Items, fmt.Sprintf("choice-%d-%d", f, i))
		}
		fields = append(fields, field)
	}
	m := newMenu("Overrides", "", fields)
	out, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = out.(menuModel)
	for i := 0; i < 5; i++ {
		out, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = out.(menuModel)
	}
	for i := 0; i < 4; i++ {
		out, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = out.(menuModel)
	}
	for _, height := range []int{24, 12, 45, 24} {
		m.fields[5].Cur = 4
		out, _ = m.Update(tea.WindowSizeMsg{Width: 80, Height: height})
		m = out.(menuModel)
		lines := strings.Split(ansi.Strip(m.View()), "\n")
		if len(lines) > height {
			t.Fatalf("menu exceeds %d rows: %d", height, len(lines))
		}
		y := -1
		for i, line := range lines {
			if strings.Contains(line, "choice-5-3") {
				y = i
			}
		}
		if y < 0 || !strings.Contains(strings.Join(lines, "\n"), "choice-5-4") {
			t.Fatalf("last field unavailable: %s", strings.Join(lines, "\n"))
		}
		clicked, _ := m.Update(tea.MouseMsg{X: 5, Y: y, Button: tea.MouseButtonLeft, Action: tea.MouseActionRelease})
		if mm := clicked.(menuModel); mm.active != 5 || mm.fields[5].Cur != 3 || mm.done {
			t.Fatalf("visible choice selected wrong option: active %d, cur %d", mm.active, mm.fields[5].Cur)
		}
		if !strings.Contains(lines[len(lines)-1], menuDone) {
			t.Fatal("done button hidden")
		}
	}
	clicked, _ := m.Update(tea.MouseMsg{X: 3, Y: 23, Button: tea.MouseButtonLeft, Action: tea.MouseActionRelease})
	if !clicked.(menuModel).cancelled {
		t.Fatal("pinned back click failed after scrolling")
	}
}

func TestConfigRowsHandleEmptyExec(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	for _, use := range []string{"exec:", "exec: \t "} {
		cfg := Config{Judges: JudgeList{{Use: use}}}
		rows := configRows(cfg)
		if rows[0].Hint != hintNotFound {
			t.Fatalf("invalid exec not marked missing: %+v", rows[0])
		}
		if err := validateJudgeSpec(cfg, cfg.Judges[0]); err == nil {
			t.Fatal("invalid exec accepted")
		}
		if view := newPageModel(rows, false, "", 0).View(); view == "" {
			t.Fatal("settings not rendered")
		}
	}
}

func TestJudgeJSONEditorRejectsInvalidEntries(t *testing.T) {
	settingsTestState(t)
	for _, text := range []string{`[{"use":"exec:"}]`, `[{"use":"missing-model"}]`, `[{"use":"fast_allow","may":["maybe"]}]`} {
		ruleTestEditor(t, text)
		cfg := Config{Judges: JudgeList{{Use: judgeFastAllow}}}
		editJudgesInEditor(&cfg)
		if judgeNames(cfg.Judges) != judgeFastAllow || !strings.Contains(tuiNotice, "Chain not changed") {
			t.Fatalf("invalid JSON editor chain saved: %s, notice %q", judgeNames(cfg.Judges), tuiNotice)
		}
	}
}

func TestEscalationSelectionUsesCatalogReference(t *testing.T) {
	cfg := Config{Escalation: &EscalationConfig{Model: "big"}}
	if escalationSelection(cfg) != 1 {
		t.Fatal("active v1 escalation opened Off")
	}
	cfg.Escalation.Disabled = true
	if escalationSelection(cfg) != 0 {
		t.Fatal("disabled escalation opened active")
	}
}

func TestSetupAddsTypedBeforeChatWithoutLosingLocalJudges(t *testing.T) {
	cfg := Config{Models: map[string]ModelConfig{
		"chat": {URL: "https://example.test/v1/chat/completions", Model: "chat"},
		"jev":  {URL: decisionDefaultURL, Model: "jev"},
	}, Judges: JudgeList{{Use: judgeFastAllow}, {Use: "exec:/first"}, {Use: "chat", May: []string{ActionAsk, ActionDeny}}, {Use: "exec:/last"}}}
	got := setupJudgeChain(cfg, "jev", "chat")
	if judgeNames(got) != "fast_allow → exec:/first → jev → chat → exec:/last" {
		t.Fatalf("setup chain: %s", judgeNames(got))
	}
	if !reflect.DeepEqual(got[3].May, []string{ActionAsk, ActionDeny}) {
		t.Fatal("setup lost custom chat restrictions")
	}
	cfg.Judges = got
	if again := setupJudgeChain(cfg, "jev", "chat"); !reflect.DeepEqual(got, again) {
		t.Fatalf("setup not idempotent: %+v", again)
	}
}

func TestSetupInstallsRequestedHarnessWhenAnotherIsInstalled(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Chdir(t.TempDir())
	oldArgs := os.Args
	os.Args = []string{"yolonot", "setup", "--harness", "codex"}
	defer func() { os.Args = oldArgs }()
	if err := GetHarness("claude").Install("/tmp/yolonot-test"); err != nil {
		t.Fatal(err)
	}
	SaveConfig(Config{Models: map[string]ModelConfig{
		"chat": {URL: "https://example.test/v1/chat/completions", Model: "chat"},
		"jev":  {URL: decisionDefaultURL, Model: "jev"},
	}, Judges: JudgeList{{Use: judgeFastAllow}, {Use: "chat"}}})
	output := captureStdout(cmdSetup)
	if !GetHarness("codex").IsInstalled() {
		t.Fatalf("requested codex setup skipped because Claude was installed: %s", output)
	}
	if got := judgeNames(LoadConfig().Judges); got != "fast_allow → jev → chat" {
		t.Fatalf("actual setup left typed after chat: %s", got)
	}
	if !strings.Contains(output, "Restart codex") {
		t.Fatalf("setup restart instructions target wrong harness: %s", output)
	}
}

func settingsTestState(t *testing.T) {
	t.Helper()
	oldDrafts, oldPage, oldNotice, oldExit := tuiRuleDrafts, tuiInPage, tuiNotice, tuiExitMsg
	tuiRuleDrafts, tuiInPage, tuiNotice, tuiExitMsg = &ruleDrafts{}, true, "", ""
	t.Cleanup(func() { tuiRuleDrafts, tuiInPage, tuiNotice, tuiExitMsg = oldDrafts, oldPage, oldNotice, oldExit })
}

func ruleTestEditor(t *testing.T, text string) {
	t.Helper()
	dir := t.TempDir()
	fixture := filepath.Join(dir, "content")
	script := filepath.Join(dir, "editor")
	if err := os.WriteFile(fixture, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat '"+fixture+"' > \"$1\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", script)
}

func TestRuleEditsAreDraftedUntilSaveAndDiscardLeavesFiles(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Chdir(t.TempDir())
	settingsTestState(t)
	global := filepath.Join(YolonotDir(), "rules")
	project := filepath.Join(mustGetwd(t), ".yolonot")
	const original = "deny-cmd dangerous*\n"
	if err := os.WriteFile(global, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}
	ruleTestEditor(t, "allow-cmd safe*\n")
	cfg := Config{}
	editRules(&cfg)
	editProjectRules(&cfg)
	if !tuiRuleDrafts.dirty() || len(tuiRuleDrafts.files) != 2 {
		t.Fatal("rule edits did not mark settings dirty")
	}
	if got, _ := os.ReadFile(global); string(got) != original {
		t.Fatalf("global policy changed before Save: %s", got)
	}
	if _, err := os.Stat(project); !os.IsNotExist(err) {
		t.Fatal("project rules created before Save")
	}
	// Discard drops the in-memory draft; no active file needs reverting.
	tuiRuleDrafts = &ruleDrafts{}
	if got, _ := os.ReadFile(global); string(got) != original || tuiRuleDrafts.dirty() {
		t.Fatal("discard did not leave the original policy intact")
	}
	editRules(&cfg)
	editProjectRules(&cfg)
	if !saveConfigWithBackup(cfg) {
		t.Fatalf("save failed: %s", tuiNotice)
	}
	for _, path := range []string{global, project} {
		if got, _ := os.ReadFile(path); string(got) != "allow-cmd safe*\n" {
			t.Fatalf("Save omitted %s: %s", path, got)
		}
	}
	if info, err := os.Stat(global); err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("existing rule permissions not preserved: %v", err)
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	path, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSettingsSaveFailureRollsBackRulesAndKeepsDraft(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	settingsTestState(t)
	global := filepath.Join(YolonotDir(), "rules")
	if err := os.WriteFile(global, []byte("deny-cmd original*\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ruleTestEditor(t, "allow-cmd staged*\n")
	cfg := Config{QuietOnAllow: true}
	editRules(&cfg)
	// atomic config persistence refuses symlinks. Rules already written
	// in the save transaction must be restored on this failure.
	target := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, configPath()); err != nil {
		t.Fatal(err)
	}
	if saveConfigWithBackup(cfg) {
		t.Fatal("failed config write reported success")
	}
	if got, _ := os.ReadFile(global); string(got) != "deny-cmd original*\n" {
		t.Fatalf("rules remained applied after failed save: %s", got)
	}
	if !tuiRuleDrafts.dirty() || !strings.Contains(tuiNotice, "Not saved") || strings.Contains(tuiExitMsg, "Saved.") {
		t.Fatalf("draft/error feedback lost: %q / %q", tuiNotice, tuiExitMsg)
	}
}

func TestSettingsSaveRefusesExternalRuleChanges(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	settingsTestState(t)
	path := filepath.Join(YolonotDir(), "rules")
	if err := os.WriteFile(path, []byte("deny-cmd original*\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ruleTestEditor(t, "allow-cmd staged*\n")
	cfg := Config{}
	editRules(&cfg)
	if err := os.WriteFile(path, []byte("deny-cmd external*\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if saveConfigWithBackup(cfg) {
		t.Fatal("overwrote rule edits made outside settings")
	}
	if got, _ := os.ReadFile(path); string(got) != "deny-cmd external*\n" {
		t.Fatalf("external policy overwritten: %s", got)
	}
	if !strings.Contains(tuiNotice, "changed outside settings") {
		t.Fatalf("conflict not explained: %s", tuiNotice)
	}
}

func TestRuleEditorFailurePreservesDraftAndError(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	settingsTestState(t)
	ruleTestEditor(t, "allow-cmd staged*\n")
	cfg := Config{}
	editRules(&cfg)
	t.Setenv("VISUAL", "/definitely/missing-editor")
	editRules(&cfg)
	if !tuiRuleDrafts.dirty() || !strings.Contains(tuiNotice, "Editor failed") {
		t.Fatalf("editor error overwritten or draft lost: %q", tuiNotice)
	}
}
