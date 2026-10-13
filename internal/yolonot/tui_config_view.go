package yolonot

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// The settings page: sections, aligned columns, a cursor row, coloured
// status words, a key bar. It never edits anything — Enter hands the
// chosen row back to cmdConfigTUI, which runs that row's editor and
// reopens the page.

var (
	stBold   = lipgloss.NewStyle().Bold(true)
	stDim    = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#6e6e73", Dark: "#a1a1a6"})
	stAccent = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#0071e3", Dark: "#2997ff"})
	stGood   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#1a7f37", Dark: "#3fb950"})
	stBad    = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#cf222e", Dark: "#f85149"})
)

type pageAction int

const (
	pageEdit pageAction = iota
	pageSave
	pageQuit
)

type pageModel struct {
	rows   []configRow
	sel    []int // indices of editable rows
	cur    int   // position in sel
	width  int
	dirty  bool
	notice string
	action pageAction
	chosen int
}

func newPageModel(rows []configRow, dirty bool, notice string, cur int) pageModel {
	m := pageModel{rows: rows, width: 100, dirty: dirty, notice: notice, cur: cur}
	for i, r := range rows {
		if r.Edit != nil {
			m.sel = append(m.sel, i)
		}
	}
	if m.cur >= len(m.sel) {
		m.cur = 0
	}
	return m
}

func (m pageModel) Init() tea.Cmd { return nil }

func (m pageModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cur > 0 {
				m.cur--
			}
		case "down", "j":
			if m.cur < len(m.sel)-1 {
				m.cur++
			}
		case "enter", "right", "l", " ":
			if len(m.sel) > 0 {
				m.action, m.chosen = pageEdit, m.sel[m.cur]
				return m, tea.Quit
			}
		case "s":
			m.action = pageSave
			return m, tea.Quit
		case "q", "esc", "ctrl+c":
			m.action = pageQuit
			return m, tea.Quit
		}
	}
	return m, nil
}

func hintStyle(h string) lipgloss.Style {
	switch {
	case goodHints[h]:
		return stGood
	case badHints[h]:
		return stBad
	}
	return stDim
}

func (m pageModel) View() string {
	var b strings.Builder
	title := stBold.Render("yolonot " + Version)
	path := stDim.Render(tildePath(configPath()))
	gap := m.width - lipgloss.Width(title) - lipgloss.Width(path) - 2
	if gap < 2 {
		gap = 2
	}
	b.WriteString(" " + title + strings.Repeat(" ", gap) + path + "\n")

	labelW, valueW, hintW := 0, 0, 0
	for _, r := range m.rows {
		labelW = max(labelW, lipgloss.Width(r.Label))
		valueW = max(valueW, lipgloss.Width(r.Value))
		hintW = max(hintW, lipgloss.Width(r.Hint))
	}
	avail := max(m.width-3-labelW-4, 12)
	hintW = min(hintW, avail/2)
	valueW = max(min(valueW, avail-hintW), 8)

	section := ""
	for i, r := range m.rows {
		if r.Section != section {
			section = r.Section
			b.WriteString("\n " + stBold.Render(section) + "\n")
		}
		selected := r.Edit != nil && len(m.sel) > 0 && m.sel[m.cur] == i
		cursor := "  "
		label := lipgloss.NewStyle().Width(labelW).Render(r.Label)
		value := lipgloss.NewStyle().Width(valueW).Render(ansi.Truncate(r.Value, valueW, "…"))
		if selected {
			cursor = stAccent.Render("❯ ")
			label = stAccent.Bold(true).Width(labelW).Render(r.Label)
		} else if r.Edit == nil {
			label = stDim.Width(labelW).Render(r.Label)
			value = stDim.Width(valueW).Render(ansi.Truncate(r.Value, valueW, "…"))
		}
		hint := hintStyle(r.Hint).Render(ansi.Truncate(r.Hint, hintW, "…"))
		b.WriteString(" " + cursor + label + "  " + value + "  " + hint + "\n")
	}

	b.WriteString("\n")
	if m.notice != "" {
		b.WriteString(" " + stAccent.Render(m.notice) + "\n")
	}
	keys := stBold.Render("↑↓") + stDim.Render(" move  ") +
		stBold.Render("→ ⏎") + stDim.Render(" edit  ") +
		stBold.Render("s") + stDim.Render(" save  ") +
		stBold.Render("q") + stDim.Render(" quit")
	if m.dirty && m.width >= 60 {
		keys += "   " + stGood.Render("unsaved changes")
	}
	b.WriteString(" " + keys + "\n")
	return b.String()
}

// runPage shows the page and returns the action, the chosen row index and
// the cursor position to restore next time.
func runPage(rows []configRow, dirty bool, notice string, cur int) (pageAction, int, int) {
	m := newPageModel(rows, dirty, notice, cur)
	out, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	if err != nil {
		return pageQuit, -1, 0
	}
	final := out.(pageModel)
	return final.action, final.chosen, final.cur
}
