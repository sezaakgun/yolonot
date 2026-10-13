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
	hover  int // row index under the mouse, -1 none
}

func newPageModel(rows []configRow, dirty bool, notice string, cur int) pageModel {
	m := pageModel{rows: rows, width: 100, dirty: dirty, notice: notice, cur: cur, hover: -1}
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
	case tea.MouseMsg:
		switch {
		case msg.Button == tea.MouseButtonWheelUp && m.cur > 0:
			m.cur--
		case msg.Button == tea.MouseButtonWheelDown && m.cur < len(m.sel)-1:
			m.cur++
		case msg.Action == tea.MouseActionRelease && msg.Button == tea.MouseButtonLeft:
			return m.click(msg.X, msg.Y)
		case msg.Action == tea.MouseActionMotion:
			m.hover = -1
			if lines := m.lineRows(); msg.Y >= 0 && msg.Y < len(lines) && lines[msg.Y] >= 0 && m.rows[lines[msg.Y]].Edit != nil {
				m.hover = lines[msg.Y]
			}
		}
	}
	return m, nil
}

// Line layout: the title, then per row a blank + section line when the
// section changes, then the row; after the rows a blank, the notice (if
// any) and the key bar. lineRow is the row index per line, -1 for chrome,
// lineKeys for the key bar.
const lineKeys = -2

func (m pageModel) lineRows() []int {
	lines := []int{-1}
	section := ""
	for i, r := range m.rows {
		if r.Section != section {
			section = r.Section
			lines = append(lines, -1, -1)
		}
		lines = append(lines, i)
	}
	lines = append(lines, -1)
	if m.notice != "" {
		lines = append(lines, -1)
	}
	return append(lines, lineKeys)
}

// Key bar words, plain, so clicks can be mapped to columns.
const keysMove, keysEdit, keysSave, keysQuit = "↑↓ move", "→ ⏎ edit", "s save", "q quit"

// click: a row opens it (first click selects and opens), the key bar's
// "save" / "quit" words act like the keys.
func (m pageModel) click(x, y int) (tea.Model, tea.Cmd) {
	lines := m.lineRows()
	if y < 0 || y >= len(lines) {
		return m, nil
	}
	switch row := lines[y]; {
	case row == lineKeys:
		col := 1 + ansi.StringWidth(keysMove+"  "+keysEdit+"  ")
		switch {
		case x >= col && x < col+ansi.StringWidth(keysSave):
			m.action = pageSave
			return m, tea.Quit
		case x >= col+ansi.StringWidth(keysSave+"  ") && x < col+ansi.StringWidth(keysSave+"  "+keysQuit):
			m.action = pageQuit
			return m, tea.Quit
		}
	case row >= 0 && m.rows[row].Edit != nil:
		for i, s := range m.sel {
			if s == row {
				m.cur = i
			}
		}
		m.action, m.chosen = pageEdit, row
		return m, tea.Quit
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
		line := " " + cursor + label + "  " + value + "  " + hint
		if i == m.hover {
			line = stHover.Render(line + strings.Repeat(" ", max(0, m.width-lipgloss.Width(line)-1)))
		}
		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	if m.notice != "" {
		b.WriteString(" " + stAccent.Render(m.notice) + "\n")
	}
	keys := stBold.Render("↑↓") + stDim.Render(" move  ") +
		stBold.Render("→ ⏎") + stDim.Render(" edit  ") +
		stBold.Render("s") + stDim.Render(" save  ") +
		stBold.Render("q") + stDim.Render(" quit")
	if m.width >= 70 {
		keys += stDim.Render("   click or wheel works too")
	}
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
	tuiClear()
	out, err := tea.NewProgram(m, tea.WithMouseAllMotion()).Run()
	if err != nil {
		return pageQuit, -1, 0
	}
	final := out.(pageModel)
	return final.action, final.chosen, final.cur
}
