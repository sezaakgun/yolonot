package yolonot

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Menus and option groups with full mouse support: hover highlights, click
// selects, wheel moves, a clickable "back" (and "done") button. Keyboard
// stays what huh taught: ↑↓, → ⏎ select, ← esc back. Text inputs remain
// huh fields (tui.go); everything else runs through here.

var stHover = lipgloss.NewStyle().Background(lipgloss.AdaptiveColor{Light: "#e8e8ed", Dark: "#2c2c2e"})

const (
	menuBack = "← back"
	menuDone = "✓ done"
)

// menuField is one titled list of options with a cursor.
type menuField struct {
	Title string
	Items []string
	Cur   int
}

// menuModel renders one or more fields; one field = a plain menu.
type menuModel struct {
	title, hint string
	fields      []menuField
	active      int // field index
	hoverLine   int // -1 none
	width       int
	cancelled   bool
	done        bool
}

// line kinds for the layout
type menuLine struct {
	field, item int // item >= 0: option; item == -1: chrome
	title, back bool
}

func newMenu(title, hint string, fields []menuField) menuModel {
	for i := range fields {
		if fields[i].Cur < 0 || fields[i].Cur >= len(fields[i].Items) {
			fields[i].Cur = 0
		}
	}
	return menuModel{title: title, hint: hint, fields: fields, hoverLine: -1, width: 100}
}

// layout: title, hint, then per field (a title line when more than one
// field) its options, a blank, then the button row: back [done].
func (m menuModel) layout() []menuLine {
	lines := []menuLine{{item: -1}, {item: -1}}
	for f := range m.fields {
		if len(m.fields) > 1 {
			lines = append(lines, menuLine{field: f, item: -1, title: true})
		}
		for i := range m.fields[f].Items {
			lines = append(lines, menuLine{field: f, item: i})
		}
	}
	lines = append(lines, menuLine{item: -1}, menuLine{item: -1, back: true})
	return lines
}

func (m menuModel) Init() tea.Cmd { return nil }

func (m menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		f := &m.fields[m.active]
		switch msg.String() {
		case "up", "k":
			if f.Cur > 0 {
				f.Cur--
			}
		case "down", "j":
			if f.Cur < len(f.Items)-1 {
				f.Cur++
			}
		case "tab":
			m.active = (m.active + 1) % len(m.fields)
		case "shift+tab":
			m.active = (m.active + len(m.fields) - 1) % len(m.fields)
		case "enter", "right", "l", " ":
			if m.active < len(m.fields)-1 {
				m.active++
				return m, nil
			}
			m.done = true
			return m, tea.Quit
		case "esc", "left", "h", "q", "ctrl+c":
			m.cancelled = true
			return m, tea.Quit
		case "y", "n":
			// yes/no menus: y and n pick directly
			if len(m.fields) == 1 && len(f.Items) == 2 && f.Items[0] == "Yes" {
				f.Cur = map[string]int{"y": 0, "n": 1}[msg.String()]
				m.done = true
				return m, tea.Quit
			}
		}
	case tea.MouseMsg:
		lines := m.layout()
		switch {
		case msg.Button == tea.MouseButtonWheelUp || msg.Button == tea.MouseButtonWheelDown:
			f := &m.fields[m.active]
			if msg.Button == tea.MouseButtonWheelUp && f.Cur > 0 {
				f.Cur--
			} else if msg.Button == tea.MouseButtonWheelDown && f.Cur < len(f.Items)-1 {
				f.Cur++
			}
		case msg.Action == tea.MouseActionMotion:
			m.hoverLine = -1
			if msg.Y >= 0 && msg.Y < len(lines) && (lines[msg.Y].item >= 0 || lines[msg.Y].back) {
				m.hoverLine = msg.Y
			}
		case msg.Action == tea.MouseActionRelease && msg.Button == tea.MouseButtonLeft:
			if msg.Y < 0 || msg.Y >= len(lines) {
				return m, nil
			}
			l := lines[msg.Y]
			switch {
			case l.back && msg.X < 2+lipgloss.Width(menuBack):
				m.cancelled = true
				return m, tea.Quit
			case l.back && len(m.fields) > 1 && msg.X >= 2+lipgloss.Width(menuBack)+3 && msg.X < 2+lipgloss.Width(menuBack)+3+lipgloss.Width(menuDone):
				m.done = true
				return m, tea.Quit
			case l.item >= 0:
				m.active = l.field
				m.fields[l.field].Cur = l.item
				if len(m.fields) == 1 {
					m.done = true
					return m, tea.Quit
				}
			}
		}
	}
	return m, nil
}

func (m menuModel) View() string {
	var b strings.Builder
	b.WriteString(" " + stBold.Render(m.title) + "\n")
	hint := m.hint
	if hint == "" {
		hint = "↑↓ move  → ⏎ select  ← esc back"
		if len(m.fields) > 1 {
			hint = "↑↓ move  ⏎ next  esc back  (or click)"
		}
	}
	b.WriteString(" " + stDim.Render(hint) + "\n")
	lines := m.layout()
	for y, l := range lines[2:] {
		y += 2
		switch {
		case l.back:
			back := stDim.Render(menuBack)
			if m.hoverLine == y {
				back = stHover.Render(menuBack)
			}
			b.WriteString("  " + back)
			if len(m.fields) > 1 {
				b.WriteString("   " + stGood.Render(menuDone))
			}
			b.WriteString("\n")
		case l.title:
			t := m.fields[l.field].Title
			if l.field == m.active {
				b.WriteString(" " + stAccent.Bold(true).Render(t) + "\n")
			} else {
				b.WriteString(" " + stBold.Render(t) + "\n")
			}
		case l.item < 0:
			b.WriteString("\n")
		default:
			f := m.fields[l.field]
			text := f.Items[l.item]
			row := "    " + text
			switch {
			case l.item == f.Cur && l.field == m.active:
				row = stAccent.Render("  ❯ " + text)
			case l.item == f.Cur:
				row = "  " + stDim.Render("❯ ") + text
			}
			if m.hoverLine == y {
				row = stHover.Render(row + strings.Repeat(" ", max(0, m.width-lipgloss.Width(row)-2)))
			}
			b.WriteString(row + "\n")
		}
	}
	return b.String()
}

// runMenu shows a menu (or option group) and reports whether it was
// submitted; the chosen indices are in the returned fields.
func runMenu(title, hint string, fields []menuField) ([]menuField, bool) {
	m := newMenu(title, hint, fields)
	tuiClear()
	out, err := tea.NewProgram(m, tea.WithMouseAllMotion()).Run()
	if err != nil {
		return fields, false
	}
	final := out.(menuModel)
	return final.fields, final.done && !final.cancelled
}
