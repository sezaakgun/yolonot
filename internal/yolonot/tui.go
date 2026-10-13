package yolonot

import (
	"errors"
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

// tuiNotice collects one-line messages from prompts while the settings
// page is open; the page shows the latest one instead of printing to a
// screen the alt-screen page would repaint over. Empty outside the page.
var tuiNotice string
var tuiInPage bool

// runField runs one huh field as a form: Esc and Ctrl-C both cancel, and
// inside the settings page the prompt takes the alternate screen so it
// leaves nothing behind. Returns false on cancel.
func runField(fields ...huh.Field) bool {
	km := huh.NewDefaultKeyMap()
	quit := []string{"ctrl+c", "esc"}
	allSelect := true
	for _, f := range fields {
		if _, isSelect := f.(*huh.Select[int]); !isSelect {
			allSelect = false
		}
	}
	if allSelect {
		// menus: ← back, → select; inputs keep both for the cursor
		quit = append(quit, "left")
		km.Select.Next = key.NewBinding(key.WithKeys("enter", "right", "tab"))
		km.Select.Submit = key.NewBinding(key.WithKeys("enter", "right"))
	}
	km.Quit = key.NewBinding(key.WithKeys(quit...))
	form := huh.NewForm(huh.NewGroup(fields...)).WithKeyMap(km).WithShowHelp(false)
	if tuiInPage {
		form = form.WithProgramOptions(tea.WithAltScreen())
	}
	err := form.Run()
	if err != nil && !errors.Is(err, huh.ErrUserAborted) {
		tuiNote("prompt failed", err.Error())
	}
	return err == nil
}

// tuiSelect presents an arrow-key menu and returns the selected index, or
// -1 on cancel (Esc, Ctrl+C).
func tuiSelect(title string, items []string, defaultIdx int) int {
	if len(items) == 0 {
		return -1
	}
	options := make([]huh.Option[int], len(items))
	for i, item := range items {
		options[i] = huh.NewOption(item, i)
	}
	selected := 0
	if defaultIdx >= 0 && defaultIdx < len(items) {
		selected = defaultIdx
	}
	if !runField(huh.NewSelect[int]().Title(title).Description("↑↓ move  → ⏎ select  ← esc back").Options(options...).Value(&selected)) {
		return -1
	}
	return selected
}

// tuiInput prompts for text with an optional default. Empty on cancel.
func tuiInput(title string, placeholder string, defaultVal string) string {
	value := defaultVal
	if !runField(huh.NewInput().Title(title).Description("⏎ ok  esc back").Placeholder(placeholder).Value(&value)) {
		return ""
	}
	return value
}

// tuiConfirm shows a yes/no prompt. False on cancel.
func tuiConfirm(prompt string) bool {
	var confirmed bool
	if !runField(huh.NewConfirm().Title(prompt).Value(&confirmed)) {
		return false
	}
	return confirmed
}

// tuiPassword prompts for sensitive input (API keys). Hidden characters.
func tuiPassword(title string) string {
	var value string
	if !runField(huh.NewInput().Title(title).EchoMode(huh.EchoModePassword).Value(&value)) {
		return ""
	}
	return value
}

// tuiNote shows a short message: on the settings page it becomes the
// page notice; elsewhere it prints.
func tuiNote(title string, description string) {
	if tuiInPage {
		tuiNotice = title
		if description != "" {
			tuiNotice += ": " + description
		}
		return
	}
	fmt.Printf("\n  %s\n  %s\n\n", title, description)
}

// noteCancelled prints the picker's cancel line, except inside the settings
// page where the alt screen would leave it as stray output after exit.
func noteCancelled() {
	if !tuiInPage {
		fmt.Println("Cancelled.")
	}
}
