package yolonot

import (
	"errors"
	"fmt"

	"github.com/charmbracelet/bubbles/key"
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
func runField(f huh.Field) bool {
	km := huh.NewDefaultKeyMap()
	km.Quit = key.NewBinding(key.WithKeys("ctrl+c", "esc"))
	form := huh.NewForm(huh.NewGroup(f)).WithKeyMap(km).WithShowHelp(false)
	tuiClear()
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
	selected := 0
	if defaultIdx >= 0 && defaultIdx < len(items) {
		selected = defaultIdx
	}
	fields, ok := runMenu(title, "", []menuField{{Items: items, Cur: selected}})
	if !ok {
		return -1
	}
	return fields[0].Cur
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
	fields, ok := runMenu(prompt, "y / n, or click", []menuField{{Items: []string{"Yes", "No"}, Cur: 1}})
	return ok && fields[0].Cur == 0
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

// tuiClear wipes the shared alternate screen before a program draws; a
// no-op outside the settings page, where programs run inline.
func tuiClear() {
	if tuiInPage {
		fmt.Print("\x1b[2J\x1b[H")
	}
}
