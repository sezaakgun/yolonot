package yolonot

import (
	"fmt"

	"github.com/charmbracelet/huh"
)

// tuiSelect presents an interactive arrow-key menu and returns the selected index.
// Returns -1 if the user cancels (Ctrl+C, Esc).
// Falls back to returning defaultIdx when stdin is not a terminal (piped input).
func tuiSelect(title string, items []string, defaultIdx int) int {
	if len(items) == 0 {
		return -1
	}

	options := make([]huh.Option[int], len(items))
	for i, item := range items {
		options[i] = huh.NewOption(item, i)
	}

	var selected int
	if defaultIdx >= 0 && defaultIdx < len(items) {
		selected = defaultIdx
	}

	err := huh.NewSelect[int]().
		Title(title).
		Options(options...).
		Value(&selected).
		Run()

	if err != nil {
		return -1
	}
	return selected
}

// tuiInput prompts for text input with an optional default value.
// Returns the entered string, or empty on cancel.
func tuiInput(title string, placeholder string, defaultVal string) string {
	var value string
	if defaultVal != "" {
		value = defaultVal
	}

	err := huh.NewInput().
		Title(title).
		Placeholder(placeholder).
		Value(&value).
		Run()

	if err != nil {
		return ""
	}
	return value
}

// tuiConfirm shows a y/n prompt. Returns true for yes.
func tuiConfirm(prompt string) bool {
	var confirmed bool
	err := huh.NewConfirm().
		Title(prompt).
		Value(&confirmed).
		Run()

	if err != nil {
		return false
	}
	return confirmed
}

// tuiPassword prompts for sensitive input (API keys). Hidden characters.
func tuiPassword(title string) string {
	var value string
	err := huh.NewInput().
		Title(title).
		EchoMode(huh.EchoModePassword).
		Value(&value).
		Run()

	if err != nil {
		return ""
	}
	return value
}

// tuiNote displays a styled message.
func tuiNote(title string, description string) {
	fmt.Printf("\n  %s\n  %s\n\n", title, description)
}
