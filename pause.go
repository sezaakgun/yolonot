package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// pauseFile returns the path to the pause marker for a session.
func pauseFile(sessionID string) string {
	return filepath.Join(YolonotDir(), "sessions", sessionID+".paused")
}

// isPaused returns true if yolonot is paused for the given session.
func isPaused(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	_, err := os.Stat(pauseFile(sessionID))
	return err == nil
}

func currentSessionID() string {
	sid := os.Getenv("CLAUDE_SESSION_ID")
	if sid == "" {
		sid = FindSessionID()
	}
	return sid
}

func cmdPause() {
	sid := currentSessionID()
	if sid == "" {
		fmt.Println("No active session found.")
		return
	}

	os.MkdirAll(filepath.Join(YolonotDir(), "sessions"), 0755)
	if err := os.WriteFile(pauseFile(sid), []byte{}, 0644); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("yolonot paused for session %s\n", sid)
	fmt.Println("All commands bypass yolonot (no rules, no LLM, no session memory).")
	fmt.Println("Run 'yolonot resume' to re-enable.")
}

func cmdResume() {
	sid := currentSessionID()
	if sid == "" {
		fmt.Println("No active session found.")
		return
	}

	if !isPaused(sid) {
		fmt.Println("yolonot is not paused.")
		return
	}

	if err := os.Remove(pauseFile(sid)); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("yolonot resumed for session %s\n", sid)
}
