package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// resolveSessionID resolves the session ID from args (--session-id flag),
// then CLAUDE_SESSION_ID env var. Returns empty if neither is set.
func resolveSessionID(args []string) string {
	for i, a := range args {
		if a == "--session-id" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "--session-id=") {
			return strings.TrimPrefix(a, "--session-id=")
		}
	}
	return os.Getenv("CLAUDE_SESSION_ID")
}

func printSessionIDError(verb string) {
	fmt.Println("Error: session ID not provided.")
	fmt.Println()
	fmt.Printf("Use --session-id flag or set CLAUDE_SESSION_ID env var:\n")
	fmt.Printf("  yolonot %s --session-id <uuid>\n", verb)
	fmt.Printf("  CLAUDE_SESSION_ID=<uuid> yolonot %s\n", verb)
	fmt.Println()
	fmt.Println("Inside Claude Code, use /yolonot", verb, "instead.")
}

func cmdPause(args []string) {
	sid := resolveSessionID(args)
	if sid == "" {
		printSessionIDError("pause")
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

func cmdResume(args []string) {
	sid := resolveSessionID(args)
	if sid == "" {
		printSessionIDError("resume")
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
