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
// --current flag (most recent session), then the active harness's session
// env var (CLAUDE_SESSION_ID, CODEX_SESSION_ID, ...). Returns empty if none
// is set.
func resolveSessionID(args []string) string {
	for i, a := range args {
		if a == "--session-id" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "--session-id=") {
			return strings.TrimPrefix(a, "--session-id=")
		}
		if a == "--current" {
			return FindSessionID()
		}
	}
	return GetSessionIDFromEnv()
}

func printSessionIDError(verb string) {
	fmt.Println("Error: session ID not provided.")
	fmt.Println()
	fmt.Printf("Use --current (most recent session), --session-id, or CLAUDE_SESSION_ID:\n")
	fmt.Printf("  yolonot %s --current\n", verb)
	fmt.Printf("  yolonot %s --session-id <uuid>\n", verb)
	fmt.Printf("  CLAUDE_SESSION_ID=<uuid> yolonot %s\n", verb)
	fmt.Println()
	fmt.Println("Inside Claude Code, use /yolonot", verb, "instead.")
}

// hasConfirmBypass returns true if the caller explicitly opted into
// bypassing yolonot via --confirm-bypass flag or YOLONOT_CONFIRM_BYPASS=1
// env var. Required for pause because pause is a total safety-layer
// disable: an agent reaching for pause to work around a blocked command
// should fail here unless the user typed the opt-in themselves.
func hasConfirmBypass(args []string) bool {
	for _, a := range args {
		if a == "--confirm-bypass" || a == "--i-understand" {
			return true
		}
	}
	return os.Getenv("YOLONOT_CONFIRM_BYPASS") == "1"
}

func cmdPause(args []string) {
	sid := resolveSessionID(args)
	if sid == "" {
		printSessionIDError("pause")
		return
	}

	if !hasConfirmBypass(args) {
		fmt.Println("yolonot: pause is a total safety-layer bypass.")
		fmt.Println("  Prefer: yolonot approve '<exact command>' — unblocks one command only.")
		fmt.Println("  If you really want to disable yolonot for this session:")
		fmt.Println("    yolonot pause --current --confirm-bypass")
		return
	}

	os.MkdirAll(filepath.Join(YolonotDir(), "sessions"), 0755)
	if err := os.WriteFile(pauseFile(sid), []byte{}, 0644); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Log pause activation so audits can spot agents disabling the safety
	// layer. DecisionEntry.Layer="pause" makes this grep-able alongside
	// regular decisions.
	LogDecision(DecisionEntry{
		SessionID: sid, Command: "yolonot pause", Cwd: ".", Layer: "pause",
		Decision: "bypass_enabled", Reasoning: "session paused via --confirm-bypass",
	})

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
