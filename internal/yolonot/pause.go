package yolonot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// globalPauseFile returns the path to the global pause marker file.
func globalPauseFile() string {
	return filepath.Join(YolonotDir(), "paused")
}

// isGloballyPaused returns true if yolonot is paused across all sessions.
func isGloballyPaused() bool {
	_, err := os.Stat(globalPauseFile())
	return err == nil
}

// pauseFile returns the path to the pause marker for a session. Returns
// empty for invalid IDs so a hostile --session-id can't escape the
// sessions/ dir via path traversal.
func pauseFile(sessionID string) string {
	if !IsValidSessionID(sessionID) {
		return ""
	}
	return filepath.Join(YolonotDir(), "sessions", sessionID+".paused")
}

// isPaused returns true if yolonot is paused globally or for the given session.
func isPaused(sessionID string) bool {
	if isGloballyPaused() {
		return true
	}
	if !IsValidSessionID(sessionID) {
		return false
	}
	_, err := os.Stat(pauseFile(sessionID))
	return err == nil
}

func hasGlobalFlag(args []string) bool {
	for _, a := range args {
		if a == "--global" || a == "-g" {
			return true
		}
	}
	return false
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
	fmt.Printf("Use --current (most recent session), --session-id, --global, or CLAUDE_SESSION_ID:\n")
	fmt.Printf("  yolonot %s --current\n", verb)
	fmt.Printf("  yolonot %s --session-id <uuid>\n", verb)
	fmt.Printf("  yolonot %s --global\n", verb)
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

// pausedSessions returns the sorted list of session IDs that currently have a
// .paused marker file in SessionDir(), plus "global" when globally paused.
func pausedSessions() []string {
	var out []string
	if isGloballyPaused() {
		out = append(out, "global")
	}
	entries, err := os.ReadDir(SessionDir())
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".paused") {
			continue
		}
		sid := strings.TrimSuffix(e.Name(), ".paused")
		if IsValidSessionID(sid) {
			out = append(out, sid)
		}
	}
	return out
}

func cmdPause(args []string) {
	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "."
	}

	if hasGlobalFlag(args) {
		if !hasConfirmBypass(args) {
			fmt.Println("yolonot: pause --global is a total safety-layer bypass across all sessions.")
			fmt.Println("  Prefer: yolonot pause --current --confirm-bypass — disables one session only.")
			fmt.Println("  If you really want to disable yolonot globally:")
			fmt.Println("    yolonot pause --global --confirm-bypass")
			return
		}
		if err := os.MkdirAll(YolonotDir(), 0755); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		if err := os.WriteFile(globalPauseFile(), []byte{}, 0644); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		LogDecision(DecisionEntry{
			SessionID: "global", Command: "yolonot pause --global", Cwd: cwd, Layer: "pause",
			Decision: "bypass_enabled", Reasoning: "globally paused via --confirm-bypass",
		})
		fmt.Println("yolonot paused globally across all sessions")
		fmt.Println("All commands bypass yolonot (no rules, no LLM, no session memory).")
		fmt.Println("Run 'yolonot resume --global' to re-enable.")
		return
	}

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

	pf := pauseFile(sid)
	if pf == "" {
		fmt.Printf("Error: invalid session id %q\n", sid)
		return
	}
	os.MkdirAll(filepath.Join(YolonotDir(), "sessions"), 0755)
	if err := os.WriteFile(pf, []byte{}, 0644); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Log pause activation so audits can spot agents disabling the safety
	// layer. DecisionEntry.Layer="pause" makes this grep-able alongside
	// regular decisions.
	LogDecision(DecisionEntry{
		SessionID: sid, Command: "yolonot pause", Cwd: cwd, Layer: "pause",
		Decision: "bypass_enabled", Reasoning: "session paused via --confirm-bypass",
	})

	fmt.Printf("yolonot paused for session %s (project: %s)\n", sid, filepath.Base(cwd))
	fmt.Println("All commands bypass yolonot (no rules, no LLM, no session memory).")
	fmt.Println("Run 'yolonot resume' to re-enable.")
}

func cmdResume(args []string) {
	if hasGlobalFlag(args) {
		if !isGloballyPaused() {
			fmt.Println("yolonot is not paused globally.")
			return
		}
		if err := os.Remove(globalPauseFile()); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Println("yolonot resumed globally")
		return
	}

	sid := resolveSessionID(args)
	if sid == "" {
		if isGloballyPaused() {
			if err := os.Remove(globalPauseFile()); err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
			fmt.Println("yolonot resumed globally")
			return
		}
		printSessionIDError("resume")
		return
	}

	if _, err := os.Stat(pauseFile(sid)); err != nil {
		if isGloballyPaused() {
			fmt.Println("yolonot is paused globally (run: yolonot resume --global).")
			return
		}
		fmt.Println("yolonot is not paused.")
		return
	}

	pf := pauseFile(sid)
	if pf == "" {
		fmt.Printf("Error: invalid session id %q\n", sid)
		return
	}
	if err := os.Remove(pf); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("yolonot resumed for session %s\n", sid)
}
