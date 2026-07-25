package yolonot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// pauseFile returns the path to the pause marker for a session. Returns
// empty for invalid IDs so a hostile --session-id can't escape the
// sessions/ dir via path traversal.
func pauseFile(sessionID string) string {
	if !IsValidSessionID(sessionID) {
		return ""
	}
	return filepath.Join(YolonotDir(), "sessions", sessionID+".paused")
}

// isPaused returns true if yolonot is paused for the given session.
func isPaused(sessionID string) bool {
	if !IsValidSessionID(sessionID) {
		return false
	}
	_, err := os.Stat(pauseFile(sessionID))
	return err == nil
}

// bypassReason reports why yolonot is standing down for this invocation:
//
//	"env"                — YOLONOT_DISABLED=1, the pre-launch escape hatch
//	"bypass-permissions" — the host is already skipping its own permission engine
//	"global"             — `yolonot pause --global` (Config.Disabled)
//	"session"            — `yolonot pause` marker for this session
//
// Empty means yolonot is active. Ordered most explicit first: the env var
// has to win even when config.json is unreadable, and the narrowest scope
// (a single session) is checked last. A zero Config — what LoadConfig
// returns for a missing or corrupt file — yields no bypass, so a broken
// config fails safe rather than silently disabling the safety layer.
func bypassReason(cfg Config, payload HookPayload) string {
	if os.Getenv("YOLONOT_DISABLED") == "1" {
		return "env"
	}
	if payload.PermissionMode == "bypassPermissions" {
		return "bypass-permissions"
	}
	if cfg.Disabled {
		return "global"
	}
	if isPaused(payload.SessionID) {
		return "session"
	}
	return ""
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

// hasGlobalFlag reports whether --global was passed. The flag switches
// pause/resume from one session to the persistent, machine-wide switch.
func hasGlobalFlag(args []string) bool {
	for _, a := range args {
		if a == "--global" {
			return true
		}
	}
	return false
}

// hasSessionFlag reports whether a session-targeting flag was passed, so
// `pause --global --current` can say the session flag was ignored rather
// than silently doing something other than what was typed.
func hasSessionFlag(args []string) bool {
	for _, a := range args {
		if a == "--current" || a == "--session-id" || strings.HasPrefix(a, "--session-id=") {
			return true
		}
	}
	return false
}

// cmdPauseGlobal sets the persistent global kill switch. Unlike the session
// marker this never expires — it is off until `yolonot resume --global`.
func cmdPauseGlobal(args []string) {
	if hasSessionFlag(args) {
		fmt.Println("Note: --global is machine-wide; the session flag was ignored.")
	}

	if !hasConfirmBypass(args) {
		fmt.Println("yolonot: --global disables the safety layer for EVERY session, current and future.")
		fmt.Println("  Prefer: yolonot approve '<exact command>' — unblocks one command only.")
		fmt.Println("  This session only: yolonot pause --current --confirm-bypass")
		fmt.Println("  If you really want to disable yolonot everywhere:")
		fmt.Println("    yolonot pause --global --confirm-bypass")
		return
	}

	cfg := LoadConfig()
	if cfg.Disabled {
		fmt.Println("yolonot is already globally disabled.")
		fmt.Println("Run 'yolonot resume --global' to re-enable.")
		return
	}

	cfg.Disabled = true
	SaveConfig(cfg)

	// SaveConfig reports failure only through Verbosef, so confirm the flag
	// actually reached disk before claiming it in the audit log.
	if !LoadConfig().Disabled {
		fmt.Fprintln(os.Stderr, "Error: could not write config — yolonot is still active.")
		fmt.Fprintln(os.Stderr, "Re-run with -v to see the underlying write error.")
		return
	}

	// Log the switch so an audit can spot the safety layer going off, and
	// pair it with the resume entry to measure how long it stayed off.
	LogDecision(DecisionEntry{
		SessionID: resolveSessionID(args), Command: "yolonot pause --global", Cwd: ".",
		Layer: "pause", Decision: "bypass_enabled",
		Reasoning: "global pause via --confirm-bypass",
	})

	fmt.Println("yolonot globally disabled — every session, current and future.")
	fmt.Println("All commands bypass yolonot (no rules, no LLM, no session memory).")
	fmt.Println("Run 'yolonot resume --global' to re-enable.")
}

// cmdResumeGlobal clears the global kill switch. Session pause markers are
// deliberately left alone — the two scopes are independent.
func cmdResumeGlobal() {
	cfg := LoadConfig()
	if !cfg.Disabled {
		fmt.Println("yolonot is not globally disabled.")
		return
	}

	cfg.Disabled = false
	SaveConfig(cfg)

	if LoadConfig().Disabled {
		fmt.Fprintln(os.Stderr, "Error: could not write config — yolonot is still globally disabled.")
		fmt.Fprintln(os.Stderr, "Re-run with -v to see the underlying write error.")
		return
	}

	LogDecision(DecisionEntry{
		Command: "yolonot resume --global", Cwd: ".",
		Layer: "pause", Decision: "bypass_disabled",
		Reasoning: "global pause cleared",
	})

	fmt.Println("yolonot re-enabled globally.")
}

func cmdPause(args []string) {
	if hasGlobalFlag(args) {
		cmdPauseGlobal(args)
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
		SessionID: sid, Command: "yolonot pause", Cwd: ".", Layer: "pause",
		Decision: "bypass_enabled", Reasoning: "session paused via --confirm-bypass",
	})

	fmt.Printf("yolonot paused for session %s\n", sid)
	fmt.Println("All commands bypass yolonot (no rules, no LLM, no session memory).")
	fmt.Println("Run 'yolonot resume' to re-enable.")
}

func cmdResume(args []string) {
	if hasGlobalFlag(args) {
		cmdResumeGlobal()
		return
	}

	sid := resolveSessionID(args)
	if sid == "" {
		printSessionIDError("resume")
		return
	}

	if !isPaused(sid) {
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

	// Without this the user resumes, sees nothing change, and concludes
	// yolonot is broken — the global switch is still holding it off.
	if LoadConfig().Disabled {
		fmt.Println("Note: yolonot is still globally disabled — run: yolonot resume --global")
	}
}
