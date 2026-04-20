package main

import (
	"os"
	"sync"
)

// Harness abstracts the AI coding CLI that yolonot integrates with.
// Adapters translate between each harness's native hook protocol and
// yolonot's canonical internal shape (HookPayload / HookResponse).
//
// The canonical shape happens to match Claude Code's hook protocol — Claude
// was the first supported harness and the rest of yolonot (tests, pipeline,
// pre-check chain) grew around its JSON. Non-Claude adapters marshal into
// the canonical shape at the hook boundary and marshal back out again when
// emitting responses.
type Harness interface {
	// Name returns a stable identifier ("claude", "codex", "opencode").
	Name() string

	// SettingsPath returns the path to the harness's config/settings file
	// that yolonot mutates during install/uninstall.
	SettingsPath() string

	// SessionIDFromEnv returns the active session id from the harness's
	// env var (e.g. CLAUDE_SESSION_ID). Empty if not set.
	SessionIDFromEnv() string

	// ParseHookInput converts the harness's native hook JSON on stdin
	// (with env-var fallback if stdin is empty) into the canonical
	// HookPayload. Returning a zero payload with no error is valid and
	// means "ignore this event" — cmdHook will exit without output.
	ParseHookInput(stdin []byte) (HookPayload, error)

	// FormatHookResponse converts a canonical HookResponse into the
	// harness's native JSON output.
	FormatHookResponse(r HookResponse) string

	// IsInstalled reports whether yolonot is currently registered in this
	// harness's settings.
	IsInstalled() bool

	// Install registers yolonot's hook binary. Idempotent — reinstalling
	// should strip old entries first.
	Install(binaryPath string) error

	// Uninstall removes yolonot's hook registration.
	Uninstall() error

	// InstallSkill writes any harness-specific skill/doc bundle. Returns
	// the path written, or empty if the harness has no skill concept.
	InstallSkill() (string, error)

	// UninstallSkill removes the skill bundle. Safe to call when absent.
	UninstallSkill() error

	// IsDetected returns true if this harness appears to be present on
	// the system (settings dir exists, CLI on PATH, etc.). Used to pick
	// the default install target when the user doesn't pass --harness.
	IsDetected() bool

	// RiskMap returns this harness's default mapping from risk tier to
	// final action. Keys are the canonical tiers (safe|low|moderate|high|
	// critical); values are one of "allow", "ask", "deny", "passthrough".
	// "passthrough" means emit an empty hook response and let the host's
	// own permission engine handle the command. User config and env vars
	// layer on top via ResolveRiskMap.
	RiskMap() map[string]string

	// PostInstallNotes returns harness-specific caveats to print after
	// `yolonot install`. Each element becomes a bullet in the install
	// summary. Empty slice when there's nothing to say — Claude is the
	// canonical shape and has no surprises; adapters that diverge (Gemini
	// needs --yolo, Codex/OpenCode can't emit "ask") declare them here.
	PostInstallNotes() []string
}

// Action constants for risk-map values. Kept alongside the interface so
// harness implementations don't have to re-declare them.
const (
	ActionAllow       = "allow"
	ActionAsk         = "ask"
	ActionDeny        = "deny"
	ActionPassthrough = "passthrough" // emit empty response, defer to host's native permission engine
)

// registeredHarnesses is the ordered list of adapters yolonot knows about.
// Registration order matters for ActiveHarness() fallback: earlier entries
// win ties. Access is guarded by harnessMu — init() writes are serialized
// by the Go runtime, but tests mutate the slice via unregisterHarness and
// that races readers (classifier_test.go:173 uses [:0] aliasing which
// would corrupt a concurrent read).
var (
	harnessMu           sync.RWMutex
	registeredHarnesses []Harness
)

// RegisterHarness adds an adapter to the registry. Called from each
// adapter's init().
func RegisterHarness(h Harness) {
	harnessMu.Lock()
	defer harnessMu.Unlock()
	registeredHarnesses = append(registeredHarnesses, h)
}

// Harnesses returns a snapshot of registered adapters in registration
// order. The caller owns the returned slice — safe to iterate without
// holding the mutex.
func Harnesses() []Harness {
	harnessMu.RLock()
	defer harnessMu.RUnlock()
	out := make([]Harness, len(registeredHarnesses))
	copy(out, registeredHarnesses)
	return out
}

// GetHarness returns the adapter with the given name, or nil.
func GetHarness(name string) Harness {
	harnessMu.RLock()
	defer harnessMu.RUnlock()
	for _, h := range registeredHarnesses {
		if h.Name() == name {
			return h
		}
	}
	return nil
}

// ActiveHarness returns the adapter yolonot should route hook traffic
// through. Resolution:
//  1. YOLONOT_HARNESS env var (explicit override)
//  2. First registered adapter whose SessionIDFromEnv() is non-empty
//  3. Claude (historical default)
//  4. First registered adapter (last-resort)
//
// Returns nil only if nothing is registered.
func ActiveHarness() Harness {
	if name := os.Getenv("YOLONOT_HARNESS"); name != "" {
		if h := GetHarness(name); h != nil {
			return h
		}
	}
	list := Harnesses()
	for _, h := range list {
		if h.SessionIDFromEnv() != "" {
			return h
		}
	}
	if h := GetHarness("claude"); h != nil {
		return h
	}
	if len(list) > 0 {
		return list[0]
	}
	return nil
}

// GetSessionIDFromEnv returns the first non-empty session id exposed by a
// registered harness. CLI commands (pause/resume/status) use this so they
// don't need to know which harness spawned them.
func GetSessionIDFromEnv() string {
	for _, h := range Harnesses() {
		if sid := h.SessionIDFromEnv(); sid != "" {
			return sid
		}
	}
	return ""
}

// IsInstalled reports whether yolonot is registered in at least one
// harness. Preserves the pre-refactor API — when only Claude was supported,
// this was the Claude-specific check.
func IsInstalled() bool {
	for _, h := range Harnesses() {
		if h.IsInstalled() {
			return true
		}
	}
	return false
}
