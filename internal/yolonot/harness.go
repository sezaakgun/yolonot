package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/syntax"
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
	// the path written, or empty if skill installation is unavailable.
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
	// needs --yolo or hooks require trust review) declare them here.
	PostInstallNotes() []string
}

// Action constants for risk-map values. Kept alongside the interface so
// harness implementations don't have to re-declare them.
const (
	ActionAllow       = "allow"
	ActionForceAllow  = "force_allow" // override even a classifier "ask" to "allow" (non-critical tiers only)
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

// supportedHarnesses excludes retired adapters from new installations.
// Legacy adapters remain registered so existing hooks and config can be
// inspected and safely uninstalled during migration.
func supportedHarnesses() []Harness {
	var out []Harness
	for _, h := range Harnesses() {
		if h.Name() != "gemini" {
			out = append(out, h)
		}
	}
	return out
}

func canonicalHarnessName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "agy":
		return "antigravity"
	case "qwen-code", "qwencode":
		return "qwen"
	case "z-code":
		return "zcode"
	case "github-copilot", "gh-copilot":
		return "copilot"
	case "grok-build":
		return "grok"
	case "dsh", "deepseek-harness":
		return "deepseek"
	case "hermes-agent":
		return "hermes"
	case "kimi-code", "kimi-cli":
		return "kimi"
	case "devin-cli", "fusion":
		return "devin"
	case "muse-code", "musecode":
		return "muse"
	case "open-hands":
		return "openhands"
	case "kiro-cli":
		return "kiro"
	case "kilocode", "kilo-code":
		return "kilo"
	case "open-claw":
		return "openclaw"
	case "pi-coding-agent":
		return "pi"
	case "reflection-mirror":
		return "mirror"
	case "ampcode":
		return "amp"
	default:
		return name
	}
}

// GetHarness returns the adapter with the given name, or nil.
func GetHarness(name string) Harness {
	name = canonicalHarnessName(name)
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
//  2. First registered non-Claude adapter whose SessionIDFromEnv() is non-empty,
//     then Claude's SessionIDFromEnv() (so hosts that export compatibility
//     CLAUDE_* variables alongside their own session ID resolve to themselves)
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
		if h.Name() != "claude" && h.SessionIDFromEnv() != "" {
			return h
		}
	}
	if h := GetHarness("claude"); h != nil && h.SessionIDFromEnv() != "" {
		return h
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
	list := Harnesses()
	for _, h := range list {
		if h.Name() != "claude" {
			if sid := h.SessionIDFromEnv(); sid != "" {
				return sid
			}
		}
	}
	if h := GetHarness("claude"); h != nil {
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

func harnessUsesPermissionRequest(h Harness) bool {
	if h == nil {
		return false
	}
	if cap, ok := h.(interface{ UsesPermissionRequestPhase() bool }); ok {
		return cap.UsesPermissionRequestPhase()
	}
	return false
}

func harnessAmbiguousPostToolUse(h Harness) bool {
	if h == nil {
		return false
	}
	if cap, ok := h.(interface{ AmbiguousPostToolUse() bool }); ok {
		return cap.AmbiguousPostToolUse()
	}
	return false
}

func harnessExitTwoOnDeny(h Harness) bool {
	if h == nil {
		return false
	}
	if cap, ok := h.(interface{ ExitTwoOnDeny() bool }); ok {
		return cap.ExitTwoOnDeny()
	}
	return false
}

// parseFlexibleHookPayload decodes a hook stdin JSON payload supporting both
// canonical snake_case (Claude/Codex/Qwen/Muse/Devin) and camelCase or
// host-specific field aliases (Grok Build, GitHub Copilot CLI, ZCode, Crush,
// Hermes, Goose, OpenHands, Kiro, Cline).
func parseFlexibleHookPayload(input []byte) (HookPayload, error) {
	if len(input) == 0 {
		return HookPayload{}, nil
	}
	var p HookPayload
	if err := json.Unmarshal(input, &p); err != nil {
		return HookPayload{}, err
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(input, &raw); err != nil {
		return HookPayload{}, err
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := raw[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	if p.HookEventName == "" {
		p.HookEventName = str("hookEventName", "eventName", "event", "event_type", "eventType", "hookName")
	}
	switch p.HookEventName {
	case "preToolUse", "pre_tool_use", "pre_tool_call", "pre_tool", "BeforeTool", "beforeShellExecution", "tool_call":
		p.HookEventName = "PreToolUse"
	case "postToolUse", "post_tool_use", "post_tool_call", "post_tool", "AfterTool", "afterShellExecution", "tool_result":
		p.HookEventName = "PostToolUse"
	case "permissionRequest", "permission_request":
		p.HookEventName = "PermissionRequest"
	}
	if p.HookEventName == "" {
		if _, ok := raw["postToolUse"].(map[string]interface{}); ok {
			p.HookEventName = "PostToolUse"
		} else if _, ok := raw["preToolUse"].(map[string]interface{}); ok {
			p.HookEventName = "PreToolUse"
		}
	}
	if p.ToolName == "" {
		p.ToolName = str("toolName", "tool")
	}
	if p.SessionID == "" {
		p.SessionID = str("sessionId", "conversation_id", "conversationId", "taskId")
	}
	if p.ToolUseID == "" {
		p.ToolUseID = str("toolUseId", "tool_call_id", "toolCallId", "call_id")
	}
	if p.Cwd == "" {
		p.Cwd = str("working_dir", "workingDir", "workdir", "projectDir")
	}
	if p.PermissionMode == "" {
		p.PermissionMode = str("permissionMode")
	}
	if len(p.ToolInput) == 0 {
		for _, k := range []string{"toolInput", "tool_args", "toolArgs", "arguments", "args", "input"} {
			if m, ok := raw[k].(map[string]interface{}); ok && len(m) > 0 {
				p.ToolInput = m
				break
			}
			if s, ok := raw[k].(string); ok && s != "" {
				var m map[string]interface{}
				if json.Unmarshal([]byte(s), &m) == nil && len(m) > 0 {
					p.ToolInput = m
					break
				}
			}
		}
	}
	// Cline nests tool_call / tool_result: {id, name, input} and/or preToolUse / postToolUse: {toolName, parameters}.
	for _, callKey := range []string{"tool_call", "tool_result"} {
		if tc, ok := raw[callKey].(map[string]interface{}); ok {
			if p.ToolName == "" {
				if tn, ok := tc["name"].(string); ok && tn != "" {
					p.ToolName = tn
				}
			}
			if p.ToolUseID == "" {
				if id, ok := tc["id"].(string); ok && id != "" {
					p.ToolUseID = id
				}
			}
			if len(p.ToolInput) == 0 {
				if inp, ok := tc["input"].(map[string]interface{}); ok {
					p.ToolInput = inp
				}
			}
		}
	}
	for _, nestedKey := range []string{"preToolUse", "postToolUse"} {
		if nm, ok := raw[nestedKey].(map[string]interface{}); ok {
			if p.ToolName == "" {
				if tn, ok := nm["toolName"].(string); ok && tn != "" {
					p.ToolName = tn
				} else if tn, ok := nm["tool"].(string); ok && tn != "" {
					p.ToolName = tn
				}
			}
			if len(p.ToolInput) == 0 {
				if params, ok := nm["parameters"].(map[string]interface{}); ok {
					p.ToolInput = params
				}
			}
		}
	}
	if len(p.ToolInput) == 0 {
		if cmd := str("command", "cmd"); cmd != "" {
			p.ToolInput = map[string]interface{}{"command": cmd}
		}
	}
	if p.HookEventName == "" {
		if raw["toolResult"] != nil || raw["tool_result"] != nil || raw["tool_response"] != nil {
			p.HookEventName = "PostToolUse"
		} else if p.ToolName != "" || len(p.ToolInput) > 0 {
			p.HookEventName = "PreToolUse"
		}
	}
	if p.ToolInput != nil {
		var parts []string
		addPart := func(s string) {
			if strings.TrimSpace(s) != "" && (len(parts) == 0 || parts[len(parts)-1] != s) {
				parts = append(parts, s)
			}
		}
		if s, ok := p.ToolInput["command"].(string); ok && strings.TrimSpace(s) != "" {
			addPart(s)
		} else if s, ok := p.ToolInput["cmd"].(string); ok && strings.TrimSpace(s) != "" {
			addPart(s)
		}
		if cmds, ok := p.ToolInput["commands"].([]interface{}); ok && len(cmds) > 0 {
			for _, c := range cmds {
				if cs, ok := c.(string); ok {
					addPart(cs)
				}
			}
		} else if cmdsStr, ok := p.ToolInput["commands"].(string); ok && strings.TrimSpace(cmdsStr) != "" {
			var arr []string
			if json.Unmarshal([]byte(cmdsStr), &arr) == nil && len(arr) > 0 {
				for _, cs := range arr {
					addPart(cs)
				}
			} else {
				addPart(cmdsStr)
			}
		}
		if len(parts) > 0 {
			joined := strings.Join(parts, "\n")
			if len(parts) > 1 {
				for _, part := range parts {
					if _, err := syntax.NewParser().Parse(strings.NewReader(part), ""); err != nil {
						if _, jerr := syntax.NewParser().Parse(strings.NewReader(joined), ""); jerr == nil {
							joined += "\n;;"
						}
						break
					}
				}
			}
			p.ToolInput["command"] = joined
		}
	}
	if p.Cwd == "" {
		if roots, ok := raw["workspaceRoots"].([]interface{}); ok && len(roots) > 0 {
			if r0, ok := roots[0].(string); ok {
				p.Cwd = r0
			}
		} else if roots, ok := raw["workspace_roots"].([]interface{}); ok && len(roots) > 0 {
			if r0, ok := roots[0].(string); ok {
				p.Cwd = r0
			}
		}
	}
	if wd, ok := p.ToolInput["workdir"].(string); ok && wd != "" {
		if !filepath.IsAbs(wd) && p.Cwd != "" {
			p.Cwd = filepath.Join(p.Cwd, wd)
		} else {
			p.Cwd = wd
		}
	} else if wd, ok := p.ToolInput["cwd"].(string); ok && wd != "" {
		if !filepath.IsAbs(wd) && p.Cwd != "" {
			p.Cwd = filepath.Join(p.Cwd, wd)
		} else {
			p.Cwd = wd
		}
	}
	if !p.BypassSandbox {
		p.BypassSandbox = extractToolInputBypassSandbox(p.ToolInput) || extractToolInputBypassSandbox(raw)
	}
	return p, nil
}

