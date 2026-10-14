package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() { RegisterHarness(&GeminiHarness{}) }

// GeminiHarness is the Google Gemini CLI adapter.
//
// Gemini's hook protocol (checked against google-gemini/gemini-cli@v0.63.0;
// local CLI version 0.46.0):
//   - Settings live in ~/.gemini/settings.json (shared file, like Claude's —
//     merge-preserve other top-level keys).
//   - Events: "BeforeTool" / "AfterTool" (no "Use" suffix).
//   - Shell tool name: "run_shell_command" (not "Bash").
//   - Matcher is a regex against tool name; anchor with ^...$ to avoid
//     matching other tools.
//   - Timeout is in milliseconds (Claude uses seconds).
//   - Stdin payload is snake_case with the same field names as the canonical
//     HookPayload, so ParseHookInput only needs to translate the event +
//     tool-name aliases.
//   - Stdout response is FLAT: {"decision":"...","reason":"...","systemMessage":"..."}
//     — not nested under hookSpecificOutput like Claude's.
//   - Crucially, Gemini supports "ask" end-to-end (hooks/types.ts:130-136 +
//     scheduler.ts:624-660) → it fires the native TUI confirmation prompt.
//     This adapter emits ask directly; Codex and OpenCode integrations
//     instead defer ask to their host.
//   - Stdout hygiene: the final JSON must be the ONLY thing on stdout;
//     anything else fails OPEN. Log to stderr via Verbosef only.
type GeminiHarness struct{}

func (g *GeminiHarness) Name() string { return "gemini" }

func (g *GeminiHarness) SupportsAsk() bool { return true }

// RiskMap is Gemini's default tier→action policy. Gemini supports "ask"
// end-to-end (native TUI confirmation prompt), so every non-allow tier
// escalates to ask — deny stays rule-origin only. Same invariant as
// Claude: an LLM-emitted "critical" stops the command for user review,
// it does not kill it. If the user wants hard denial they write a rule.
// (Caveat: without --yolo the host prompts anyway, so yolonot's "allow"
// is cosmetic in that mode — see memory: gemini_yolo_requirement.)
func (g *GeminiHarness) RiskMap() map[string]string {
	return map[string]string{
		RiskSafe:     ActionAllow,
		RiskLow:      ActionAllow,
		RiskModerate: ActionAsk,
		RiskHigh:     ActionAsk,
		RiskCritical: ActionAsk,
	}
}

func (g *GeminiHarness) SettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gemini", "settings.json")
}

// SessionIDFromEnv honours YOLONOT_GEMINI_SESSION_ID as a user override.
// Gemini does not export its session id as an env var (hookRunner.ts:347-353
// sets GEMINI_PROJECT_DIR and CLAUDE_PROJECT_DIR for compat, but not a
// session id). Session ids only arrive via stdin.
func (g *GeminiHarness) SessionIDFromEnv() string {
	return os.Getenv("YOLONOT_GEMINI_SESSION_ID")
}

// ParseHookInput decodes Gemini's stdin JSON into the canonical HookPayload
// and normalises Gemini's event- and tool-name aliases so the rest of
// yolonot (rule engine, fast-allow, session) sees Claude-shaped values.
func (g *GeminiHarness) ParseHookInput(input []byte) (HookPayload, error) {
	if len(input) == 0 {
		return HookPayload{}, nil
	}
	var p HookPayload
	if err := json.Unmarshal(input, &p); err != nil {
		return HookPayload{}, err
	}
	switch p.HookEventName {
	case "BeforeTool":
		p.HookEventName = "PreToolUse"
	case "AfterTool":
		p.HookEventName = "PostToolUse"
	}
	if p.ToolName == "run_shell_command" {
		p.ToolName = "Bash"
	}
	return p, nil
}

// geminiResponse is the flat wire shape Gemini's scheduler expects. The
// three decision values (allow/ask/deny) are spelled identically to the
// canonical set, so only the envelope changes.
type geminiResponse struct {
	Decision      string `json:"decision"`
	Reason        string `json:"reason,omitempty"`
	SystemMessage string `json:"systemMessage,omitempty"`
}

// FormatHookResponse translates the canonical nested HookResponse into
// Gemini's flat wire shape. An empty decision produces empty output, same
// as Codex — Gemini treats empty stdout as implicit allow, and emitting a
// bare `{"decision":""}` would fail-open on the parser.
func (g *GeminiHarness) FormatHookResponse(r HookResponse) string {
	decision := r.HookSpecificOutput.PermissionDecision
	if decision == "" {
		return ""
	}
	out := geminiResponse{
		Decision:      decision,
		Reason:        r.HookSpecificOutput.PermissionDecisionReason,
		SystemMessage: r.SystemMessage,
	}
	data, _ := json.Marshal(out)
	return string(data)
}

func (g *GeminiHarness) IsInstalled() bool {
	s := g.loadSettings()
	hooks, _ := s["hooks"].(map[string]interface{})
	pre, _ := hooks["BeforeTool"].([]interface{})
	for _, entry := range pre {
		e, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		hs, _ := e["hooks"].([]interface{})
		for _, h := range hs {
			hm, ok := h.(map[string]interface{})
			if !ok {
				continue
			}
			if cmd, ok := hm["command"].(string); ok && strings.Contains(cmd, "yolonot") {
				return true
			}
		}
	}
	return false
}

// geminiMatcher anchors against the shell tool name so BeforeTool hooks
// for non-shell tools (read_file, write_file, MCP calls, …) don't land in
// yolonot, which is Bash-only.
const geminiMatcher = "^run_shell_command$"

func (g *GeminiHarness) Install(binaryPath string) error {
	s, err := g.readSettings()
	if err != nil {
		return err
	}
	stripGeminiHooks(s)
	hooks, _ := s["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = map[string]interface{}{}
		s["hooks"] = hooks
	}

	// Pin --harness gemini so ActiveHarness() routes through this adapter.
	// Without it, the default harness is Claude, which emits the nested
	// hookSpecificOutput envelope — Gemini would fail-open on that.
	// Timeout is milliseconds in Gemini's schema (Claude uses seconds).
	bp := binaryPath + " hook --harness gemini"
	preHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 60000.0}
	postHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 60000.0}

	addHookToEvent(hooks, "BeforeTool", geminiMatcher, preHook)
	addHookToEvent(hooks, "AfterTool", geminiMatcher, postHook)

	if err := g.saveSettings(s); err != nil {
		return err
	}
	Verbosef("wrote %s (%s matcher for BeforeTool + AfterTool, timeout 60000ms)", g.SettingsPath(), geminiMatcher)
	return nil
}

func (g *GeminiHarness) Uninstall() error {
	Verbosef("stripping yolonot hooks from %s", g.SettingsPath())
	return g.removeHooks()
}

func geminiSkillDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gemini", "skills", "yolonot")
}

func (g *GeminiHarness) InstallSkill() (string, error) {
	return installHarnessSkill(g.Name(), geminiSkillDir())
}

func (g *GeminiHarness) UninstallSkill() error {
	return uninstallHarnessSkill(geminiSkillDir())
}

// PostInstallNotes warns about Gemini's --yolo requirement. Without YOLO
// mode, Gemini always prompts the user before running a shell tool, and
// yolonot's "allow" decision is effectively cosmetic — the user still
// confirms manually. Detection tries to read settings.json; if YOLO is
// already the default, the note is suppressed.
func (g *GeminiHarness) PostInstallNotes() []string {
	if g.yoloAlreadyDefault() {
		return nil
	}
	return []string{
		"Launch Gemini with `gemini --yolo` (or set general.defaultApprovalMode=\"yolo\" in ~/.gemini/settings.json).",
		"Without YOLO mode Gemini prompts on every shell command regardless of yolonot's decision — allow becomes cosmetic.",
	}
}

// yoloAlreadyDefault checks ~/.gemini/settings.json for
// general.defaultApprovalMode == "yolo". Any parse/IO error is treated as
// "not set" — the warning is cheap, false positives are fine.
func (g *GeminiHarness) yoloAlreadyDefault() bool {
	s := g.loadSettings()
	general, _ := s["general"].(map[string]interface{})
	mode, _ := general["defaultApprovalMode"].(string)
	return mode == "yolo"
}

// IsDetected returns true if ~/.gemini exists. Unlike Claude, we don't
// optimistically create the dir — if the user hasn't used Gemini CLI yet,
// yolonot shouldn't pick it as an install target.
func (g *GeminiHarness) IsDetected() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(home, ".gemini"))
	return err == nil
}

func (g *GeminiHarness) loadSettings() map[string]interface{} {
	s, _ := g.readSettings()
	if s == nil {
		return map[string]interface{}{}
	}
	return s
}

func (g *GeminiHarness) readSettings() (map[string]interface{}, error) {
	data, err := os.ReadFile(g.SettingsPath())
	if os.IsNotExist(err) {
		return map[string]interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s map[string]interface{}
	if err := json.Unmarshal(data, &s); err != nil || s == nil {
		return nil, fmt.Errorf("%s: expected a valid JSON object", g.SettingsPath())
	}
	if err := uniqueJSONFields(data); err != nil {
		return nil, err
	}
	if value, exists := s["hooks"]; exists {
		hooks, ok := value.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s: hooks must be an object", g.SettingsPath())
		}
		for _, event := range []string{"BeforeTool", "AfterTool"} {
			if value, exists := hooks[event]; exists && value != nil {
				if _, ok := value.([]interface{}); !ok {
					return nil, fmt.Errorf("%s: hooks.%s must be an array", g.SettingsPath(), event)
				}
			}
		}
	}
	return s, nil
}

func (g *GeminiHarness) saveSettings(s map[string]interface{}) error {
	data, _ := json.MarshalIndent(s, "", "  ")
	perm := os.FileMode(0600)
	if info, err := os.Stat(g.SettingsPath()); err == nil {
		perm = info.Mode().Perm()
	}
	return atomicWriteFile(g.SettingsPath(), append(data, '\n'), perm)
}

func (g *GeminiHarness) removeHooks() error {
	s, err := g.readSettings()
	if err != nil {
		return err
	}
	stripGeminiHooks(s)
	return g.saveSettings(s)
}

func stripGeminiHooks(s map[string]interface{}) {
	hooks, _ := s["hooks"].(map[string]interface{})

	for _, event := range []string{"BeforeTool", "AfterTool"} {
		entries, _ := hooks[event].([]interface{})
		var newEntries []interface{}
		for _, entry := range entries {
			e, ok := entry.(map[string]interface{})
			if !ok {
				newEntries = append(newEntries, entry)
				continue
			}
			hs, ok := e["hooks"].([]interface{})
			if !ok {
				newEntries = append(newEntries, entry)
				continue
			}
			var remaining []interface{}
			for _, h := range hs {
				if hm, ok := h.(map[string]interface{}); ok {
					if cmd, _ := hm["command"].(string); strings.Contains(cmd, "yolonot") {
						continue
					}
				}
				remaining = append(remaining, h)
			}
			if len(remaining) > 0 {
				e["hooks"] = remaining
				newEntries = append(newEntries, e)
			}
		}
		if len(newEntries) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = newEntries
		}
	}
}
