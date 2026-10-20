package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func init() { RegisterHarness(newClaudeHarness()) }

// ClaudeHarness is the Claude Code adapter. It is the historical default
// and the canonical hook protocol — HookPayload / HookResponse are shaped
// after Claude's JSON, so Parse/Format are near-passthrough.
type ClaudeHarness struct {
	baseHarness
}

func newClaudeHarness() *ClaudeHarness {
	h := &ClaudeHarness{
		baseHarness: baseHarness{
			name:           "claude",
			supportsAsk:    true,
			riskMap:        claudeCompatRiskMap(),
			sessionEnvKeys: []string{"YOLONOT_CLAUDE_SESSION_ID", "CLAUDE_SESSION_ID"},
			configDirFn:    claudeConfigDir,
			settingsPathFn: func() string {
				return filepath.Join(claudeConfigDir(), "settings.json")
			},
			isDetectedFn: func() bool {
				_, err := os.UserHomeDir()
				return err == nil
			},
			parseFn: func(input []byte) (HookPayload, error) {
				if len(input) == 0 {
					if toolInput := os.Getenv("CLAUDE_TOOL_INPUT"); toolInput != "" {
						input = []byte(fmt.Sprintf(
							`{"hook_event_name":"%s","tool_name":"%s","session_id":"%s","tool_input":%s}`,
							envOr("CLAUDE_HOOK_EVENT_NAME", "PreToolUse"),
							envOr("CLAUDE_TOOL_NAME", "Bash"),
							envOr("CLAUDE_SESSION_ID", "unknown"),
							toolInput))
					}
				}
				return parseFlexibleHookPayload(input)
			},
			formatFn: func(r HookResponse) string {
				data, _ := json.Marshal(r)
				return string(data)
			},
			notes: []string{
				"Claude Desktop: add model API-key variables in Local > gear, then start a new session; shell-profile exports may not reach hooks or mods.",
				"Rule/exec success does not prove model access. Check model failures in yolonot log and your failure policy; see docs/harnesses.md#claude-desktop-model-credentials.",
			},
		},
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName:     "claude",
		events:          []string{"PreToolUse", "PostToolUse"},
		matcher:         "Bash|PowerShell",
		matchAnyYolonot: true,
		buildEntry: func(event, binaryPath string) map[string]interface{} {
			// Claude 2.1.295+ runs exec-form handlers, which keep paths literal on
			// Bash and PowerShell hosts and block if the safety gate cannot start,
			// crashes, times out, or emits malformed output. An older Claude ignores
			// args and would run bare yolonot, which prints status and allows.
			entry := map[string]interface{}{"type": "command", "timeout": 60.0}
			if event == "PreToolUse" {
				entry["onFailure"] = "block"
			}
			if claudeSupportsExecHooks() {
				entry["command"], entry["args"] = binaryPath, []string{"hook", "--harness", "claude"}
			} else {
				entry["command"] = shellHookCommand(binaryPath, "claude")
			}
			return entry
		},
	})
	return h
}

func claudeConfigDir() string {
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude")
}

var claudeSupportsExecHooks = func() bool {
	path, err := harnessBinary("claude")
	if err != nil {
		return false
	}
	return versionAtLeast(harnessVersion("claude", path), [3]int{2, 1, 295})
}

// versionAtLeast reads the first dotted version in s ("2.1.300 (Claude Code)").
func versionAtLeast(s string, want [3]int) bool {
	m := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`).FindStringSubmatch(s)
	if m == nil {
		return false
	}
	for i, w := range want {
		n, _ := strconv.Atoi(m[i+1])
		if n != w {
			return n > w
		}
	}
	return true
}

// Command hooks are shell strings. Quote paths so spaces, quotes and shell
// metacharacters in an installation directory stay literal.
func shellHookCommand(binary, harness string) string {
	return "'" + strings.ReplaceAll(binary, "'", "'\\''") + "' hook --harness " + harness
}

// --- Package-level helpers kept for back-compat with existing tests ---
//
// Pre-refactor, tests reached for `loadSettings()` / `settingsPath()` as
// package globals. These wrappers delegate to the Claude adapter so the
// test surface doesn't change.

func claudeAdapter() *ClaudeHarness {
	if h, ok := GetHarness("claude").(*ClaudeHarness); ok {
		return h
	}
	return newClaudeHarness()
}

func loadSettings() map[string]interface{}  { return claudeAdapter().loadSettings() }
func saveSettings(s map[string]interface{}) { claudeAdapter().saveSettings(s) }

// binaryPath returns the path to the running yolonot executable. Used by
// Install() to register the hook command.
func binaryPath() string {
	exe, _ := os.Executable()
	return exe
}

// addHookToEvent inserts a hook into Claude's settings.json "hooks" map
// under the given event + matcher. Placed before any ".*" catch-all so
// yolonot's pre-check runs first.
//
// Exposed at package scope because it mutates the generic map Claude uses —
// keeping it outside the struct lets tests that construct a raw map
// exercise the ordering logic directly.
func addHookToEvent(hooks map[string]interface{}, event, matcher string, hook map[string]interface{}) {
	entries, _ := hooks[event].([]interface{})

	for _, entry := range entries {
		if e, ok := entry.(map[string]interface{}); ok {
			if m, _ := e["matcher"].(string); m == matcher {
				hs, _ := e["hooks"].([]interface{})
				e["hooks"] = append(hs, hook)
				return
			}
		}
	}

	newEntry := map[string]interface{}{
		"matcher": matcher,
		"hooks":   []interface{}{hook},
	}
	insertIdx := len(entries)
	for i, entry := range entries {
		if e, ok := entry.(map[string]interface{}); ok {
			if m, _ := e["matcher"].(string); m == ".*" {
				insertIdx = i
				break
			}
		}
	}
	entries = append(entries, nil)
	copy(entries[insertIdx+1:], entries[insertIdx:])
	entries[insertIdx] = newEntry
	hooks[event] = entries
}
