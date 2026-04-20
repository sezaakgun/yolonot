package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
)

func init() { RegisterHarness(&OpencodeHarness{}) }

// OpencodeHarness is the sst/opencode adapter.
//
// OpenCode's plugin protocol is TypeScript-native — plugins are ES modules
// loaded at CLI startup from ~/.config/opencode/plugin/*.ts (or
// .opencode/plugin/ in a project). There is no stdin/stdout hook contract.
// We bridge by installing a small TS shim (harness_opencode_plugin.ts,
// embedded via //go:embed) that spawns `yolonot hook` and translates the
// response back into the Error-throw convention OpenCode uses to block a
// tool.execute.before/after call.
//
// Differences from Claude/Codex:
//   - Install writes a TS file, not a JSON settings fragment.
//   - SettingsPath returns the plugin file path (what IsInstalled probes).
//   - No session-id env var — sessions are passed via the plugin hook args
//     and piped into our stdin JSON. SessionIDFromEnv checks the optional
//     YOLONOT_OPENCODE_SESSION_ID override for CLI pause/resume.
//   - No skill concept.
type OpencodeHarness struct{}

func (o *OpencodeHarness) Name() string { return "opencode" }

// RiskMap is OpenCode's default tier→action policy.
//
// Unlike Codex, OpenCode cannot meaningfully "passthrough": its plugin
// API has no native permission-prompt engine, and the embedded shim
// treats empty stdout as "allow" (harness_opencode_plugin.ts:50–52).
// Using ActionPassthrough here would silently promote moderate to allow
// without that intent being visible in the RiskMap. So moderate maps to
// ActionAllow explicitly — same effective behavior, but legible in config
// and overridable via YOLONOT_OPENCODE_RISK_MODERATE=deny for users who
// want a stricter default. High/critical escalate to deny.
func (o *OpencodeHarness) RiskMap() map[string]string {
	return map[string]string{
		RiskSafe:     ActionAllow,
		RiskLow:      ActionAllow,
		RiskModerate: ActionAllow,
		RiskHigh:     ActionDeny,
		RiskCritical: ActionDeny,
	}
}

// SettingsPath returns the path to the installed yolonot plugin file.
// Called "settings" for interface consistency — OpenCode has no single
// settings file; this is the artifact `yolonot install` manages.
func (o *OpencodeHarness) SettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "opencode", "plugin", "yolonot.ts")
}

func (o *OpencodeHarness) SessionIDFromEnv() string {
	return os.Getenv("YOLONOT_OPENCODE_SESSION_ID")
}

// ParseHookInput decodes the canonical stdin JSON that our embedded TS
// plugin hands back to `yolonot hook`. The plugin constructs it in the
// Claude shape (hook_event_name, tool_name, session_id, cwd, tool_input)
// precisely so this adapter can stay a passthrough.
func (o *OpencodeHarness) ParseHookInput(input []byte) (HookPayload, error) {
	if len(input) == 0 {
		return HookPayload{}, nil
	}
	var p HookPayload
	if err := json.Unmarshal(input, &p); err != nil {
		return HookPayload{}, err
	}
	return p, nil
}

// FormatHookResponse emits the canonical Claude-shaped response. The TS
// plugin reads permissionDecision / permissionDecisionReason out of
// hookSpecificOutput and throws on deny/ask.
func (o *OpencodeHarness) FormatHookResponse(r HookResponse) string {
	data, _ := json.Marshal(r)
	return string(data)
}

func (o *OpencodeHarness) IsInstalled() bool {
	data, err := os.ReadFile(o.SettingsPath())
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte("yolonot"))
}

func (o *OpencodeHarness) Install(binaryPath string) error {
	path := o.SettingsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	ts := bytes.ReplaceAll(embeddedOpencodePluginTS, []byte("__YOLONOT_BIN__"), []byte(binaryPath))
	if err := os.WriteFile(path, ts, 0644); err != nil {
		return err
	}
	Verbosef("wrote %s (%d bytes)", path, len(ts))
	return nil
}

func (o *OpencodeHarness) Uninstall() error {
	path := o.SettingsPath()
	Verbosef("removing %s", path)
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (o *OpencodeHarness) InstallSkill() (string, error) { return "", nil }
func (o *OpencodeHarness) UninstallSkill() error         { return nil }

// PostInstallNotes documents OpenCode's plugin-based installation and
// the lack of an "ask" primitive. The plugin treats any non-deny
// response as allow, so ask-rules effectively become allow — not a
// security regression since the LLM's ask classification surfaces via
// deny-escalation on the risk map, but surprising if users expect the
// Claude three-state model.
func (o *OpencodeHarness) PostInstallNotes() []string {
	return []string{
		"OpenCode installs as a TypeScript plugin (~/.config/opencode/plugin/yolonot.ts) — restart OpenCode to activate.",
		"OpenCode has no 'ask' hook primitive — yolonot 'ask' rules fall through to allow; use 'deny' rules for hard blocks.",
		"Run 'yolonot upgrade' after updating the binary so the plugin shim stays in sync.",
	}
}

// IsDetected returns true if ~/.config/opencode exists.
func (o *OpencodeHarness) IsDetected() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(home, ".config", "opencode"))
	return err == nil
}
