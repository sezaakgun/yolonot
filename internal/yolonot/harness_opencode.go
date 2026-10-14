package yolonot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func init() { RegisterHarness(&OpencodeHarness{}) }

// OpencodeHarness is the sst/opencode adapter.
//
// OpenCode's plugin protocol is TypeScript-native — plugins are ES modules
// loaded from ~/.config/opencode/plugins/*.ts (XDG_CONFIG_HOME is respected).
// The import-free shim supports V1's named factory and V2's default definition.
// There is no stdin/stdout hook contract in either OpenCode version.
// We bridge by installing a small TS shim (harness_opencode_plugin.ts,
// embedded via //go:embed) that spawns `yolonot hook` and translates the
// response back into the Error-throw convention OpenCode uses to block a
// tool callback. V2 wraps the final shell executor and participates in native
// permission evaluation; V1 uses tool.execute.before/after.
//
// Differences from Claude/Codex:
//   - Install writes a TS file, not a JSON settings fragment.
//   - SettingsPath returns the plugin file path (what IsInstalled probes).
//   - No session-id env var — sessions are passed via the plugin hook args
//     and piped into our stdin JSON. SessionIDFromEnv checks the optional
//     YOLONOT_OPENCODE_SESSION_ID override for CLI pause/resume.
//   - V2's shim marks hook subprocesses with YOLONOT_OPENCODE_API=2 so
//     core policy can use native ask support without changing V1 behavior.
type OpencodeHarness struct{}

func (o *OpencodeHarness) Name() string { return "opencode" }

func (o *OpencodeHarness) SupportsAsk() bool {
	return os.Getenv("YOLONOT_OPENCODE_API") == "2"
}

// RiskMap is OpenCode's default tier→action policy.
//
// V2 exposes native asks. V1's shim only blocks on deny; empty stdout returns
// control to OpenCode without blocking.
// Using ActionPassthrough here would silently promote moderate to allow
// without that intent being visible in the RiskMap. So moderate maps to
// ActionAllow explicitly — same effective behavior, but legible in config
// and overridable via YOLONOT_OPENCODE_RISK_MODERATE=deny for users who
// want a stricter default. High/critical escalate to deny.
func (o *OpencodeHarness) RiskMap() map[string]string {
	moderate := ActionAllow
	if o.SupportsAsk() {
		moderate = ActionAsk
	}
	return map[string]string{
		RiskSafe:     ActionAllow,
		RiskLow:      ActionAllow,
		RiskModerate: moderate,
		RiskHigh:     ActionDeny,
		RiskCritical: ActionDeny,
	}
}

// SettingsPath returns the path to the installed yolonot plugin file.
// Called "settings" for interface consistency — OpenCode has no single
// settings file; this is the artifact `yolonot install` manages.
func (o *OpencodeHarness) SettingsPath() string {
	return filepath.Join(opencodeConfigDir(), "plugins", "yolonot.ts")
}

func opencodeConfigDir() string {
	if config := os.Getenv("XDG_CONFIG_HOME"); config != "" {
		return filepath.Join(config, "opencode")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "opencode")
}

func (o *OpencodeHarness) SessionIDFromEnv() string {
	if override := os.Getenv("YOLONOT_OPENCODE_SESSION_ID"); override != "" {
		return override
	}
	return os.Getenv("OPENCODE_SESSION_ID")
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
// hookSpecificOutput and throws on deny. Ask returns control to OpenCode.
func (o *OpencodeHarness) FormatHookResponse(r HookResponse) string {
	// The core uses a decisionless warning envelope when it deliberately
	// falls back to host permissions. Express that trusted passthrough as
	// empty stdout; the shim keeps rejecting malformed nonempty output.
	if r.HookSpecificOutput.PermissionDecision == "" {
		return ""
	}
	data, _ := json.Marshal(r)
	return string(data)
}

func (o *OpencodeHarness) IsInstalled() bool {
	for _, path := range []string{o.SettingsPath(), filepath.Join(opencodeConfigDir(), "plugin", "yolonot.ts")} {
		data, err := os.ReadFile(path)
		if err == nil && bytes.Contains(data, []byte("// yolonot — OpenCode plugin shim")) {
			return true
		}
	}
	return false
}

func (o *OpencodeHarness) Install(binaryPath string) error {
	path := o.SettingsPath()
	quotedBinary, _ := json.Marshal(binaryPath)
	ts := bytes.ReplaceAll(embeddedOpencodePluginTS, []byte(`"__YOLONOT_BIN__"`), quotedBinary)
	if err := atomicWriteFile(path, ts, 0644); err != nil {
		return err
	}
	// Both directories are discovered by current OpenCode. Remove the
	// previous owned copy so upgrading cannot execute the policy twice.
	legacy := filepath.Join(opencodeConfigDir(), "plugin", "yolonot.ts")
	if err := removeOwnedOpencodePlugin(legacy); err != nil {
		return err
	}
	Verbosef("wrote %s (%d bytes)", path, len(ts))
	return nil
}

func (o *OpencodeHarness) Uninstall() error {
	for _, path := range []string{o.SettingsPath(), filepath.Join(opencodeConfigDir(), "plugin", "yolonot.ts")} {
		if err := removeOwnedOpencodePlugin(path); err != nil {
			return err
		}
	}
	return nil
}

func removeOwnedOpencodePlugin(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Contains(data, []byte("// yolonot — OpenCode plugin shim")) {
		return nil
	}
	Verbosef("removing %s", path)
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (o *OpencodeHarness) InstallSkill() (string, error) {
	return installHarnessSkill("opencode", filepath.Join(opencodeConfigDir(), "skills", "yolonot"))
}
func (o *OpencodeHarness) UninstallSkill() error {
	return uninstallHarnessSkill(filepath.Join(opencodeConfigDir(), "skills", "yolonot"))
}

// PostInstallNotes documents OpenCode's plugin-based installation and
// the lack of an "ask" primitive in this shim. A valid non-deny response
// returns control to OpenCode, so ask-rules cannot guarantee a prompt.
func (o *OpencodeHarness) PostInstallNotes() []string {
	return []string{
		fmt.Sprintf("OpenCode installs as a TypeScript plugin (%s). Reload or restart OpenCode to activate.", o.SettingsPath()),
		"OpenCode V2 uses native permission prompts for 'ask'. V1 defers ask to the host. Host auto-accept can approve native asks; use deny rules for hard blocks.",
		"Run 'yolonot upgrade' after updating the binary so the plugin shim stays in sync.",
	}
}

// IsDetected returns true if OpenCode's configuration directory exists.
func (o *OpencodeHarness) IsDetected() bool {
	_, err := os.Stat(opencodeConfigDir())
	return err == nil
}
