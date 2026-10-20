package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// baseHarness implements common Harness methods and capability interfaces via
// Go struct embedding and functional/declarative specs. Concrete harness types
// embed baseHarness and configure their protocol and installer strategy in
// their constructor.
type baseHarness struct {
	name                 string
	supportsAsk          bool
	supportsAskFn        func() bool
	usesPermRequestPhase bool
	ambiguousPostToolUse bool
	exitTwoOnDeny        bool
	sessionEnvKeys       []string
	configDirFn          func() string
	settingsPathFn       func() string
	skillDirFn           func() string
	riskMap              map[string]string
	riskMapFn            func() map[string]string
	parseFn              func([]byte) (HookPayload, error)
	parseFailureFn       func([]byte, error) string
	formatFn             func(HookResponse) string
	isInstalledFn        func(settingsPath string) bool
	installFn            func(settingsPath, binaryPath string) error
	uninstallFn          func(settingsPath string) error
	isDetectedFn         func() bool
	notes                []string
	notesFn              func(settingsPath string) []string
}

func (b *baseHarness) Name() string { return b.name }
func (b *baseHarness) SupportsAsk() bool {
	if b.supportsAskFn != nil {
		return b.supportsAskFn()
	}
	return b.supportsAsk
}
func (b *baseHarness) UsesPermissionRequestPhase() bool { return b.usesPermRequestPhase }
func (b *baseHarness) AmbiguousPostToolUse() bool       { return b.ambiguousPostToolUse }
func (b *baseHarness) ExitTwoOnDeny() bool              { return b.exitTwoOnDeny }

func (b *baseHarness) SettingsPath() string {
	if b.settingsPathFn != nil {
		return b.settingsPathFn()
	}
	return ""
}

func (b *baseHarness) SessionIDFromEnv() string {
	return firstNonEmptyEnv(b.sessionEnvKeys...)
}

func (b *baseHarness) RiskMap() map[string]string {
	if b.riskMapFn != nil {
		return b.riskMapFn()
	}
	out := make(map[string]string, len(b.riskMap))
	for k, v := range b.riskMap {
		out[k] = v
	}
	return out
}

func (b *baseHarness) ParseHookInput(input []byte) (HookPayload, error) {
	var (
		p   HookPayload
		err error
	)
	if b.parseFn != nil {
		p, err = b.parseFn(input)
	} else {
		p, err = parseFlexibleHookPayload(input)
	}
	if err == nil && p.HookEventName != "" && b.name != "claude" {
		if p.Cwd == "" {
			p.Cwd, _ = os.Getwd()
		} else if !filepath.IsAbs(p.Cwd) {
			if wd, werr := os.Getwd(); werr == nil && wd != "" {
				p.Cwd = filepath.Join(wd, p.Cwd)
			}
		}
	}
	return p, err
}

func (b *baseHarness) ParseFailure(input []byte, err error) string {
	if b.parseFailureFn != nil {
		return b.parseFailureFn(input, err)
	}
	return ""
}

func (b *baseHarness) FormatHookResponse(r HookResponse) string {
	if b.formatFn != nil {
		return b.formatFn(r)
	}
	return formatClaudePreToolUse(r)
}

func (b *baseHarness) IsInstalled() bool {
	return b.isInstalledFn(b.SettingsPath())
}

func (b *baseHarness) Install(binaryPath string) error {
	return b.installFn(b.SettingsPath(), binaryPath)
}

func (b *baseHarness) Uninstall() error {
	return b.uninstallFn(b.SettingsPath())
}

func (b *baseHarness) skillDir() string {
	if b.skillDirFn != nil {
		return b.skillDirFn()
	}
	return filepath.Join(b.configDirFn(), "skills", "yolonot")
}

func (b *baseHarness) InstallSkill() (string, error) {
	return installHarnessSkill(b.name, b.skillDir())
}

func (b *baseHarness) UninstallSkill() error {
	return uninstallHarnessSkill(b.skillDir())
}

func (b *baseHarness) readSettings() (map[string]interface{}, error) {
	return readHarnessJSON(b.SettingsPath())
}

func (b *baseHarness) loadSettings() map[string]interface{} {
	s, _ := b.readSettings()
	if s == nil {
		return map[string]interface{}{}
	}
	return s
}

func (b *baseHarness) saveSettings(s map[string]interface{}) error {
	return saveHarnessJSONWithPerm(b.SettingsPath(), s, 0o644)
}

func (b *baseHarness) readHooks() (map[string]interface{}, error) {
	return b.readSettings()
}

func (b *baseHarness) loadHooks() map[string]interface{} {
	return b.loadSettings()
}

func (b *baseHarness) saveHooks(s map[string]interface{}) error {
	return b.saveSettings(s)
}

func (b *baseHarness) removeHooks() error {
	return b.Uninstall()
}

func (b *baseHarness) IsDetected() bool {
	if b.isDetectedFn != nil {
		return b.isDetectedFn()
	}
	return dirExists(b.configDirFn())
}

func (b *baseHarness) PostInstallNotes() []string {
	if b.notesFn != nil {
		return b.notesFn(b.SettingsPath())
	}
	return b.notes
}

// --- RiskMap Presets ---

func claudeCompatRiskMap() map[string]string {
	return map[string]string{
		RiskSafe:     ActionAllow,
		RiskLow:      ActionAllow,
		RiskModerate: ActionAsk,
		RiskHigh:     ActionAsk,
		RiskCritical: ActionAsk,
	}
}

func allowDenyRiskMap() map[string]string {
	return map[string]string{
		RiskSafe:     ActionAllow,
		RiskLow:      ActionAllow,
		RiskModerate: ActionPassthrough,
		RiskHigh:     ActionDeny,
		RiskCritical: ActionDeny,
	}
}

func askDenyRiskMap() map[string]string {
	return map[string]string{
		RiskSafe:     ActionAllow,
		RiskLow:      ActionAllow,
		RiskModerate: ActionAsk,
		RiskHigh:     ActionDeny,
		RiskCritical: ActionDeny,
	}
}

func denyOnlyRiskMap() map[string]string {
	return allowDenyRiskMap()
}

// --- Response Formatters ---

func formatClaudePreToolUse(r HookResponse) string {
	if r.HookSpecificOutput.PermissionDecision == "" {
		return ""
	}
	if r.HookSpecificOutput.HookEventName == "" {
		r.HookSpecificOutput.HookEventName = "PreToolUse"
	}
	data, _ := json.Marshal(r)
	return string(data)
}

func formatCanonicalPluginResponse(r HookResponse) string {
	return formatClaudePreToolUse(r)
}

func formatPermissionRequestOrClaude(r HookResponse, askOnPre bool) string {
	if r.HookSpecificOutput.HookEventName == "PermissionRequest" {
		decision := r.HookSpecificOutput.PermissionDecision
		if decision != ActionAllow && decision != ActionDeny {
			return ""
		}
		verdict := map[string]string{"behavior": decision}
		if decision == ActionDeny && r.HookSpecificOutput.PermissionDecisionReason != "" {
			verdict["message"] = r.HookSpecificOutput.PermissionDecisionReason
		}
		data, _ := json.Marshal(map[string]interface{}{
			"hookSpecificOutput": map[string]interface{}{
				"hookEventName": "PermissionRequest",
				"decision":      verdict,
			},
		})
		return string(data)
	}
	switch r.HookSpecificOutput.PermissionDecision {
	case "", ActionAllow:
		return ""
	case ActionAsk:
		if !askOnPre {
			return ""
		}
	}
	data, _ := json.Marshal(r)
	return string(data)
}

// --- Shared Environment & File Helpers ---

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func xdgOrHomeConfigDir(envKeys []string, xdgSubdir, homeRel string) string {
	if dir := firstNonEmptyEnv(envKeys...); dir != "" {
		return dir
	}
	if xdgSubdir != "" {
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, xdgSubdir)
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, homeRel)
}

func dirExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func readHarnessJSON(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s map[string]interface{}
	if err := json.Unmarshal(data, &s); err != nil || s == nil {
		return nil, fmt.Errorf("%s: expected a valid JSON object", path)
	}
	if err := uniqueJSONFields(data); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

func saveHarnessJSON(path string, s map[string]interface{}) error {
	return saveHarnessJSONWithPerm(path, s, 0o644)
}

func saveHarnessJSONWithPerm(path string, s map[string]interface{}, defaultPerm os.FileMode) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	perm := defaultPerm
	if perm == 0 {
		perm = 0o644
	}
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	return atomicWriteFile(path, append(data, '\n'), perm)
}

func validateHooksObject(path string, s map[string]interface{}, eventsSubKey string, events []string) error {
	value, exists := s["hooks"]
	if !exists {
		return nil
	}
	hooks, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%s: hooks must be an object", path)
	}
	if eventsSubKey != "" {
		return nil
	}
	for _, ev := range events {
		if v, ok := hooks[ev]; ok && v != nil {
			if _, isArr := v.([]interface{}); !isArr {
				return fmt.Errorf("%s: hooks.%s must be an array", path, ev)
			}
		}
	}
	return nil
}

func quoteYAMLString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func stripTaggedBlock(text, startMarker, endMarker string) string {
	for {
		s := strings.Index(text, startMarker)
		if s < 0 {
			break
		}
		e := strings.Index(text[s:], endMarker)
		if e < 0 {
			end := s + len(startMarker)
			if end < len(text) && text[end] == '\n' {
				end++
			}
			text = text[:s] + text[end:]
			break
		}
		end := s + e + len(endMarker)
		if end < len(text) && text[end] == '\n' {
			end++
		}
		if s > 0 && text[s-1] == '\n' {
			s--
		}
		text = text[:s] + text[end:]
	}
	return text
}

// --- Strategy 1: Nested JSON Hook Installer (Claude / Qwen / ZCode / Copilot / Grok / DeepSeek / Devin / Muse / Goose / OpenHands) ---

type nestedJSONHooksSpec struct {
	harnessName             string
	events                  []string
	stripEvents             []string
	matcher                 string
	eventsSubKey            string // e.g. "events" for ZCode
	namedRootHook           string // e.g. "yolonot-command-guard" for Antigravity
	setEnabledFlag          bool   // sets hooks["enabled"] = true
	matchAnyYolonot         bool   // matches any command containing "yolonot"
	defaultPerm             os.FileMode
	rootDefaults            map[string]interface{}
	entryExtras             map[string]interface{}
	buildEntry              func(event, binaryPath string) map[string]interface{}
	removeFileWhenEmpty     bool
	acceptRootHooksFallback bool
	preInstall              func(settingsPath string) error
	postInstall             func(settingsPath string) error
	postUninstall           func(settingsPath string) error
}

func (b *baseHarness) useNestedJSONHooks(spec nestedJSONHooksSpec) {
	allStrip := spec.stripEvents
	if len(allStrip) == 0 {
		allStrip = spec.events
	}
	b.isInstalledFn = func(settingsPath string) bool {
		s, err := readHarnessJSON(settingsPath)
		if err != nil {
			return false
		}
		if spec.namedRootHook != "" {
			def, ok := s[spec.namedRootHook].(map[string]interface{})
			if !ok || def["enabled"] == false {
				return false
			}
			for _, ev := range allStrip {
				if hasYolonotNestedHook(def, ev, spec.harnessName, spec.matchAnyYolonot) {
					return true
				}
			}
			return false
		}
		hooks, _ := s["hooks"].(map[string]interface{})
		if hooks == nil && spec.acceptRootHooksFallback {
			hooks = s
		}
		if hooks == nil {
			return false
		}
		if spec.setEnabledFlag {
			if enabled, ok := hooks["enabled"].(bool); !ok || !enabled {
				return false
			}
		}
		target := hooks
		if spec.eventsSubKey != "" {
			target, _ = hooks[spec.eventsSubKey].(map[string]interface{})
		}
		for _, ev := range allStrip {
			if hasYolonotNestedHook(target, ev, spec.harnessName, spec.matchAnyYolonot) {
				return true
			}
		}
		return false
	}

	b.installFn = func(settingsPath, binaryPath string) error {
		s, err := readHarnessJSON(settingsPath)
		if err != nil {
			return err
		}
		if spec.namedRootHook == "" {
			if err := validateHooksObject(settingsPath, s, spec.eventsSubKey, allStrip); err != nil {
				return err
			}
		}
		if spec.preInstall != nil {
			if err := spec.preInstall(settingsPath); err != nil {
				return err
			}
		}
		for k, v := range spec.rootDefaults {
			if _, exists := s[k]; !exists {
				s[k] = v
			}
		}
		cmd := shellHookCommand(binaryPath, spec.harnessName)
		makeEntry := func(ev string) map[string]interface{} {
			if spec.buildEntry != nil {
				return spec.buildEntry(ev, binaryPath)
			}
			e := map[string]interface{}{
				"type":    "command",
				"command": cmd,
			}
			if len(spec.entryExtras) == 0 {
				e["timeout"] = 60.0
			} else {
				for k, v := range spec.entryExtras {
					e[k] = v
				}
			}
			return e
		}
		if spec.namedRootHook != "" {
			def := map[string]interface{}{"enabled": true}
			for _, ev := range spec.events {
				addHookToEvent(def, ev, spec.matcher, makeEntry(ev))
			}
			s[spec.namedRootHook] = def
		} else {
			hooks, _ := s["hooks"].(map[string]interface{})
			if hooks == nil {
				hooks = map[string]interface{}{}
				s["hooks"] = hooks
			}
			if spec.setEnabledFlag {
				hooks["enabled"] = true
			}
			target := hooks
			if spec.eventsSubKey != "" {
				sub, _ := hooks[spec.eventsSubKey].(map[string]interface{})
				if sub == nil {
					sub = map[string]interface{}{}
					hooks[spec.eventsSubKey] = sub
				}
				target = sub
			}
			stripYolonotNestedHooks(target, allStrip...)
			for _, ev := range spec.events {
				addHookToEvent(target, ev, spec.matcher, makeEntry(ev))
			}
		}
		if err := saveHarnessJSONWithPerm(settingsPath, s, spec.defaultPerm); err != nil {
			return err
		}
		if spec.postInstall != nil {
			return spec.postInstall(settingsPath)
		}
		return nil
	}

	b.uninstallFn = func(settingsPath string) error {
		s, err := readHarnessJSON(settingsPath)
		if err != nil {
			return err
		}
		if spec.namedRootHook != "" {
			if _, exists := s[spec.namedRootHook]; !exists {
				return nil
			}
			delete(s, spec.namedRootHook)
			if err := saveHarnessJSONWithPerm(settingsPath, s, spec.defaultPerm); err != nil {
				return err
			}
			if spec.postUninstall != nil {
				return spec.postUninstall(settingsPath)
			}
			return nil
		}
		if err := validateHooksObject(settingsPath, s, spec.eventsSubKey, allStrip); err != nil {
			return err
		}
		hooks, _ := s["hooks"].(map[string]interface{})
		target := hooks
		if hooks != nil && spec.eventsSubKey != "" {
			target, _ = hooks[spec.eventsSubKey].(map[string]interface{})
		}
		stripYolonotNestedHooks(target, allStrip...)
		if spec.removeFileWhenEmpty && len(target) == 0 {
			err := os.Remove(settingsPath)
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if err := saveHarnessJSONWithPerm(settingsPath, s, spec.defaultPerm); err != nil {
			return err
		}
		if spec.postUninstall != nil {
			return spec.postUninstall(settingsPath)
		}
		return nil
	}
}

func hasYolonotNestedHook(hooks map[string]interface{}, event, harnessName string, matchAny bool) bool {
	if hooks == nil {
		return false
	}
	entries, _ := hooks[event].([]interface{})
	want := "--harness " + harnessName
	for _, entry := range entries {
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
			if cmd, ok := hm["command"].(string); ok && strings.Contains(cmd, "yolonot") && (matchAny || strings.Contains(cmd, want)) {
				return true
			}
		}
	}
	return false
}

func stripYolonotNestedHooks(hooks map[string]interface{}, events ...string) {
	if hooks == nil {
		return
	}
	for _, event := range events {
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

// --- Strategy 2: Flat JSON Hook Installer (Crush / Kiro) ---

type flatJSONHooksSpec struct {
	harnessName     string
	events          []string
	stripEvents     []string
	matcher         string
	matchAnyYolonot bool
	defaultPerm     os.FileMode
	rootDefaults    map[string]interface{}
	entryExtras     map[string]interface{}
	postInstall     func(settingsPath string) error
	postUninstall   func(settingsPath string) error
}

func (b *baseHarness) useFlatJSONHooks(spec flatJSONHooksSpec) {
	allStrip := spec.stripEvents
	if len(allStrip) == 0 {
		allStrip = spec.events
	}
	b.isInstalledFn = func(settingsPath string) bool {
		s, err := readHarnessJSON(settingsPath)
		if err != nil {
			return false
		}
		hooks, _ := s["hooks"].(map[string]interface{})
		if hooks == nil {
			return false
		}
		want := "--harness " + spec.harnessName
		for _, ev := range spec.events {
			entries, _ := hooks[ev].([]interface{})
			for _, it := range entries {
				if m, ok := it.(map[string]interface{}); ok {
					if cmd, _ := m["command"].(string); strings.Contains(cmd, "yolonot") && (spec.matchAnyYolonot || strings.Contains(cmd, want)) {
						return true
					}
				}
			}
		}
		return false
	}

	b.installFn = func(settingsPath, binaryPath string) error {
		s, err := readHarnessJSON(settingsPath)
		if err != nil {
			return err
		}
		if err := validateHooksObject(settingsPath, s, "", allStrip); err != nil {
			return err
		}
		for k, v := range spec.rootDefaults {
			if _, exists := s[k]; !exists {
				s[k] = v
			}
		}
		hooks, _ := s["hooks"].(map[string]interface{})
		if hooks == nil {
			hooks = map[string]interface{}{}
			s["hooks"] = hooks
		}
		stripFlatJSONHooks(hooks, allStrip...)
		cmd := shellHookCommand(binaryPath, spec.harnessName)
		for _, ev := range spec.events {
			entry := map[string]interface{}{
				"command": cmd,
			}
			if spec.matcher != "" {
				entry["matcher"] = spec.matcher
			}
			for k, v := range spec.entryExtras {
				entry[k] = v
			}
			existing, _ := hooks[ev].([]interface{})
			hooks[ev] = append(existing, entry)
		}
		if err := saveHarnessJSONWithPerm(settingsPath, s, spec.defaultPerm); err != nil {
			return err
		}
		if spec.postInstall != nil {
			return spec.postInstall(settingsPath)
		}
		return nil
	}

	b.uninstallFn = func(settingsPath string) error {
		s, err := readHarnessJSON(settingsPath)
		if err != nil {
			return err
		}
		if err := validateHooksObject(settingsPath, s, "", allStrip); err != nil {
			return err
		}
		hooks, _ := s["hooks"].(map[string]interface{})
		stripFlatJSONHooks(hooks, allStrip...)
		if err := saveHarnessJSONWithPerm(settingsPath, s, spec.defaultPerm); err != nil {
			return err
		}
		if spec.postUninstall != nil {
			return spec.postUninstall(settingsPath)
		}
		return nil
	}
}

func stripFlatJSONHooks(hooks map[string]interface{}, events ...string) {
	if hooks == nil {
		return
	}
	for _, ev := range events {
		entries, _ := hooks[ev].([]interface{})
		var kept []interface{}
		for _, it := range entries {
			if m, ok := it.(map[string]interface{}); ok {
				if cmd, _ := m["command"].(string); strings.Contains(cmd, "yolonot") {
					continue
				}
			}
			kept = append(kept, it)
		}
		if len(kept) == 0 {
			delete(hooks, ev)
		} else {
			hooks[ev] = kept
		}
	}
}

// --- Strategy 3: Tagged Block Installer (Hermes YAML / Kimi TOML) ---

func (b *baseHarness) useTaggedBlockHooks(buildBlock func(binaryPath string) string) {
	want := "--harness " + b.name
	b.isInstalledFn = func(settingsPath string) bool {
		data, err := os.ReadFile(settingsPath)
		return err == nil && strings.Contains(string(data), want)
	}
	b.installFn = func(settingsPath, binaryPath string) error {
		existing, err := os.ReadFile(settingsPath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		perm := os.FileMode(0o644)
		if info, statErr := os.Stat(settingsPath); statErr == nil {
			perm = info.Mode().Perm()
		}
		cleaned := stripTaggedBlock(string(existing), "# yolonot-hooks-start", "# yolonot-hooks-end")
		out := strings.TrimRight(cleaned, "\n") + buildBlock(binaryPath)
		return atomicWriteFile(settingsPath, []byte(out), perm)
	}
	b.uninstallFn = func(settingsPath string) error {
		data, err := os.ReadFile(settingsPath)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		perm := os.FileMode(0o644)
		if info, statErr := os.Stat(settingsPath); statErr == nil {
			perm = info.Mode().Perm()
		}
		cleaned := stripTaggedBlock(string(data), "# yolonot-hooks-start", "# yolonot-hooks-end")
		return atomicWriteFile(settingsPath, []byte(cleaned), perm)
	}
}

// --- Strategy 4: Plugin / Extension Shim File Installer (Kilo / OpenClaw / Pi / Mirror / Amp) ---

type shimFileHooksSpec struct {
	marker               string
	removeDirOnUninstall bool
	legacyPathsFn        func(settingsPath string) []string
	buildShim            func(settingsPath, binaryPath string) ([]byte, error)
	postInstall          func(settingsPath string) error
	postUninstall        func(settingsPath string) error
}

func (b *baseHarness) useShimFileHooks(spec shimFileHooksSpec) {
	allPaths := func(settingsPath string) []string {
		paths := []string{settingsPath}
		if spec.legacyPathsFn != nil {
			paths = append(paths, spec.legacyPathsFn(settingsPath)...)
		}
		return paths
	}
	removeOwned := func(path string) error {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !strings.Contains(string(data), spec.marker) {
			return nil
		}
		if spec.removeDirOnUninstall {
			return os.RemoveAll(filepath.Dir(path))
		}
		err = os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	b.isInstalledFn = func(settingsPath string) bool {
		for _, p := range allPaths(settingsPath) {
			data, err := os.ReadFile(p)
			if err == nil && strings.Contains(string(data), spec.marker) {
				return true
			}
		}
		return false
	}
	b.installFn = func(settingsPath, binaryPath string) error {
		if binaryPath == "" {
			binaryPath = "yolonot"
		}
		content, err := spec.buildShim(settingsPath, binaryPath)
		if err != nil {
			return err
		}
		if err := atomicWriteFile(settingsPath, content, 0o644); err != nil {
			return err
		}
		if spec.legacyPathsFn != nil {
			for _, lp := range spec.legacyPathsFn(settingsPath) {
				if err := removeOwned(lp); err != nil {
					return err
				}
			}
		}
		if spec.postInstall != nil {
			return spec.postInstall(settingsPath)
		}
		return nil
	}
	b.uninstallFn = func(settingsPath string) error {
		for _, p := range allPaths(settingsPath) {
			if err := removeOwned(p); err != nil {
				return err
			}
		}
		if spec.postUninstall != nil {
			return spec.postUninstall(settingsPath)
		}
		return nil
	}
}
