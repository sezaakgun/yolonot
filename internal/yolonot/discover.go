package yolonot

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/sezaakgun/yolonot/internal/fastallow"
	"github.com/sezaakgun/yolonot/internal/glob"
)

// discoverGOOS allows tests to simulate macOS/Linux/Windows managed-settings
// path resolution without mutating the host OS.
var discoverGOOS = runtime.GOOS

// RuleOverlap describes whether a discovered host rule is already covered by or
// conflicts with yolonot's active rules or built-in fast_allow.
type RuleOverlap struct {
	Status    string `json:"status"`               // "none", "exact_duplicate", "covered_by_fast_allow", "conflict"
	MatchedBy string `json:"matched_by,omitempty"` // e.g. "allow-cmd git *", "fast_allow", "deny-cmd rm *"
}

// DiscoveredRule represents a single command or file-access rule extracted from
// a host harness configuration file.
type DiscoveredRule struct {
	Action              string      `json:"action"`                         // "allow", "deny", "ask", "sensitive"
	Raw                 string      `json:"raw"`                            // original host syntax, e.g. "Bash(git push:*)"
	SuggestedRule       string      `json:"suggested_rule,omitempty"`       // normalized .yolonot syntax, e.g. "allow-cmd git push *"
	UnconvertibleReason string      `json:"unconvertible_reason,omitempty"` // populated when rule is a complex inline script
	BroadWarning        string      `json:"broad_warning,omitempty"`        // populated when an allow rule is dangerously broad
	Overlap             RuleOverlap `json:"overlap"`
}

// DiscoveredHint represents a prose classifier hint extracted from host settings
// (such as Claude Code's autoMode.{environment,allow,soft_deny}).
type DiscoveredHint struct {
	Kind string `json:"kind"` // "context", "allow-hint", "ask-hint"
	Text string `json:"text"`
}

// DiscoveredPolicyAlert represents a host-level permission or sandbox setting
// that weakens or bypasses safety guarantees.
type DiscoveredPolicyAlert struct {
	Category string `json:"category"` // "host_permissions" or "host_sandbox"
	Detail   string `json:"detail"`
}

// DiscoveredHostFile holds all rules, hints, and policy alerts extracted from a
// single host configuration file.
type DiscoveredHostFile struct {
	Harness      string                  `json:"harness"` // "claude", "antigravity", "codex", "cursor", "opencode"
	Scope        string                  `json:"scope"`   // "managed", "user", "project"
	Path         string                  `json:"path"`
	Rules        []DiscoveredRule        `json:"rules,omitempty"`
	Hints        []DiscoveredHint        `json:"hints,omitempty"`
	PolicyAlerts []DiscoveredPolicyAlert `json:"policy_alerts,omitempty"`
}

// DiscoverSummary is the top-level report returned by DiscoverHostPermissions
// and serialized by `yolonot rules discover --json`.
type DiscoverSummary struct {
	Cwd             string               `json:"cwd"`
	ProjectRoot     string               `json:"project_root,omitempty"`
	HostFiles       []DiscoveredHostFile `json:"host_files"`
	ActiveRules     []string             `json:"active_rules"`
	ActiveSensitive []string             `json:"active_sensitive,omitempty"`
	ActiveHints     []DiscoveredHint     `json:"active_hints,omitempty"`
}

func systemRootPrefix() string {
	return os.Getenv("YOLONOT_SYSTEM_ROOT")
}

func sysPath(elem ...string) string {
	rel := filepath.Join(elem...)
	if root := systemRootPrefix(); root != "" {
		clean := rel
		if len(clean) >= 2 && clean[1] == ':' {
			clean = clean[2:]
		}
		clean = strings.TrimLeft(clean, `/\`)
		return filepath.Join(root, clean)
	}
	if !strings.HasPrefix(rel, string(filepath.Separator)) && (len(rel) < 2 || rel[1] != ':') {
		return string(filepath.Separator) + rel
	}
	return rel
}

func projectDirsForCwd(cwd string) []string {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if cwd == "" {
		return nil
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		home = canonicalDirectory(home)
	}
	cur := canonicalDirectory(cwd)
	root := projectRoot(cur)
	var out []string
	add := func(d string) {
		if d == "" || (home != "" && d == home) || slices.Contains(out, d) {
			return
		}
		out = append(out, d)
	}
	add(cur)
	add(root)
	if repo := findRepoRoot(cur); repo != "" {
		add(repo)
	}
	return out
}

func claudeManagedFiles() []string {
	var files []string
	addDir := func(dir string) {
		if dir == "" {
			return
		}
		files = append(files, filepath.Join(dir, "managed-settings.json"))
		if matches, err := filepath.Glob(filepath.Join(dir, "managed-settings.d", "*.json")); err == nil {
			sort.Strings(matches)
			files = append(files, matches...)
		}
	}
	if custom := os.Getenv("CLAUDE_CODE_MANAGED_SETTINGS_PATH"); custom != "" {
		info, err := os.Stat(custom)
		if err == nil && info.IsDir() {
			addDir(custom)
		} else {
			files = append(files, custom)
			addDir(filepath.Dir(custom))
		}
		return dedupeStrings(files)
	}
	switch discoverGOOS {
	case "darwin":
		addDir(sysPath("Library", "Application Support", "ClaudeCode"))
	case "windows":
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		addDir(sysPath(pf, "ClaudeCode"))
		addDir(sysPath(pd, "ClaudeCode"))
	default:
		addDir(sysPath("etc", "claude-code"))
	}
	return dedupeStrings(files)
}

func antigravityManagedFiles() []string {
	switch discoverGOOS {
	case "darwin":
		return []string{sysPath("Library", "Application Support", "Antigravity", "admin_settings.json")}
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return []string{sysPath(pd, "Antigravity", "admin_settings.json")}
	default:
		return []string{sysPath("etc", "antigravity", "admin_settings.json")}
	}
}

func codexManagedDir() string {
	switch discoverGOOS {
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return sysPath(pd, "OpenAI", "Codex")
	default:
		return sysPath("etc", "codex")
	}
}

func cursorUserDir() string {
	if dir := os.Getenv("CURSOR_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".cursor")
}

func opencodeUserDir() string {
	if dir := os.Getenv("OPENCODE_CONFIG_DIR"); dir != "" {
		return dir
	}
	return opencodeConfigDir()
}

// DiscoverHostPermissions scans managed, user, and project configuration files
// across the given harnesses (or all supported harnesses when targets is empty)
// and classifies each discovered rule against yolonot's active rules and fast_allow.
func DiscoverHostPermissions(cwd string, targets ...Harness) DiscoverSummary {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if len(targets) == 0 {
		targets = supportedHarnesses()
	}
	projDirs := projectDirsForCwd(cwd)
	activeRules := LoadRules(cwd)
	activeSensitive := LoadSensitivePatterns(cwd)
	activeHints := collectActiveHints(cwd)

	var hostFiles []DiscoveredHostFile
	seen := map[string]bool{}
	addFile := func(f *DiscoveredHostFile) {
		if f == nil || (len(f.Rules) == 0 && len(f.Hints) == 0 && len(f.PolicyAlerts) == 0) {
			return
		}
		key := f.Harness + "\x00" + f.Path
		if seen[key] {
			return
		}
		seen[key] = true
		for i := range f.Rules {
			annotateDiscoveredRule(&f.Rules[i], activeRules, activeSensitive)
		}
		hostFiles = append(hostFiles, *f)
	}

	home, _ := os.UserHomeDir()
	for _, h := range targets {
		if h == nil {
			continue
		}
		switch h.Name() {
		case "claude":
			for _, p := range claudeManagedFiles() {
				addFile(parseClaudeSettingsFile("managed", p))
			}
			dir := claudeConfigDir()
			if dir != "" {
				addFile(parseClaudeSettingsFile("user", filepath.Join(dir, "settings.json")))
				addFile(parseClaudeSettingsFile("user", filepath.Join(dir, "settings.local.json")))
			}
			for _, d := range projDirs {
				addFile(parseClaudeSettingsFile("project", filepath.Join(d, ".claude", "settings.json")))
				addFile(parseClaudeSettingsFile("project", filepath.Join(d, ".claude", "settings.local.json")))
			}

		case "antigravity":
			for _, p := range antigravityManagedFiles() {
				addFile(parseAntigravitySettingsFile("managed", p))
			}
			if home != "" {
				addFile(parseAntigravitySettingsFile("user", filepath.Join(home, ".gemini", "config", "config.json")))
				for _, p := range matchingAntigravityProjectFiles(home, projDirs) {
					addFile(parseAntigravitySettingsFile("project", p))
				}
			}

		case "codex":
			mDir := codexManagedDir()
			for _, name := range []string{"requirements.toml", "managed_config.toml", "config.toml"} {
				addFile(parseCodexTOMLFile("managed", filepath.Join(mDir, name)))
			}
			for _, p := range globSorted(filepath.Join(mDir, "rules", "*.rules")) {
				addFile(parseCodexRulesFile("managed", p))
			}
			uDir := codexConfigDir()
			if uDir != "" {
				addFile(parseCodexTOMLFile("user", filepath.Join(uDir, "config.toml")))
				for _, p := range globSorted(filepath.Join(uDir, "rules", "*.rules")) {
					addFile(parseCodexRulesFile("user", p))
				}
			}
			for _, d := range projDirs {
				addFile(parseCodexTOMLFile("project", filepath.Join(d, ".codex", "config.toml")))
				for _, p := range globSorted(filepath.Join(d, ".codex", "rules", "*.rules")) {
					addFile(parseCodexRulesFile("project", p))
				}
			}

		case "cursor":
			if uDir := cursorUserDir(); uDir != "" {
				addFile(parseCursorConfigFile("user", filepath.Join(uDir, "cli-config.json")))
			}
			for _, d := range projDirs {
				addFile(parseCursorConfigFile("project", filepath.Join(d, ".cursor", "cli.json")))
			}

		case "opencode":
			if custom := os.Getenv("OPENCODE_CONFIG"); custom != "" {
				addFile(parseOpencodeConfigFile("user", custom))
			}
			if uDir := opencodeUserDir(); uDir != "" {
				addFile(parseOpencodeConfigFile("user", filepath.Join(uDir, "opencode.json")))
				addFile(parseOpencodeConfigFile("user", filepath.Join(uDir, "opencode.jsonc")))
			}
			for _, d := range projDirs {
				addFile(parseOpencodeConfigFile("project", filepath.Join(d, "opencode.json")))
				addFile(parseOpencodeConfigFile("project", filepath.Join(d, "opencode.jsonc")))
				addFile(parseOpencodeConfigFile("project", filepath.Join(d, ".opencode", "opencode.json")))
			}

		default:
			discoverExtendedHarness(h.Name(), home, projDirs, addFile)
		}
	}

	var activeRuleStrs []string
	for _, r := range activeRules {
		activeRuleStrs = append(activeRuleStrs, fmt.Sprintf("%s-%s %s", r.Action, r.Type, r.Pattern))
	}
	if activeRuleStrs == nil {
		activeRuleStrs = []string{}
	}
	if hostFiles == nil {
		hostFiles = []DiscoveredHostFile{}
	}
	return DiscoverSummary{
		Cwd:             cwd,
		ProjectRoot:     projectRoot(cwd),
		HostFiles:       hostFiles,
		ActiveRules:     activeRuleStrs,
		ActiveSensitive: activeSensitive,
		ActiveHints:     activeHints,
	}
}

func globSorted(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}

func collectActiveHints(cwd string) []DiscoveredHint {
	var out []DiscoveredHint
	seen := map[string]bool{}
	add := func(kind, text string) {
		if text == "" || text == "$defaults" || seen[kind+"\x00"+text] {
			return
		}
		seen[kind+"\x00"+text] = true
		out = append(out, DiscoveredHint{Kind: kind, Text: text})
	}
	wh := LoadHints(cwd)
	for _, s := range wh.Context {
		add("context", s)
	}
	for _, s := range wh.AllowHints {
		add("allow-hint", s)
	}
	for _, s := range wh.AskHints {
		add("ask-hint", s)
	}
	cfg := LoadConfig()
	for _, s := range cfg.Prompt.Context {
		add("context", s)
	}
	for _, s := range cfg.Prompt.AllowHints {
		add("allow-hint", s)
	}
	for _, s := range cfg.Prompt.AskHints {
		add("ask-hint", s)
	}
	return out
}

func parseClaudeSettingsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, false, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "claude", Scope: scope, Path: path}

	var perms map[string]interface{}
	if p, ok := raw["permissions"].(map[string]interface{}); ok {
		perms = p
		if mode, _ := p["defaultMode"].(string); mode == "bypassPermissions" {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("defaultMode is bypassPermissions in %s (bypasses both host prompts and yolonot hooks)", path),
			})
		}
	}
	for _, action := range []string{"allow", "deny", "ask"} {
		var items []interface{}
		if perms != nil {
			items, _ = perms[action].([]interface{})
		}
		if len(items) == 0 {
			items, _ = raw[action].([]interface{})
		}
		for _, it := range items {
			s, ok := it.(string)
			if !ok {
				continue
			}
			if dr, ok := convertClaudePermissionRule(action, s); ok {
				out.Rules = append(out.Rules, dr)
			}
		}
	}
	if sb, ok := raw["sandbox"].(map[string]interface{}); ok {
		if enabled, ok := sb["enabled"].(bool); ok && !enabled {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_sandbox",
				Detail:   fmt.Sprintf("sandbox.enabled is false in %s", path),
			})
		}
	}
	if am, ok := raw["autoMode"].(map[string]interface{}); ok {
		for _, pair := range []struct {
			field, kind string
		}{
			{"environment", "context"},
			{"allow", "allow-hint"},
			{"soft_deny", "ask-hint"},
		} {
			list, _ := am[pair.field].([]interface{})
			for _, it := range list {
				s, _ := it.(string)
				s = strings.TrimSpace(s)
				if s != "" && s != "$defaults" {
					out.Hints = append(out.Hints, DiscoveredHint{Kind: pair.kind, Text: s})
				}
			}
		}
	}
	return out
}

func buildSuggestedShellRule(action, raw, inner string, appendWildcardIfSingleWord bool) DiscoveredRule {
	if isComplexInlineShell(inner) {
		return DiscoveredRule{
			Action:              action,
			Raw:                 raw,
			UnconvertibleReason: "complex inline shell expression (prefer an allow-hint or script rule)",
		}
	}
	if strings.HasPrefix(inner, "*/") && !strings.ContainsAny(inner, " \t") {
		pathPat := inner
		if strings.HasSuffix(pathPat, "*") && scriptPathRe.MatchString(" "+strings.TrimSuffix(pathPat, "*")) {
			pathPat = strings.TrimSuffix(pathPat, "*")
		}
		if scriptPathRe.MatchString(" "+pathPat) || strings.HasSuffix(pathPat, "/scripts/*") {
			return DiscoveredRule{
				Action:        action,
				Raw:           raw,
				SuggestedRule: action + "-path " + pathPat,
			}
		}
	}
	pat := inner
	if appendWildcardIfSingleWord && pat != "*" && !strings.ContainsAny(pat, " \t*") {
		pat += " *"
	}
	return DiscoveredRule{
		Action:        action,
		Raw:           raw,
		SuggestedRule: action + "-cmd " + pat,
	}
}

func normalizeColonWildcard(inner string) string {
	if inner == "" {
		return "*"
	}
	if strings.HasSuffix(inner, ":*") {
		return strings.TrimSuffix(inner, ":*") + " *"
	}
	if idx := strings.IndexByte(inner, ':'); idx > 0 && !strings.ContainsAny(inner[:idx], " \t/") {
		return inner[:idx] + " " + inner[idx+1:]
	}
	return inner
}

func convertClaudePermissionRule(action, raw string) (DiscoveredRule, bool) {
	s := strings.TrimSpace(raw)
	if s == "*" || s == "Bash" || s == "Bash(*)" || s == "PowerShell" || s == "PowerShell(*)" {
		return DiscoveredRule{
			Action:        action,
			Raw:           s,
			SuggestedRule: action + "-cmd *",
		}, true
	}
	for _, prefix := range []string{"Bash(", "PowerShell("} {
		if strings.HasPrefix(s, prefix) && strings.HasSuffix(s, ")") {
			inner := normalizeColonWildcard(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, prefix), ")")))
			return buildSuggestedShellRule(action, s, inner, false), true
		}
	}
	if action == "deny" {
		for _, prefix := range []string{"Read(", "Edit(", "Write("} {
			if strings.HasPrefix(s, prefix) && strings.HasSuffix(s, ")") {
				inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, prefix), ")"))
				pat := normalizeSensitiveGlob(inner)
				if pat != "" {
					return DiscoveredRule{
						Action:        "sensitive",
						Raw:           s,
						SuggestedRule: "sensitive " + pat,
					}, true
				}
			}
		}
	}
	return DiscoveredRule{}, false
}

func normalizeSensitiveGlob(p string) string {
	if strings.ContainsAny(p, "\r\n") {
		return ""
	}
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "~/")
	p = strings.TrimPrefix(p, "**/")
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimLeft(p, "*")
	if strings.HasSuffix(p, "/**") {
		p = strings.TrimSuffix(p, "/**") + "/"
	} else {
		p = strings.TrimRight(p, "*")
	}
	p = strings.TrimSpace(p)
	if p == "" || p == "." || p == "/" {
		return ""
	}
	return p
}

func matchingAntigravityProjectFiles(home string, projDirs []string) []string {
	if home == "" || len(projDirs) == 0 {
		return nil
	}
	candidates := globSorted(filepath.Join(home, ".gemini", "config", "projects", "*.json"))
	var matched []string
	for _, p := range candidates {
		raw, ok := readJSONObjectFile(p, false, false)
		if !ok {
			continue
		}
		pr, _ := raw["projectResources"].(map[string]interface{})
		resList, _ := pr["resources"].([]interface{})
		for _, item := range resList {
			rm, _ := item.(map[string]interface{})
			gf, _ := rm["gitFolder"].(map[string]interface{})
			uri, _ := gf["folderUri"].(string)
			if uri == "" {
				uri, _ = rm["folderUri"].(string)
			}
			folder := strings.TrimPrefix(uri, "file://")
			if folder == "" {
				continue
			}
			folder = canonicalDirectory(folder)
			if slices.Contains(projDirs, folder) {
				matched = append(matched, p)
				break
			}
		}
	}
	return matched
}

func parseAntigravitySettingsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, false, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "antigravity", Scope: scope, Path: path}

	if us, ok := raw["userSettings"].(map[string]interface{}); ok {
		if sb, ok := us["enableTerminalSandbox"].(bool); ok && !sb {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_sandbox",
				Detail:   fmt.Sprintf("userSettings.enableTerminalSandbox is false in %s", path),
			})
		}
		if pol, _ := us["autoExecutionPolicy"].(string); pol == "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER" {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("userSettings.autoExecutionPolicy is EAGER in %s (auto-runs passthrough commands without prompting)", path),
			})
		}
		if grants, ok := us["globalPermissionGrants"].(map[string]interface{}); ok {
			extractAntigravityGrants(out, grants)
		}
	}
	if grants, ok := raw["permissionGrants"].(map[string]interface{}); ok {
		extractAntigravityGrants(out, grants)
	}
	if perms, ok := raw["permissions"].(map[string]interface{}); ok {
		extractAntigravityGrants(out, perms)
	}
	return out
}

func extractAntigravityGrants(out *DiscoveredHostFile, grants map[string]interface{}) {
	for _, action := range []string{"allow", "deny", "ask"} {
		items, _ := grants[action].([]interface{})
		for _, it := range items {
			s, ok := it.(string)
			if !ok {
				continue
			}
			if dr, ok := convertAntigravityGrant(action, s); ok {
				out.Rules = append(out.Rules, dr)
			}
		}
	}
}

func convertAntigravityGrant(action, raw string) (DiscoveredRule, bool) {
	s := strings.TrimSpace(raw)
	if s == "*" || s == "command(*)" || s == "command" {
		return DiscoveredRule{
			Action:        action,
			Raw:           s,
			SuggestedRule: action + "-cmd *",
		}, true
	}
	for _, prefix := range []string{"command(", "unsandboxed("} {
		if strings.HasPrefix(s, prefix) && strings.HasSuffix(s, ")") {
			inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, prefix), ")"))
			if inner == "" {
				inner = "*"
			}
			return buildSuggestedShellRule(action, s, inner, true), true
		}
	}
	return DiscoveredRule{}, false
}

func parseCodexTOMLFile(scope, path string) *DiscoveredHostFile {
	data, err := readDiscoveryFile(path, scope == "project")
	if err != nil {
		return nil
	}
	var parsed map[string]interface{}
	if toml.Unmarshal(data, &parsed) != nil {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "codex", Scope: scope, Path: path}
	if ap, _ := parsed["approval_policy"].(string); ap == "never" {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf(`approval_policy is "never" in %s (Codex auto-runs passthrough/moderate commands without prompting)`, path),
		})
	}
	if sm, _ := parsed["sandbox_mode"].(string); sm == "danger-full-access" {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_sandbox",
			Detail:   fmt.Sprintf(`sandbox_mode is "danger-full-access" in %s (Codex host sandbox disabled)`, path),
		})
	}
	return out
}

var (
	codexPrefixRuleRe = regexp.MustCompile(`(?s)prefix_rule\s*\(((?:[^)"]|"(?:\\.|[^"\\])*")*)\)`)
	codexPatternRe    = regexp.MustCompile(`(?s)pattern\s*=\s*\[((?:[^\]"]|"(?:\\.|[^"\\])*")*)\]`)
	codexDecisionRe   = regexp.MustCompile(`decision\s*=\s*"(allow|prompt|forbidden)"`)
	codexQuotedTokRe  = regexp.MustCompile(`"((?:\\.|[^"\\])*)"`)
)

func parseCodexRulesFile(scope, path string) *DiscoveredHostFile {
	data, err := readDiscoveryFile(path, scope == "project")
	if err != nil {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "codex", Scope: scope, Path: path}
	cleaned := stripStarlarkComments(string(data))
	matches := codexPrefixRuleRe.FindAllStringSubmatch(cleaned, -1)
	for _, m := range matches {
		body := m[1]
		patMatch := codexPatternRe.FindStringSubmatch(body)
		if patMatch == nil {
			continue
		}
		var tokens []string
		var quotedTokens []string
		for _, tm := range codexQuotedTokRe.FindAllStringSubmatch(patMatch[1], -1) {
			tok := strings.ReplaceAll(tm[1], `\"`, `"`)
			tok = strings.ReplaceAll(tok, `\\`, `\`)
			tokens = append(tokens, tok)
			quotedTokens = append(quotedTokens, fmt.Sprintf("%q", tok))
		}
		if len(tokens) == 0 {
			continue
		}
		decision := "allow"
		if dm := codexDecisionRe.FindStringSubmatch(body); dm != nil {
			decision = dm[1]
		}
		action := "allow"
		switch decision {
		case "prompt":
			action = "ask"
		case "forbidden":
			action = "deny"
		}
		raw := fmt.Sprintf("prefix_rule(pattern=[%s], decision=%q)", strings.Join(quotedTokens, ", "), decision)
		innerTokens := unwrapCodexShellTokens(tokens)
		joined := strings.Join(innerTokens, " ")
		if isComplexInlineShell(joined) {
			out.Rules = append(out.Rules, DiscoveredRule{
				Action:              action,
				Raw:                 raw,
				UnconvertibleReason: "complex inline shell script (prefer an allow-hint or script path rule)",
			})
			continue
		}
		pat := joined
		if !strings.HasSuffix(pat, "*") {
			pat = pat + " *"
		}
		out.Rules = append(out.Rules, buildSuggestedShellRule(action, raw, pat, false))
	}
	return out
}

func stripStarlarkComments(s string) string {
	var b strings.Builder
	inString := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && inString && i+1 < len(s) {
			b.WriteByte(c)
			i++
			b.WriteByte(s[i])
			continue
		}
		if c == '"' {
			inString = !inString
			b.WriteByte(c)
			continue
		}
		if c == '#' && !inString {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			if i < len(s) {
				b.WriteByte('\n')
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func unwrapCodexShellTokens(tokens []string) []string {
	if len(tokens) == 3 {
		base := filepath.Base(tokens[0])
		if (base == "zsh" || base == "bash" || base == "sh") && (tokens[1] == "-lc" || tokens[1] == "-c") {
			return []string{strings.TrimSpace(tokens[2])}
		}
	}
	return tokens
}

func parseCursorConfigFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, false, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "cursor", Scope: scope, Path: path}
	var perms map[string]interface{}
	if p, ok := raw["permissions"].(map[string]interface{}); ok {
		perms = p
	}
	for _, action := range []string{"allow", "deny", "ask"} {
		var items []interface{}
		if perms != nil {
			items, _ = perms[action].([]interface{})
		}
		if len(items) == 0 {
			items, _ = raw[action].([]interface{})
		}
		for _, it := range items {
			s, ok := it.(string)
			if !ok {
				continue
			}
			if dr, ok := convertCursorPermissionRule(action, s); ok {
				out.Rules = append(out.Rules, dr)
			}
		}
	}
	if sb, ok := raw["sandbox"].(map[string]interface{}); ok {
		if enabled, ok := sb["enabled"].(bool); ok && !enabled {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_sandbox",
				Detail:   fmt.Sprintf("sandbox.enabled is false in %s", path),
			})
		}
		if mode, _ := sb["mode"].(string); mode == "disabled" {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_sandbox",
				Detail:   fmt.Sprintf("sandbox.mode is disabled in %s", path),
			})
		}
	}
	return out
}

func convertCursorPermissionRule(action, raw string) (DiscoveredRule, bool) {
	s := strings.TrimSpace(raw)
	if s == "*" || s == "Shell" || s == "Shell(*)" {
		return DiscoveredRule{
			Action:        action,
			Raw:           s,
			SuggestedRule: action + "-cmd *",
		}, true
	}
	if strings.HasPrefix(s, "Shell(") && strings.HasSuffix(s, ")") {
		inner := normalizeColonWildcard(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "Shell("), ")")))
		return buildSuggestedShellRule(action, s, inner, true), true
	}
	return DiscoveredRule{}, false
}

func parseOpencodeConfigFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "opencode", Scope: scope, Path: path}
	perm, _ := raw["permission"].(map[string]interface{})
	if perm == nil {
		return out
	}
	switch bash := perm["bash"].(type) {
	case string:
		if bash == "allow" {
			out.Rules = append(out.Rules, DiscoveredRule{
				Action:        "allow",
				Raw:           `permission.bash="allow"`,
				SuggestedRule: "allow-cmd *",
			})
		}
	case map[string]interface{}:
		keys := make([]string, 0, len(bash))
		for k := range bash {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			act, _ := bash[k].(string)
			if act != "allow" && act != "ask" && act != "deny" {
				continue
			}
			if k == "*" && act == "ask" {
				continue
			}
			rawStr := fmt.Sprintf("permission.bash[%q]=%q", k, act)
			out.Rules = append(out.Rules, buildSuggestedShellRule(act, rawStr, strings.TrimSpace(k), true))
		}
	}
	if readMap, ok := perm["read"].(map[string]interface{}); ok {
		keys := make([]string, 0, len(readMap))
		for k := range readMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if act, _ := readMap[k].(string); act == "deny" {
				if pat := normalizeSensitiveGlob(k); pat != "" {
					out.Rules = append(out.Rules, DiscoveredRule{
						Action:        "sensitive",
						Raw:           fmt.Sprintf("permission.read[%q]=\"deny\"", k),
						SuggestedRule: "sensitive " + pat,
					})
				}
			}
		}
	}
	return out
}

const maxDiscoveryFileBytes = 1 << 20 // 1 MiB

func readDiscoveryFile(path string, rejectSymlink bool) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		if rejectSymlink {
			return nil, fmt.Errorf("refusing symlink %s", path)
		}
		fi, err = os.Stat(path)
		if err != nil {
			return nil, err
		}
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxDiscoveryFileBytes {
		return nil, fmt.Errorf("non-regular or oversize file %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxDiscoveryFileBytes))
}

func readJSONObjectFile(path string, allowJSONC bool, rejectSymlink bool) (map[string]interface{}, bool) {
	data, err := readDiscoveryFile(path, rejectSymlink)
	if err != nil {
		return nil, false
	}
	if allowJSONC {
		data = stripJSONCComments(data)
	}
	var obj map[string]interface{}
	if json.Unmarshal(data, &obj) != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

func stripJSONCComments(data []byte) []byte {
	s := string(data)
	var b strings.Builder
	inString := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && inString && i+1 < len(s) {
			b.WriteByte(c)
			i++
			b.WriteByte(s[i])
			continue
		}
		if c == '"' {
			inString = !inString
			b.WriteByte(c)
			continue
		}
		if !inString && i+1 < len(s) && c == '/' && s[i+1] == '/' {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			if i < len(s) {
				b.WriteByte('\n')
			}
			continue
		}
		if !inString && i+1 < len(s) && c == '/' && s[i+1] == '*' {
			i += 2
			for i+1 < len(s) && !(s[i] == '*' && s[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		b.WriteByte(c)
	}
	return stripTrailingJSONCommas(b.String())
}

func stripTrailingJSONCommas(s string) []byte {
	out := []byte(s)
	inString := false
	for i := 0; i < len(out); i++ {
		if out[i] == '\\' && inString && i+1 < len(out) {
			i++
			continue
		}
		if out[i] == '"' {
			inString = !inString
			continue
		}
		if !inString && out[i] == ',' {
			j := i + 1
			for j < len(out) && (out[j] == ' ' || out[j] == '\t' || out[j] == '\r' || out[j] == '\n') {
				j++
			}
			if j < len(out) && (out[j] == '}' || out[j] == ']') {
				out[i] = ' '
			}
		}
	}
	return out
}

func hasControlOrBiDi(s string) bool {
	for _, r := range s {
		if (r < 0x20 && r != '\t') || r == 0x7F || (r >= 0x80 && r <= 0x9F) ||
			r == 0x2028 || r == 0x2029 || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0xFEFF {
			return true
		}
	}
	return false
}

func isComplexInlineShell(s string) bool {
	return len(s) > 160 || hasControlOrBiDi(s) || strings.Contains(s, ";") || strings.Contains(s, "&&") || strings.Contains(s, "||") ||
		strings.Contains(s, "$(") || strings.Contains(s, "\n") || strings.Contains(s, "\r") || strings.Contains(s, "|") ||
		strings.Contains(s, " >") || strings.Contains(s, " 2>") || strings.Contains(s, "{")
}

func annotateDiscoveredRule(dr *DiscoveredRule, activeRules []Rule, activeSensitive []string) {
	dr.Overlap = RuleOverlap{Status: "none"}
	if dr.SuggestedRule == "" {
		return
	}
	if dr.Action == "sensitive" {
		pat := strings.TrimSpace(strings.TrimPrefix(dr.SuggestedRule, "sensitive "))
		if slices.Contains(activeSensitive, pat) {
			dr.Overlap = RuleOverlap{Status: "exact_duplicate", MatchedBy: "sensitive " + pat}
		}
		return
	}
	ruleType := "cmd"
	prefix := dr.Action + "-cmd "
	if strings.HasPrefix(dr.SuggestedRule, dr.Action+"-path ") {
		ruleType = "path"
		prefix = dr.Action + "-path "
	} else if !strings.HasPrefix(dr.SuggestedRule, prefix) {
		return
	}
	pat := strings.TrimSpace(strings.TrimPrefix(dr.SuggestedRule, prefix))
	if ruleType == "cmd" && dr.Action == "allow" {
		dr.BroadWarning = discoveredAllowBroadWarning(pat, dr.Raw)
	}
	probe := sampleCommandForPattern(pat)
	pathProbe := strings.ReplaceAll(pat, "*", "sample")

	coveredByActiveRule := func(ar Rule) bool {
		if ar.Type == ruleType && ar.Pattern == pat {
			return true
		}
		if ruleType == "path" {
			if ar.Type == "path" && glob.Match(ar.Pattern, pathProbe) {
				return true
			}
			if ar.Type == "cmd" && (ar.Pattern == pat || ar.Pattern == pat+"*") {
				return true
			}
			return false
		}
		if ar.Type != "cmd" {
			return false
		}
		return probe != "" && matchCmd(ar.Pattern, probe)
	}

	conflictsWithActiveRule := func(ar Rule) bool {
		if coveredByActiveRule(ar) {
			return true
		}
		if ruleType == "path" && ar.Type == "path" {
			return glob.Match(pat, strings.ReplaceAll(ar.Pattern, "*", "sample"))
		}
		if ruleType == "cmd" && ar.Type == "cmd" {
			if arProbe := sampleCommandForPattern(ar.Pattern); arProbe != "" && matchCmd(pat, arProbe) {
				return true
			}
		}
		return false
	}

	// Pass 1: check conflicts across all active rules first so an earlier broad
	// allow rule never masks a specific deny/ask conflict.
	for _, ar := range activeRules {
		if ar.Action != dr.Action && ((ar.Type == ruleType && ar.Pattern == pat) || (dr.BroadWarning == "" && conflictsWithActiveRule(ar))) {
			dr.Overlap = RuleOverlap{Status: "conflict", MatchedBy: fmt.Sprintf("%s-%s %s", ar.Action, ar.Type, ar.Pattern)}
			return
		}
	}
	// Pass 2: check duplicates (directional: active rule must cover discovered rule).
	for _, ar := range activeRules {
		if ar.Action == dr.Action && ((ar.Type == ruleType && ar.Pattern == pat) || (dr.BroadWarning == "" && coveredByActiveRule(ar))) {
			dr.Overlap = RuleOverlap{Status: "exact_duplicate", MatchedBy: fmt.Sprintf("%s-%s %s", ar.Action, ar.Type, ar.Pattern)}
			return
		}
	}
	if ruleType == "cmd" && dr.Action == "allow" && dr.BroadWarning == "" && probe != "" && !strings.HasPrefix(pat, "*") {
		if pass, _ := fastallow.IsLocallySafeWith(probe, nil); pass {
			dr.Overlap = RuleOverlap{Status: "covered_by_fast_allow", MatchedBy: "fast_allow"}
		}
	}
}

func discoveredAllowBroadWarning(pat, raw string) string {
	if w := broadAllowCmdWarning(pat); w != "" {
		return w
	}
	if isBroadHostAllowRule(raw) {
		return fmt.Sprintf("allow-cmd %s is overly broad and bypasses the judge for an entire tool family", pat)
	}
	return ""
}

func sampleCommandForPattern(pat string) string {
	p := strings.TrimSpace(pat)
	if p == "" || p == "*" {
		return ""
	}
	if strings.HasSuffix(p, " *") {
		return strings.TrimSuffix(p, " *") + " sample-arg"
	}
	if strings.HasSuffix(p, "*") {
		return strings.TrimSuffix(p, "*")
	}
	return p
}

// cmdRulesDiscover implements `yolonot rules discover [--json] [--cwd <dir>]`.
func cmdRulesDiscover(args []string) {
	cwd, _ := os.Getwd()
	jsonOut := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--json":
			jsonOut = true
		case args[i] == "--cwd" && i+1 < len(args):
			i++
			cwd = args[i]
		case strings.HasPrefix(args[i], "--cwd="):
			cwd = strings.TrimPrefix(args[i], "--cwd=")
		}
	}
	var targets []Harness
	if name := harnessArgument(args); name != "" {
		if h := GetHarness(name); h != nil {
			targets = []Harness{h}
		}
	}
	summary := DiscoverHostPermissions(cwd, targets...)
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
		return
	}

	fmt.Println("yolonot rules discover")
	fmt.Println()
	if len(summary.HostFiles) == 0 {
		fmt.Println("No host permission rules or autoMode hints found across configured harnesses.")
		return
	}

	for _, f := range summary.HostFiles {
		fmt.Printf("[%s · %s] %s\n", f.Harness, f.Scope, sanitizeBanner(f.Path))
		for _, a := range f.PolicyAlerts {
			fmt.Printf("  ⚠ policy: %s\n", sanitizeBanner(a.Detail))
		}
		for _, r := range f.Rules {
			rawLabel := truncateStr(sanitizeBanner(r.Raw), 42)
			sugLabel := sanitizeBanner(r.SuggestedRule)
			matchLabel := sanitizeBanner(r.Overlap.MatchedBy)
			switch {
			case r.UnconvertibleReason != "":
				fmt.Printf("  · %-42s → skip (%s)\n", rawLabel, r.UnconvertibleReason)
			case r.Overlap.Status == "exact_duplicate":
				fmt.Printf("  ✓ %-42s → %s  [already covered by %s]\n", rawLabel, sugLabel, matchLabel)
			case r.Overlap.Status == "covered_by_fast_allow":
				fmt.Printf("  ✓ %-42s → %s  [already covered by fast_allow]\n", rawLabel, sugLabel)
			case r.Overlap.Status == "conflict":
				fmt.Printf("  ! %-42s → %s  [conflicts with %s]\n", rawLabel, sugLabel, matchLabel)
			case r.BroadWarning != "":
				fmt.Printf("  ⚠ %-42s → %s  [too broad: %s]\n", rawLabel, sugLabel, sanitizeBanner(r.BroadWarning))
			default:
				fmt.Printf("  + %-42s → %s\n", rawLabel, sugLabel)
			}
		}
		for _, h := range f.Hints {
			fmt.Printf("  + [%s] %q\n", h.Kind, truncateStr(sanitizeBanner(h.Text), 88))
		}
		fmt.Println()
	}

	fmt.Println("To review and sync these into yolonot with LLM guidance, run in your harness:")
	fmt.Println("  /yolonot sync host permissions")
}

func hasUnsyncedHostEntry(f DiscoveredHostFile, activeHints []DiscoveredHint) bool {
	for _, r := range f.Rules {
		if r.SuggestedRule != "" && r.BroadWarning == "" && r.UnconvertibleReason == "" && r.Overlap.Status == "none" {
			return true
		}
	}
	for _, h := range f.Hints {
		found := false
		for _, ah := range activeHints {
			if ah.Kind == h.Kind && ah.Text == h.Text {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

func printHostPermissionsNudge(cwd string) {
	summary := DiscoverHostPermissions(cwd)
	var names []string
	fileCount := 0
	for _, f := range summary.HostFiles {
		if hasUnsyncedHostEntry(f, summary.ActiveHints) {
			fileCount++
			base := filepath.Base(f.Path)
			if !slices.Contains(names, base) {
				names = append(names, base)
			}
		}
	}
	if fileCount == 0 {
		return
	}
	fmt.Printf("\nHost permissions detected in %d file(s) (%s).\n", fileCount, strings.Join(names, ", "))
	fmt.Println("To review and sync them into yolonot, run in your preferred harness:")
	fmt.Println("  /yolonot sync host permissions")
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
