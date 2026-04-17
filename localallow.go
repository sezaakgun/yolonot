package main

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// IsLocallySafe returns (true, reason) iff the command is provably safe to
// allow without any context. It parses the command with mvdan/sh and walks
// the AST, mirroring Dippy's analyzer behavior:
//
//   - simple commands whose head is in safeCommands (or reaches one via
//     wrapper unwrapping: time, timeout, nice, nohup, strace, ltrace,
//     command, builtin);
//   - pipelines (|, |&), list chaining (&&, ||, ;, newline), subshells,
//     brace groups, and `time` clauses — safe iff all component stmts
//     are safe;
//   - prefix env assignments (FOO=bar ls) when the assigned word is
//     substitution-free;
//   - redirects only to known-benign targets (/dev/null, -, /dev/std*,
//     &N); unsafe targets fall through to the LLM;
//   - word-level substitutions ($(...), <(...), >(...), backticks) are
//     recursively analyzed — a CmdSubst is accepted iff its inner
//     command is itself IsLocallySafe (same for ProcSubst);
//   - heredocs (<<) are accepted when the delimiter is quoted (no
//     expansion) or when the body contains no unsafe substitutions;
//     here-strings (<<<) must have a substitution-free word.
//
// On any doubt the function returns (false, ""); the caller falls through
// to the LLM classifier. This is deliberately conservative — the LLM is
// the safety net, not this function.
// extraAllowRedirectPatterns is consulted by isSafeRedir for output
// redirects whose literal target isn't in safeRedirectTargets. Set by the
// caller (hook.go) from `allow-redirect` rules; the hook binary is a
// short-lived single-threaded process so a package-level var is safe.
var extraAllowRedirectPatterns []string

// IsLocallySafeWith is IsLocallySafe plus allow-redirect patterns — an
// output redirect whose literal target matches any of these globs is
// permitted in the fast-path. Empty list is equivalent to IsLocallySafe.
func IsLocallySafeWith(command string, allowRedirects []string) (bool, string) {
	prev := extraAllowRedirectPatterns
	extraAllowRedirectPatterns = allowRedirects
	defer func() { extraAllowRedirectPatterns = prev }()
	return IsLocallySafe(command)
}

func IsLocallySafe(command string) (bool, string) {
	command = strings.TrimSpace(command)
	if command == "" {
		return false, ""
	}

	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(command), "cmd")
	if err != nil {
		return false, ""
	}
	if len(file.Stmts) == 0 {
		return false, ""
	}

	// Each top-level Stmt (separated by ; or newline) must be safe.
	firstLabel := ""
	for _, stmt := range file.Stmts {
		if !isSafeStmt(stmt) {
			return false, ""
		}
		if firstLabel == "" {
			head, sub := firstHeadAndSub(stmt)
			if head != "" {
				firstLabel = head
				if sub != "" {
					firstLabel = head + " " + sub
				}
			}
		}
	}

	if firstLabel == "" {
		return false, ""
	}
	return true, "built-in allow: " + firstLabel + " is read-only"
}

// isSafeStmt verifies a Stmt (top-level or nested) is safe. Rejects
// background/coprocess/negation; walks redirects and the inner command.
func isSafeStmt(stmt *syntax.Stmt) bool {
	if stmt == nil {
		return false
	}
	if stmt.Background || stmt.Coprocess || stmt.Negated {
		return false
	}
	for _, r := range stmt.Redirs {
		if !isSafeRedir(r) {
			return false
		}
	}
	return isSafeCmd(stmt.Cmd)
}

// isSafeCmd dispatches on the command type. Mirrors the Dippy node kinds
// we care about: CallExpr, pipelines / list chains (BinaryCmd), Subshell,
// Block, TimeClause. Anything else (IfClause, ForClause, WhileClause,
// FuncDecl, LetClause, ArithmCmd, TestClause, CaseClause, DeclClause,
// CoprocClause) falls through to the LLM.
func isSafeCmd(cmd syntax.Command) bool {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		return isSafeCall(c)
	case *syntax.BinaryCmd:
		switch c.Op {
		case syntax.Pipe, syntax.PipeAll, syntax.AndStmt, syntax.OrStmt:
			return isSafeStmt(c.X) && isSafeStmt(c.Y)
		}
		return false
	case *syntax.Subshell:
		for _, s := range c.Stmts {
			if !isSafeStmt(s) {
				return false
			}
		}
		return len(c.Stmts) > 0
	case *syntax.Block:
		for _, s := range c.Stmts {
			if !isSafeStmt(s) {
				return false
			}
		}
		return len(c.Stmts) > 0
	case *syntax.TimeClause:
		if c.Stmt == nil {
			return true // bare `time` — harmless
		}
		return isSafeStmt(c.Stmt)
	default:
		return false
	}
}

// isSafeCall validates a simple command. Rules:
//   - all prefix env assignments must have substitution-free Values;
//   - Args[0] (after assignments) must be a literal word;
//   - head is either in safeCommands, a multiplex head whose Args[1] is
//     a whitelisted subcommand, OR a wrapper that unwraps to a safe
//     inner command;
//   - every Args word must be substitution-free (apart from CmdSubst/
//     ProcSubst that are themselves IsLocallySafe-safe).
func isSafeCall(c *syntax.CallExpr) bool {
	if c == nil {
		return false
	}
	for _, a := range c.Assigns {
		if !isSafeAssign(a) {
			return false
		}
	}
	if len(c.Args) == 0 {
		// Bare `FOO=bar` assignment with no command. Dippy treats this
		// as `env assignment` → allow. But assigns already validated.
		return len(c.Assigns) > 0
	}

	head, ok := literalWord(c.Args[0])
	if !ok {
		return false
	}

	// Version/help short-circuit. Dippy's analyzer runs this check before
	// any CLI-specific handler, so e.g. `gh --help` bypasses ghHandler
	// entirely. We mirror that here to keep parity without duplicating
	// --help/-h/--version logic into every handler.
	if isVersionOrHelp(c.Args) {
		for _, arg := range c.Args {
			if !isSafeWord(arg) {
				return false
			}
		}
		return true
	}

	// xargs delegates to its inner command — handled before the normal
	// wrapper/handler path because it changes the tokens we validate.
	if head == "xargs" {
		// xargs's own words must be substitution-safe.
		for _, arg := range c.Args {
			if !isSafeWord(arg) {
				return false
			}
		}
		inner, ok := xargsUnwrap(wordsToTokens(c.Args))
		if !ok {
			return false
		}
		return analyzeInnerTokens(inner)
	}

	// CLI handlers take precedence over safeCommands / subcommandReadOnly.
	// If a handler exists for this head, it owns the decision.
	if handler, exists := cliHandlers[head]; exists {
		for _, arg := range c.Args {
			if !isSafeWord(arg) {
				return false
			}
		}
		ok, _ := handler(wordsToTokens(c.Args))
		return ok
	}

	// Wrapper unwrapping: time/timeout/nice/nohup/strace/ltrace/command/builtin.
	// `command -v foo` and `command -V foo` are always allowed (Dippy parity).
	if isWrapperCommand(head) {
		if head == "command" && len(c.Args) >= 2 {
			if flag, ok := literalWord(c.Args[1]); ok && (flag == "-v" || flag == "-V") {
				// Still need arg-word safety for the probed name.
				for _, arg := range c.Args {
					if !isSafeWord(arg) {
						return false
					}
				}
				return true
			}
		}
		// Skip numeric and flag tokens to find inner command head.
		inner := skipWrapperPrefix(c.Args[1:])
		if len(inner) == 0 {
			return false
		}
		// Build a synthetic CallExpr for the inner command; reuse isSafeCall.
		inlineCall := &syntax.CallExpr{Args: inner}
		if !isSafeCall(inlineCall) {
			return false
		}
		// Also ensure the wrapper's own args contain no unsafe substitutions.
		for _, arg := range c.Args {
			if !isSafeWord(arg) {
				return false
			}
		}
		return true
	}

	if _, known := safeCommands[head]; !known {
		if !needsSubcommandGate(head) {
			return false
		}
		if len(c.Args) < 2 {
			return false
		}
		sub, ok := literalWord(c.Args[1])
		if !ok {
			return false
		}
		if _, allowed := subcommandReadOnly[head][sub]; !allowed {
			return false
		}
	}

	for _, arg := range c.Args {
		if !isSafeWord(arg) {
			return false
		}
	}
	return true
}

// skipWrapperPrefix walks past numeric args and flags (-n, --foo, --)
// to find the next bare word, mirroring Dippy's wrapper-unwrap loop.
func skipWrapperPrefix(args []*syntax.Word) []*syntax.Word {
	j := 0
	for j < len(args) {
		tok, ok := literalWord(args[j])
		if !ok {
			break
		}
		if isNumeric(tok) {
			j++
			continue
		}
		if tok == "--" {
			j++
			break
		}
		if strings.HasPrefix(tok, "-") && tok != "-" {
			j++
			continue
		}
		break
	}
	return args[j:]
}

// isVersionOrHelp mirrors Dippy's analyzer._is_version_or_help. Allows:
//
//   - 2 tokens with tokens[1] ∈ {help, version, --help, -h, --version}
//   - any command whose last token is --help/-h with total tokens ≤ 4
//
// Checked before CLI handler dispatch so e.g. `git --help` and
// `gh pr --help` short-circuit to allow regardless of the handler's own
// rules.
func isVersionOrHelp(args []*syntax.Word) bool {
	if len(args) < 2 {
		return false
	}
	last, ok := literalWord(args[len(args)-1])
	if !ok {
		return false
	}
	if len(args) == 2 {
		switch last {
		case "help", "version", "--help", "-h", "--version":
			return true
		}
	}
	if (last == "--help" || last == "-h") && len(args) <= 4 {
		return true
	}
	return false
}

// isNumeric returns true for integer or simple decimal literals
// (what `timeout`, `nice -n N`, etc. accept as counts/durations).
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	// Strip trailing unit suffix (Ns, 3m, 1h, 2d) that `timeout` accepts.
	if n := len(s); n > 1 && (s[n-1] == 's' || s[n-1] == 'm' || s[n-1] == 'h' || s[n-1] == 'd') {
		s = s[:n-1]
	}
	sawDot := false
	for i, r := range s {
		if r == '.' {
			if sawDot {
				return false
			}
			sawDot = true
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
		_ = i
	}
	return true
}

// isSafeAssign accepts a prefix env assignment (FOO=bar) whose Value word
// is substitution-free. Rejects array assigns, indexed assigns, and +=
// (which mutates an existing binding in ways the word-safety check
// doesn't cover).
func isSafeAssign(a *syntax.Assign) bool {
	if a == nil {
		return false
	}
	if a.Append || a.Naked || a.Index != nil || a.Array != nil {
		return false
	}
	if a.Name != nil {
		if _, bad := dangerousEnvNames[a.Name.Value]; bad {
			return false
		}
		// GIT_CONFIG_KEY_<N> / GIT_CONFIG_VALUE_<N> pairs (with GIT_CONFIG_COUNT)
		// are the env-var equivalent of `git -c key=value` and can set
		// core.sshCommand / core.editor / alias.* to execute arbitrary shells.
		if strings.HasPrefix(a.Name.Value, "GIT_CONFIG_") {
			return false
		}
	}
	if a.Value == nil {
		return true // bare `FOO=` — empties the var, harmless.
	}
	return isSafeWord(a.Value)
}

// dangerousEnvNames are environment-variable names whose values are
// interpreted as executable commands or config-file overrides, giving a
// prefix assignment the same blast radius as `cmd --flag=value`. Blocking
// them at assignment time covers both `FOO=x cmd` prefix form and any
// later subprocess spawned via an allowlisted command that internally
// shells out.
var dangerousEnvNames = map[string]struct{}{
	// git — arbitrary-exec vectors.
	"GIT_SSH":             {},
	"GIT_SSH_COMMAND":     {},
	"GIT_EXTERNAL_DIFF":   {},
	"GIT_PAGER":           {},
	"GIT_EDITOR":          {},
	"GIT_SEQUENCE_EDITOR": {},
	// Generic editor/pager overrides — same class.
	"EDITOR":        {},
	"VISUAL":        {},
	"PAGER":         {},
	// kube/helm/docker — config-file redirection (re-covered by CLI flag
	// handlers, but prefix form would bypass those handlers entirely).
	"KUBECONFIG": {},
	"DOCKER_CONFIG": {},
	"DOCKER_HOST":   {},
	// LD_PRELOAD / DYLD_INSERT_LIBRARIES load attacker libs into any
	// spawned child — the nuclear option.
	"LD_PRELOAD":             {},
	"LD_LIBRARY_PATH":        {},
	"DYLD_INSERT_LIBRARIES":  {},
	"DYLD_LIBRARY_PATH":      {},
	"DYLD_FALLBACK_LIBRARY_PATH": {},
	// PATH prefix manipulation points every unqualified command at an
	// attacker directory.
	"PATH": {},
}

// hasPathTraversal reports whether any slash-separated component of p is
// exactly `..` — the one-component case that lets `/tmp/*` glob-match
// `/tmp/../etc/passwd`. `.` components are harmless; we don't flag those.
func hasPathTraversal(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// safeRedirectTargets mirrors Dippy's SAFE_REDIRECT_TARGETS exactly.
// Notably excludes /dev/stderr — Dippy treats stderr redirects as user
// output and prompts.
var safeRedirectTargets = map[string]struct{}{
	"/dev/null":   {},
	"-":           {},
	"/dev/stdout": {},
	"/dev/stdin":  {},
}

// isSafeRedir accepts redirects whose target is in safeRedirectTargets
// or is an FD duplication (&N). Rejects heredocs unless the delimiter is
// quoted (in which case the body is literal, safe) or the body contains
// no unsafe substitutions. Rejects here-strings unless their word is
// substitution-free.
func isSafeRedir(r *syntax.Redirect) bool {
	if r == nil {
		return false
	}

	switch r.Op {
	case syntax.Hdoc, syntax.DashHdoc:
		// <<EOF / <<-EOF — delimiter is r.Word, body is r.Hdoc.
		if isQuotedDelimiter(r.Word) {
			return true // body is taken literally, no expansion.
		}
		// Unquoted delimiter: body may expand substitutions.
		return isSafeHeredocBody(r.Hdoc)
	case syntax.WordHdoc:
		// <<< "word" — single-word stdin.
		return isSafeWord(r.Word)
	case syntax.RdrIn:
		// Input redirect `< path` is a read. Dippy only checks output
		// redirects against config — stdin redirects are always safe as
		// long as the target word is substitution-free.
		if r.Word == nil {
			return false
		}
		return isSafeWord(r.Word)
	case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrClob:
		// Fallthrough to target check.
	case syntax.DplIn, syntax.DplOut:
		// FD duplication: <& N or >& N. Target must be a literal fd
		// (digit string) or `-` to close. Writing to a pre-existing fd
		// is as safe as whatever opened it; we accept.
		target, ok := literalWord(r.Word)
		if !ok {
			return false
		}
		if target == "-" {
			return true
		}
		for _, c := range target {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	default:
		// RdrInOut (<>), AppClob (>>|), RdrAllClob (&>|), AppAllClob (&>>|)
		// — too bash-rare to whitelist; fall through.
		return false
	}

	if r.Word == nil {
		return false
	}
	target, ok := literalWord(r.Word)
	if !ok {
		// Target contains substitutions. Check them recursively — even
		// if the eventual path is non-benign, a safe cmdsub inside is
		// fine (Dippy walks these too). But we also can't know the
		// eventual target, so reject outright unless we can prove the
		// concrete target is safe. Conservative: reject.
		return false
	}
	if _, ok := safeRedirectTargets[target]; ok {
		return true
	}
	// User-declared-safe redirect targets via `allow-redirect <glob>`.
	// Only consulted for output redirects (Rdr/App variants); input redirects
	// were accepted above as substitution-free reads. The target must still
	// be a literal path (we got here via literalWord), so glob matching is
	// deterministic.
	//
	// Path-traversal guard: reject any target whose path components contain
	// `..`. Without this, `allow-redirect /tmp/*` would match
	// `/tmp/../etc/passwd` because our glob treats `*` as matching `/`.
	// We check on the raw target (before Clean) so `foo/../bar` is rejected
	// regardless of how the shell would eventually resolve it.
	if !hasPathTraversal(target) {
		for _, pat := range extraAllowRedirectPatterns {
			if globMatch(pat, target) {
				return true
			}
		}
	}
	if strings.HasPrefix(target, "&") {
		rest := target[1:]
		if rest == "" {
			return false
		}
		for _, c := range rest {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// isQuotedDelimiter reports whether a heredoc delimiter word is quoted
// (in whole or in part). A quoted delimiter disables expansion of the
// body, making it a plain literal.
func isQuotedDelimiter(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		switch part.(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
			return true
		}
	}
	return false
}

// isSafeHeredocBody walks a heredoc body Word. Literal parts are fine;
// CmdSubst and ArithmExp recursively analyzed as full commands.
func isSafeHeredocBody(w *syntax.Word) bool {
	if w == nil {
		return true
	}
	for _, part := range w.Parts {
		if !isSafePart(part) {
			return false
		}
	}
	return true
}

// isSafeWord walks a Word's parts and rejects unsafe expansions. Literal
// text, single/double-quoted strings, parameter references, and
// *substitution-safe* CmdSubst/ProcSubst are accepted. A CmdSubst is safe
// iff its inner command is IsLocallySafe-safe — this matches Dippy's
// recursive analyze() call on cmdsub bodies.
func isSafeWord(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		if !isSafePart(part) {
			return false
		}
	}
	return true
}

func isSafePart(part syntax.WordPart) bool {
	switch p := part.(type) {
	case *syntax.Lit:
		return true
	case *syntax.SglQuoted:
		return true
	case *syntax.DblQuoted:
		for _, inner := range p.Parts {
			if !isSafePart(inner) {
				return false
			}
		}
		return true
	case *syntax.ParamExp:
		return isSafeParamExp(p)
	case *syntax.CmdSubst:
		return isSafeCmdSubst(p)
	case *syntax.ProcSubst:
		return isSafeProcSubst(p)
	case *syntax.ArithmExp:
		// Arithmetic expressions can embed CmdSubst (e.g. $(( $(cmd) + 1 )))
		// but mvdan/sh represents those under ArithmExpr; rejecting wholesale
		// is the conservative choice. Dippy inspects for cmdsubs but yolonot
		// prefers fall-through.
		return false
	case *syntax.ExtGlob:
		// Extended globs (!(...), @(...), ?(...)). mvdan/sh stores the
		// pattern as a single *Lit — it doesn't recurse into nested
		// substitutions. Bash, however, WILL evaluate `$(…)` / backticks
		// inside an extglob at match time. Reject anything that contains
		// substitution-introducing characters to avoid a hidden approval
		// of e.g. `ls !(.git|$(rm foo))`.
		if p.Pattern == nil {
			return true
		}
		if strings.ContainsAny(p.Pattern.Value, "$`") {
			return false
		}
		return true
	default:
		return false
	}
}

// isSafeCmdSubst returns true iff every Stmt inside the cmdsub is itself
// safe. This is the recursive hook matching Dippy's analyze() call on
// cmdsub.command. Empty cmdsubs ($()) are rejected — no head to name,
// and Dippy's analyzer would ask on empty anyway.
func isSafeCmdSubst(c *syntax.CmdSubst) bool {
	if c == nil {
		return false
	}
	if len(c.Stmts) == 0 {
		return false
	}
	for _, s := range c.Stmts {
		if !isSafeStmt(s) {
			return false
		}
	}
	return true
}

// isSafeProcSubst mirrors isSafeCmdSubst for <( ) / >( ).
func isSafeProcSubst(p *syntax.ProcSubst) bool {
	if p == nil {
		return false
	}
	if len(p.Stmts) == 0 {
		return false
	}
	for _, s := range p.Stmts {
		if !isSafeStmt(s) {
			return false
		}
	}
	return true
}

// isSafeParamExp allows bare ${VAR} / $VAR reads with the simplest operators
// (default / alternate / length / substring). Rejects anything that could
// assign, prompt, or evaluate a subexpression.
func isSafeParamExp(p *syntax.ParamExp) bool {
	if p == nil {
		return false
	}
	if p.Excl || p.Names != 0 {
		return false
	}
	if p.Exp != nil {
		switch p.Exp.Op {
		case syntax.AssignUnset, syntax.AssignUnsetOrNull, syntax.ErrorUnset, syntax.ErrorUnsetOrNull:
			return false
		}
		if p.Exp.Word != nil && !isSafeWord(p.Exp.Word) {
			return false
		}
	}
	if p.Slice != nil {
		return false
	}
	if p.Repl != nil {
		if p.Repl.Orig != nil && !isSafeWord(p.Repl.Orig) {
			return false
		}
		if p.Repl.With != nil && !isSafeWord(p.Repl.With) {
			return false
		}
	}
	return true
}

// literalWord returns the Word's text if it's a plain literal (no
// substitutions, no expansions). Concatenated literals like foo"bar"'baz'
// are joined.
func literalWord(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				sb.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return sb.String(), true
}

// firstHeadAndSub extracts the command name (and subcommand, for multiplex
// heads) for the reason string. Walks into pipelines, subshells, blocks,
// and time clauses to find the first leaf command.
func firstHeadAndSub(stmt *syntax.Stmt) (string, string) {
	if stmt == nil {
		return "", ""
	}
	switch c := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if len(c.Args) == 0 {
			return "", ""
		}
		head, _ := literalWord(c.Args[0])
		if isWrapperCommand(head) && len(c.Args) > 1 {
			inner := skipWrapperPrefix(c.Args[1:])
			if len(inner) > 0 {
				if h, ok := literalWord(inner[0]); ok {
					if hasSubcommandLabel(h) && len(inner) >= 2 {
						sub, _ := literalWord(inner[1])
						return h, sub
					}
					return h, ""
				}
			}
		}
		if hasSubcommandLabel(head) && len(c.Args) >= 2 {
			sub, _ := literalWord(c.Args[1])
			return head, sub
		}
		return head, ""
	case *syntax.BinaryCmd:
		return firstHeadAndSub(c.X)
	case *syntax.Subshell:
		if len(c.Stmts) > 0 {
			return firstHeadAndSub(c.Stmts[0])
		}
	case *syntax.Block:
		if len(c.Stmts) > 0 {
			return firstHeadAndSub(c.Stmts[0])
		}
	case *syntax.TimeClause:
		return firstHeadAndSub(c.Stmt)
	}
	return "", ""
}
