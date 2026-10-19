package yolonot

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// inlineScriptSQRe / inlineScriptDQRe extract `-c '...'` / `-c "..."`
// one-liner bodies. Two regexes instead of one because RE2 has no
// backreferences: a shared ["'] open/close class can close on the wrong
// quote kind and truncate the body at the first embedded quote
// (`bash -c "echo 'hi'; rm -rf /"` used to capture just `echo `). (?s)
// lets bodies span newlines — agents emit multiline -c scripts routinely.
var (
	inlineScriptSQRe = regexp.MustCompile(`(?s)-c[ \t]+'([^']*)'`)
	inlineScriptDQRe = regexp.MustCompile(`(?s)-c[ \t]+"((?:[^"\\]|\\.)*)"`)
)

// extractInlineScript returns the body of the first `-c` one-liner in
// command, or "" if none. When both quote forms appear, the earlier one in
// the command wins.
func extractInlineScript(command string) string {
	sq := inlineScriptSQRe.FindStringSubmatchIndex(command)
	dq := inlineScriptDQRe.FindStringSubmatchIndex(command)
	switch {
	case sq == nil && dq == nil:
		return ""
	case sq == nil:
		return command[dq[2]:dq[3]]
	case dq == nil:
		return command[sq[2]:sq[3]]
	case sq[0] < dq[0]:
		return command[sq[2]:sq[3]]
	default:
		return command[dq[2]:dq[3]]
	}
}

// scriptExtRe recognizes a script-file token after quote/punctuation
// stripping. A superset of scriptPathRe's extension list, case-insensitive.
// scriptPathRe itself stays untouched: user `*-path` rules match against
// what it extracts, and widening it would silently change rule semantics.
var scriptExtRe = regexp.MustCompile(`(?i)\.(py|sh|bash|zsh|js|mjs|cjs|ts|tsx|jsx|rb|pl|php|lua|go|ps1|fish|awk|r|sql)$`)

// scriptRef is one script-file token referenced by a command: the token as
// written, the absolute path it resolves to ("" when it cannot be resolved
// SAFELY — an unexpandable $VAR, or a relative path with no positional
// proof of execution), and whether the token is PROVEN to be the file the
// command executes (see provenScriptToken) rather than a referenced
// data/argument file (`psql -f x.sql`, an absolute path in a compound
// command).
type scriptRef struct {
	raw      string
	abs      string
	executed bool
}

// scriptInterpreters is the CLOSED list of interpreters whose first
// non-flag operand is, by the tool's own CLI grammar, a script file opened
// relative to the process working directory. Matched against the bare
// command word only — never a path form like ./venv/bin/python, because a
// path inside the (attacker-writable) repo can be any binary wearing an
// interpreter's name. Every addition must be reviewed against three facts:
// (1) the first non-dash operand is the script file and it halts the
// tool's own option parsing, (2) the file is opened relative to the
// process cwd, with no PATH search that could win over an existing cwd
// file, and (3) the tool has no positional (non-dash) chdir.
//
// Deliberately excluded: bun / npm / pnpm / yarn / go / cargo / deno
// (operand is a package, module, or registered task name — attaching a
// same-named file would be a decoy), `source` / `.` (bash searches PATH
// BEFORE cwd for source targets), fish / pwsh / powershell (operand
// semantics not verified against the three facts above).
var scriptInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"python": true, "python2": true, "python3": true,
	"node": true, "ruby": true, "perl": true, "php": true, "lua": true,
}

// isInterpreterWord reports whether the bare word w is a whitelisted
// interpreter, including versioned python spellings (python3.12).
func isInterpreterWord(w string) bool {
	if scriptInterpreters[w] {
		return true
	}
	rest, ok := strings.CutPrefix(w, "python")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// isInertCommand reports whether every byte of command belongs to a small
// whitelisted alphabet on which bash performs NO interpretation beyond
// whitespace word-splitting: letters, digits, space, tab, and . _ - / = +
// : , @. On this class there are no quotes, no escapes, no expansions
// ($ ` ~ * ? [ {), no separators or redirects (; & | < > ( ) newline), and
// no comments — so strings.Fields(command) is PROVABLY identical to the
// argv bash builds, and the command is provably a single simple command.
func isInertCommand(command string) bool {
	for i := 0; i < len(command); i++ {
		b := command[i]
		switch {
		case b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9':
		case b == ' ' || b == '\t':
		case b == '.' || b == '_' || b == '-' || b == '/' || b == '=' ||
			b == '+' || b == ':' || b == ',' || b == '@':
		default:
			return false
		}
	}
	return true
}

// provenScriptToken returns the one token of command that PROVABLY names
// the file bash will execute (or hand to an interpreter), or "" when no
// such proof exists.
func provenScriptToken(command string) string {
	_, exp := provenScriptWords(strings.Fields(command), nil)
	return exp
}

var varRefRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

func expandKnownVars(s string, vars map[string]string) string {
	if len(vars) == 0 || !strings.Contains(s, "$") {
		return s
	}
	return varRefRe.ReplaceAllStringFunc(s, func(m string) string {
		name := strings.TrimPrefix(m, "$")
		name = strings.TrimPrefix(name, "{")
		name = strings.TrimSuffix(name, "}")
		if v, ok := vars[name]; ok {
			return v
		}
		return m
	})
}

func expandHomeVarOnly(p string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	switch {
	case p == "$HOME" || p == "${HOME}":
		return home
	case strings.HasPrefix(p, "$HOME/"):
		return filepath.Join(home, p[len("$HOME/"):])
	case strings.HasPrefix(p, "${HOME}/"):
		return filepath.Join(home, p[len("${HOME}/"):])
	}
	return p
}

// expandWord resolves a single whitespace-delimited shell word into its raw
// token (without outer quotes) and its expanded path value, honoring bash
// quoting rules.
func expandWord(w string, vars map[string]string) (raw string, expanded string, ok bool) {
	if len(w) >= 2 && w[0] == '\'' && w[len(w)-1] == '\'' {
		inner := w[1 : len(w)-1]
		if strings.ContainsRune(inner, '\'') || !isInertCommand(inner) {
			return "", "", false
		}
		return inner, inner, true
	}
	if len(w) >= 2 && w[0] == '"' && w[len(w)-1] == '"' {
		inner := w[1 : len(w)-1]
		if strings.ContainsAny(inner, `"\\`) {
			return "", "", false
		}
		exp := expandHomeVarOnly(inner)
		exp = expandKnownVars(exp, vars)
		if !isInertCommand(exp) {
			return "", "", false
		}
		return inner, exp, true
	}
	exp := expandUserPath(w)
	exp = expandKnownVars(exp, vars)
	if !isInertCommand(exp) {
		return "", "", false
	}
	return w, exp, true
}

func provenScriptWords(rawFields []string, vars map[string]string) (rawTok, expTok string) {
	if len(rawFields) == 0 {
		return "", ""
	}
	raws := make([]string, len(rawFields))
	exps := make([]string, len(rawFields))
	for i, f := range rawFields {
		r, e, ok := expandWord(f, vars)
		if !ok {
			return "", ""
		}
		raws[i] = r
		exps[i] = e
	}
	if len(exps) >= 3 && exps[0] == "uv" && exps[1] == "run" && !strings.HasPrefix(exps[2], "-") && !strings.HasPrefix(exps[2], "+") {
		raws = raws[2:]
		exps = exps[2:]
	}
	if len(exps) == 0 {
		return "", ""
	}
	switch {
	case isInterpreterWord(exps[0]):
		if len(exps) < 2 || strings.HasPrefix(exps[1], "-") || strings.HasPrefix(exps[1], "+") {
			return "", ""
		}
		return raws[1], exps[1]
	case strings.Contains(exps[0], "/"):
		return raws[0], exps[0]
	}
	return "", ""
}

var heredocStartRe = regexp.MustCompile(`<<(-?)\s*(?:'([^']*)'|"([^"]*)"|\\?([A-Za-z0-9_.-]+))`)

// stripHeredocs removes heredoc operators (`<<EOF`, `<<'EOF'`, `<<-EOF`) and
// their bodies while preserving commands on the header line and lines after the
// closing delimiter. If a heredoc is unclosed or malformed, truncates at `<<`.
func stripHeredocs(command string) string {
	if !strings.Contains(command, "<<") {
		return command
	}
	lines := strings.Split(command, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		searchLine := strings.ReplaceAll(line, "<<<", "   ")
		idx := strings.Index(searchLine, "<<")
		if idx < 0 {
			out = append(out, line)
			continue
		}
		m := heredocStartRe.FindStringSubmatchIndex(searchLine[idx:])
		if m == nil || m[0] != 0 {
			out = append(out, line[:idx])
			return strings.Join(out, "\n")
		}
		stripTabs := m[2] != m[3] && searchLine[idx+m[2]:idx+m[3]] == "-"
		var delim string
		switch {
		case m[4] != -1:
			delim = line[idx+m[4] : idx+m[5]]
		case m[6] != -1:
			delim = line[idx+m[6] : idx+m[7]]
		case m[8] != -1:
			delim = line[idx+m[8] : idx+m[9]]
		}
		if delim == "" {
			out = append(out, line[:idx])
			return strings.Join(out, "\n")
		}
		header := line[:idx] + " " + line[idx+m[1]:]
		out = append(out, header)
		closed := false
		for i+1 < len(lines) {
			i++
			check := lines[i]
			if stripTabs {
				check = strings.TrimLeft(check, "\t")
			}
			if check == delim {
				closed = true
				break
			}
		}
		if !closed {
			return strings.Join(out, "\n")
		}
	}
	return strings.Join(out, "\n")
}

// blankCodeQuotes blanks every quoted region that contains whitespace —
// i.e. a code body / message / multi-word string — while preserving quoted
// single-word tokens (a quoted script PATH like "scripts/x.sh").
func blankCodeQuotes(command string) string {
	rs := []rune(command)
	out := make([]rune, len(rs))
	copy(out, rs)
	inS, inD, esc := false, false, false
	start := -1
	hasSpace := false
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case esc:
			esc = false
		case r == '\\' && !inS:
			esc = true
		case r == '\'' && !inD:
			if !inS {
				inS, start, hasSpace = true, i, false
			} else {
				inS = false
				if hasSpace {
					for j := start; j <= i; j++ {
						out[j] = ' '
					}
				}
			}
		case r == '"' && !inS:
			if !inD {
				inD, start, hasSpace = true, i, false
			} else {
				inD = false
				if hasSpace {
					for j := start; j <= i; j++ {
						out[j] = ' '
					}
				}
			}
		case (inS || inD) && (r == ' ' || r == '\t' || r == '\n'):
			hasSpace = true
		}
	}
	return string(out)
}

// extractScriptRefs finds script-file tokens referenced anywhere in
// command, for ENRICHMENT only — the provably-executed file is identified
// separately by provenScriptToken.
func extractScriptRefs(command string) []scriptRef {
	return extractScriptRefsWithVars(command, nil)
}

func extractScriptRefsWithVars(command string, vars map[string]string) []scriptRef {
	sanitized := blankCodeQuotes(stripHeredocs(command))
	redirectTargets := map[string]bool{}
	for _, m := range redirectTargetRe.FindAllStringSubmatch(sanitized, -1) {
		t := strings.TrimFunc(m[1], func(r rune) bool {
			return strings.ContainsRune(`"'();,`, r)
		})
		redirectTargets[t] = true
		if len(vars) > 0 {
			redirectTargets[expandKnownVars(t, vars)] = true
		}
	}
	sanitized = strings.Map(func(r rune) rune {
		if strings.ContainsRune(";|&<>()\n", r) {
			return ' '
		}
		return r
	}, sanitized)
	var refs []scriptRef
	for _, tok := range strings.Fields(sanitized) {
		cand := strings.TrimFunc(tok, func(r rune) bool {
			return strings.ContainsRune(`"'();,`, r)
		})
		expCand := expandKnownVars(cand, vars)
		if !scriptExtRe.MatchString(cand) || strings.Contains(cand, "://") || redirectTargets[cand] || redirectTargets[expCand] {
			continue
		}
		refs = append(refs, scriptRef{raw: cand, abs: resolveScriptPath(expCand)})
	}
	return refs
}

var redirectTargetRe = regexp.MustCompile(`&?>>?\|?\s*([^\s;|&<>()]+)`)

type provenHit struct {
	raw   string
	token string
	dir   string
}

var shellKeywords = map[string]bool{"if": true, "then": true, "else": true, "elif": true, "while": true, "until": true, "do": true, "time": true}

var cwdBuiltins = map[string]bool{
	"cd": true, "pushd": true, "popd": true, "source": true, ".": true, "eval": true, "builtin": true, "command": true, "exec": true,
	"alias": true, "unalias": true, "shopt": true, "enable": true, "export": true, "set": true, "declare": true, "typeset": true,
	"readonly": true, "local": true, "unset": true, "trap": true, "hash": true,
}

var fileMutatingCmds = map[string]bool{
	"cp": true, "mv": true, "rm": true, "ln": true, "install": true, "dd": true, "tee": true,
	"truncate": true, "patch": true, "sed": true, "awk": true, "perl": true, "ruby": true,
	"rsync": true, "tar": true, "unzip": true, "gunzip": true, "bunzip2": true, "xz": true,
	"curl": true, "wget": true, "git": true, "chmod": true, "chown": true, "touch": true,
}

var targetMutatingCmds = map[string]bool{
	"cp": true, "mv": true, "rm": true, "ln": true, "install": true, "tee": true, "truncate": true,
}

var metadataOnlyCmds = map[string]bool{
	"chmod": true, "chown": true, "touch": true,
}

var readOnlyGitSubcmds = map[string]bool{
	"status": true, "diff": true, "log": true, "show": true, "rev-parse": true,
	"branch": true, "tag": true, "remote": true, "describe": true, "ls-files": true,
	"ls-tree": true, "cat-file": true, "for-each-ref": true, "shortlog": true,
	"blame": true, "grep": true, "reflog": true, "config": true, "version": true, "help": true,
}

func isReadOnlyGitCommand(words []string) bool {
	for i := 1; i < len(words); i++ {
		w := words[i]
		if w == "-C" || w == "-c" || w == "--git-dir" || w == "--work-tree" {
			i++
			continue
		}
		if strings.HasPrefix(w, "-") {
			continue
		}
		return readOnlyGitSubcmds[w]
	}
	return false
}

var dangerousEnvVars = map[string]bool{
	"HOME": true, "CDPATH": true, "PATH": true, "IFS": true, "ENV": true, "BASH_ENV": true,
	"LD_PRELOAD": true, "DYLD_INSERT_LIBRARIES": true, "PYTHONPATH": true, "NODE_OPTIONS": true,
	"RUBYOPT": true, "PERL5OPT": true,
}

var envAssignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func isTaintedScript(cand string, tainted []string) bool {
	if cand == "" || len(tainted) == 0 {
		return false
	}
	candClean := filepath.Clean(cand)
	candBase := filepath.Base(candClean)
	for _, t := range tainted {
		tClean := filepath.Clean(t)
		if candClean == tClean || candBase == filepath.Base(tClean) {
			return true
		}
		if tClean == "." || strings.HasPrefix(candClean, tClean+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func provenScriptTokens(command string) []provenHit {
	hits, _, _ := provenScriptTokensAndTaint(command)
	return hits
}

// provenScriptTokensAndTaint extends provenScriptToken's proof across a list of
// simple commands, tracking target-specific file taint and simple literal
// variable assignments across segments.
func provenScriptTokensAndTaint(command string) ([]provenHit, []string, map[string]string) {
	command = stripHeredocs(command)
	command = strings.NewReplacer(">&1", " ", ">&2", " ", "<&0", " ", ">&", "> ", "&>", " >", "<&", "< ").Replace(command)
	var hits []provenHit
	var tainted []string
	vars := map[string]string{}
	dir := ""
	for i, seg := range splitSimpleCommands(command) {
		head := seg.text
		hasFileRedirect := strings.Contains(head, ">")
		var segRedirectTargets []string
		if hasFileRedirect {
			for _, m := range redirectTargetRe.FindAllStringSubmatch(head, -1) {
				_, expTarget, ok := expandWord(m[1], vars)
				if !ok || expTarget == "" {
					return hits, append(tainted, "."), vars
				}
				segRedirectTargets = append(segRedirectTargets, expTarget)
			}
			if len(segRedirectTargets) == 0 {
				return hits, append(tainted, "."), vars
			}
		}
		if idx := strings.IndexAny(head, "<>"); idx >= 0 {
			head = head[:idx]
		}
		words := strings.Fields(head)
		bare := len(words) > 0 && words[0] == "cd"
		hasKeyword := false
		for len(words) > 0 && shellKeywords[words[0]] {
			hasKeyword = true
			words = words[1:]
		}
		var segAssigns [][2]string
		for len(words) > 0 && envAssignRe.MatchString(words[0]) {
			eq := strings.IndexByte(words[0], '=')
			name, val := words[0][:eq], words[0][eq+1:]
			if dangerousEnvVars[name] {
				return hits, tainted, vars
			}
			segAssigns = append(segAssigns, [2]string{name, val})
			words = words[1:]
		}
		if len(words) > 0 && words[0] == "cd" {
			target, ok := literalCdTarget(words, vars)
			if !ok || !bare || i != 0 || hasFileRedirect || (seg.term != "&&" && seg.term != ";" && seg.term != "\n") {
				return hits, tainted, vars
			}
			dir = target
			continue
		}
		if len(words) == 0 {
			if hasFileRedirect || hasKeyword || (seg.term != "&&" && seg.term != ";" && seg.term != "\n" && seg.term != "") {
				return hits, append(tainted, segRedirectTargets...), vars
			}
			for _, kv := range segAssigns {
				_, expVal, ok := expandWord(kv[1], vars)
				if !ok {
					return hits, tainted, vars
				}
				vars[kv[0]] = expVal
			}
			continue
		}
		_, cmdWord, cmdOK := expandWord(words[0], vars)
		if !cmdOK {
			return hits, append(tainted, "."), vars
		}
		baseCmd := filepath.Base(cmdWord)
		if cwdBuiltins[baseCmd] {
			return hits, tainted, vars
		}
		expWords := make([]string, len(words))
		expWords[0] = cmdWord
		for wi := 1; wi < len(words); wi++ {
			_, ew, ok := expandWord(words[wi], vars)
			if !ok {
				if fileMutatingCmds[baseCmd] && !metadataOnlyCmds[baseCmd] {
					return hits, append(tainted, "."), vars
				}
				return hits, tainted, vars
			}
			expWords[wi] = ew
		}
		if fileMutatingCmds[baseCmd] {
			switch {
			case metadataOnlyCmds[baseCmd]:
				// chmod/chown/touch do not alter file contents.
			case baseCmd == "git" && isReadOnlyGitCommand(expWords):
				// Read-only git subcommand.
			case targetMutatingCmds[baseCmd]:
				added := 0
				for _, arg := range expWords[1:] {
					if strings.HasPrefix(arg, "-") {
						continue
					}
					tainted = append(tainted, arg)
					added++
				}
				if added == 0 {
					return hits, append(tainted, "."), vars
				}
			default:
				return hits, append(tainted, "."), vars
			}
			tainted = append(tainted, segRedirectTargets...)
			continue
		}
		rawTok, expTok := provenScriptWords(words, vars)
		if expTok != "" {
			if isTaintedScript(expTok, tainted) || isTaintedScript(rawTok, tainted) {
				tainted = append(tainted, expTok)
				return hits, tainted, vars
			}
			hits = append(hits, provenHit{raw: rawTok, token: expTok, dir: dir})
		} else if isInterpreterWord(baseCmd) {
			return hits, tainted, vars
		}
		tainted = append(tainted, segRedirectTargets...)
	}
	return hits, tainted, vars
}

func literalCdTarget(words []string, vars map[string]string) (string, bool) {
	if len(words) != 2 || strings.HasPrefix(words[1], "-") {
		return "", false
	}
	_, target, ok := expandWord(words[1], vars)
	if !ok {
		return "", false
	}
	if !filepath.IsAbs(target) && os.Getenv("CDPATH") != "" {
		return "", false
	}
	return target, true
}

type simpleCommand struct {
	text string
	term string
}

func splitSimpleCommands(command string) []simpleCommand {
	var out []simpleCommand
	start := 0
	for i := 0; i < len(command); i++ {
		term := ""
		switch {
		case strings.HasPrefix(command[i:], "&&"):
			term = "&&"
		case strings.HasPrefix(command[i:], "||"):
			term = "||"
		case command[i] == ';', command[i] == '|', command[i] == '&':
			term = command[i : i+1]
		case command[i] == '\n':
			term = "\n"
		}
		if term == "" {
			continue
		}
		out = append(out, simpleCommand{text: command[start:i], term: term})
		i += len(term) - 1
		start = i + 1
	}
	return append(out, simpleCommand{text: command[start:]})
}

func expandUserPath(p string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	switch {
	case p == "~" || p == "$HOME" || p == "${HOME}":
		return home
	case strings.HasPrefix(p, "~/"):
		return filepath.Join(home, p[2:])
	case strings.HasPrefix(p, "$HOME/"):
		return filepath.Join(home, p[len("$HOME/"):])
	case strings.HasPrefix(p, "${HOME}/"):
		return filepath.Join(home, p[len("${HOME}/"):])
	}
	return p
}

func resolveScriptPath(cand string) string {
	cand = expandUserPath(cand)
	if strings.ContainsAny(cand, "$`") {
		return ""
	}
	if filepath.IsAbs(cand) {
		return filepath.Clean(cand)
	}
	return ""
}

const (
	maxAttachedScripts       = 3
	maxWithheldNotes         = 3
	maxAttachBytes           = 64 * 1024
	maxClassifierPromptBytes = 128 * 1024
)

const (
	whReasonCapReached = iota
	whReasonSensitive
	whReasonOutside
	whReasonUnreadable
	whReasonTooLarge
	whReasonNotText
	whReasonUnproven
	whReasonUnresolved
)

var withholdReasonText = map[int]string{
	whReasonCapReached: "attachment limit reached",
	whReasonSensitive:  "under a sensitive directory that is never attached",
	whReasonOutside:    "outside the project directory",
	whReasonUnreadable: "file not readable",
	whReasonTooLarge:   "file exceeds the attach size limit; a truncated view is never attached",
	whReasonNotText:    "binary or non-UTF-8 file",
	whReasonUnproven:   "not provably the file this command executes (only `<interpreter> <script>` or a path as the command word attaches, and only while the working directory is known)",
	whReasonUnresolved: "path could not be resolved",
}

func renderAttachedScript(content []byte) string {
	lines := strings.Split(string(content), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i, ln := range lines {
		if looksLikeSecret(ln) {
			lines[i] = "<redacted line — looks like a secret>"
		}
	}
	return strings.Join(lines, "\n")
}

type attachedScript struct {
	ref     scriptRef
	content []byte
	digest  [32]byte
	outside bool
}

type withheldScript struct {
	ref    scriptRef
	reason int
}

var (
	errScriptTooLarge = errors.New("script exceeds the attach size limit")
	errScriptNotText  = errors.New("script is not valid UTF-8 text")
)

func readScriptForPrompt(path string) (content []byte, digest [32]byte, err error) {
	f, err := openReadOnlyNoFollow(path)
	if err != nil {
		return nil, digest, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, digest, err
	}
	if !fi.Mode().IsRegular() {
		return nil, digest, fmt.Errorf("not a regular file")
	}
	content, err = io.ReadAll(io.LimitReader(f, maxAttachBytes+1))
	if err != nil {
		return nil, digest, err
	}
	if len(content) > maxAttachBytes {
		return nil, digest, errScriptTooLarge
	}
	if !utf8.Valid(content) {
		return nil, digest, errScriptNotText
	}
	return content, sha256.Sum256(content), nil
}

func collectScripts(command, cwd string) ([]attachedScript, []withheldScript) {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	root := attachRoot(cwd)

	var refs []scriptRef
	proven := map[string]bool{}
	hits, tainted, vars := provenScriptTokensAndTaint(command)
	for _, hit := range hits {
		abs := expandUserPath(hit.token)
		if !filepath.IsAbs(abs) {
			base := cwd
			if hit.dir != "" {
				base = hit.dir
				if !filepath.IsAbs(base) {
					base = cwd + string(filepath.Separator) + base
				}
			}
			abs = base + string(filepath.Separator) + abs
		}
		raw := hit.raw
		if raw == "" {
			raw = hit.token
		}
		refs = append(refs, scriptRef{raw: raw, abs: abs, executed: true})
		proven[raw] = true
		proven[hit.token] = true
	}
	for _, r := range extractScriptRefsWithVars(command, vars) {
		if proven[r.raw] {
			continue
		}
		if isTaintedScript(r.raw, tainted) || isTaintedScript(r.abs, tainted) {
			r.abs = ""
		}
		refs = append(refs, r)
	}

	var attached []attachedScript
	var withheld []withheldScript
	seen := map[string]bool{}
	withhold := func(ref scriptRef, reason int) {
		Verbosef("collectScripts: script %q not attached: %s", ref.raw, withholdReasonText[reason])
		withheld = append(withheld, withheldScript{ref: ref, reason: reason})
	}
	for _, ref := range refs {
		if ref.abs == "" {
			withhold(ref, unresolvedReason(ref.raw))
			continue
		}
		if seen[ref.abs] {
			continue
		}
		if isSensitivePath(ref.abs) {
			seen[ref.abs] = true
			if attachOutsideRoot {
				withhold(ref, whReasonSensitive)
			} else {
				withhold(ref, whReasonOutside)
			}
			continue
		}
		inside := isWithinAttachBoundary(ref.abs, root)
		if !inside && !attachOutsideRoot {
			seen[ref.abs] = true
			withhold(ref, whReasonOutside)
			continue
		}
		if len(attached) >= maxAttachedScripts {
			withhold(ref, whReasonCapReached)
			continue
		}
		content, digest, err := readScriptForPrompt(ref.abs)
		if err != nil {
			seen[ref.abs] = true
			switch {
			case errors.Is(err, errScriptTooLarge):
				withhold(ref, whReasonTooLarge)
			case errors.Is(err, errScriptNotText):
				withhold(ref, whReasonNotText)
			default:
				withhold(ref, whReasonUnreadable)
			}
			continue
		}
		seen[ref.abs] = true
		attached = append(attached, attachedScript{ref: ref, content: content, digest: digest, outside: !inside})
	}
	return attached, withheld
}

func describeCollected(attached []attachedScript, withheld []withheldScript) (seen, notSeen []string) {
	for _, a := range attached {
		seen = append(seen, a.ref.raw)
	}
	for _, w := range withheld {
		notSeen = append(notSeen, w.ref.raw+": "+withholdReasonText[w.reason])
	}
	return seen, notSeen
}

func unresolvedReason(raw string) int {
	exp := expandUserPath(raw)
	if !filepath.IsAbs(exp) && !strings.ContainsAny(exp, "$`") {
		return whReasonUnproven
	}
	return whReasonUnresolved
}

var sensitiveHomeDirs = []string{".ssh", ".aws", ".gnupg", ".config", ".kube", ".docker", ".azure", ".gcloud"}

func isSensitivePath(abs string) bool {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	resolvedHome := home
	if resolved, err := filepath.EvalSymlinks(home); err == nil {
		resolvedHome = resolved
	}
	resolvedAbs := filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		resolvedAbs = filepath.Clean(resolved)
	}
	cleanAbs := filepath.Clean(abs)
	for _, d := range sensitiveHomeDirs {
		for _, h := range []string{home, resolvedHome} {
			base := filepath.Clean(filepath.Join(h, d))
			for _, b := range []string{base, evalSymlinkOrSelf(base)} {
				for _, a := range []string{cleanAbs, resolvedAbs} {
					rel, err := filepath.Rel(b, a)
					if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
						return true
					}
				}
			}
		}
	}
	return false
}

func evalSymlinkOrSelf(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return filepath.Clean(resolved)
	}
	return p
}

func buildPromptFromCollectedWithSensitive(command string, attached []attachedScript, withheld []withheldScript, sensitive []string) string {
	prompt := "Command: " + command
	if currentBypassSandbox {
		prompt += "\n[Sandbox: agent requested unsandboxed execution (host sandbox bypass)]"
	}
	if matched := matchedSensitivePatterns(command, sensitive); len(matched) > 0 {
		prompt += "\n[Sensitive: command references user-declared sensitive path (" + strings.Join(matched, ", ") + ")]"
	}
	for _, a := range attached {
		marker := ""
		if a.outside {
			marker = " (resolves outside the project root)"
		}
		if a.ref.executed {
			prompt += "\n\nContents of the file this command executes: " + a.ref.raw + marker +
				" (entry file only — it may read or run other files not shown)\n" + renderAttachedScript(a.content)
		} else {
			prompt += "\n\nContents of a script file the command references: " + a.ref.raw + marker + "\n" + renderAttachedScript(a.content)
		}
	}
	shown := append([]withheldScript(nil), withheld...)
	sort.SliceStable(shown, func(i, j int) bool { return shown[i].reason < shown[j].reason })
	extra := 0
	if len(shown) > maxWithheldNotes {
		extra = len(shown) - maxWithheldNotes
		shown = shown[:maxWithheldNotes]
	}
	for _, w := range shown {
		prompt += fmt.Sprintf("\n\nNote: the command references script %s but its contents were not attached (%s).", w.ref.raw, withholdReasonText[w.reason])
	}
	if extra > 0 {
		prompt += fmt.Sprintf("\n\nNote: %d additional referenced script(s) were not attached.", extra)
	}
	if body := extractInlineScript(command); body != "" {
		prompt += "\n\nInline script:\n" + body
	}
	prompt = forgedPromptHeaderRe.ReplaceAllString(prompt, "[redacted untrusted prompt-injection block in command/script]")
	prompt += "\n\nAnalyze: is this safe to execute?"
	return prompt
}

var forgedPromptHeaderRe = regexp.MustCompile(`(?im)(\[?\s*trusted\s+project\s+configuration\s*\]?|\b(?:project\s+context|allow\s+when|ask\s+when|project\s+allow\s+hints|project\s+ask\s+hints)\s*:)(?:\s*\n[ \t#]*-[^\n]*)*`)

func BuildAnalyzePrompt(command, cwd string) string {
	attached, withheld := collectScripts(command, cwd)
	return buildPromptFromCollectedWithSensitive(command, attached, withheld, LoadSensitivePatterns(cwd))
}

var attachOutsideRoot bool

func attachRoot(cwd string) string {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if root := findRepoRoot(cwd); root != "" {
		return root
	}
	return cwd
}

func isPathInside(abs, root string) bool {
	if abs == "" || root == "" {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(abs))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func isWithinAttachBoundary(abs, root string) bool {
	if isPathInside(abs, root) {
		return true
	}
	mainRoot := resolveWorktreeMainRoot(root)
	if mainRoot == "" {
		mainRoot = root
	}
	if mainRoot != root && isPathInside(abs, mainRoot) {
		return true
	}
	if scriptRepo := findRepoRoot(filepath.Dir(abs)); scriptRepo != "" {
		if scriptMain := resolveWorktreeMainRoot(scriptRepo); scriptMain != "" {
			if isPathInside(scriptMain, mainRoot) && isPathInside(mainRoot, scriptMain) {
				return true
			}
		}
	}
	return false
}

var secretLineRe = regexp.MustCompile(`(?i)(sk-[a-z0-9]{20,}|sk-ant-[a-z0-9-]{20,}|AKIA[A-Z0-9]{16}|ghp_[a-z0-9]{36}|xox[abprs]-[a-z0-9-]{10,}|BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY|(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['"]?[a-z0-9_\-/+=]{8,})`)

func looksLikeSecret(line string) bool {
	return secretLineRe.MatchString(line)
}
