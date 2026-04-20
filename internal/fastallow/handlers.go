package fastallow

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// CLI handlers — Go-idiomatic ports of Dippy's per-command handlers
// (src/dippy/cli/*.py). Each handler inspects the already-parsed token
// list for a single command (no pipe or chain — the caller has already
// split on those) and returns whether the call is provably safe.
//
// Attribution: Dippy is MIT-licensed by Lily Dayton.
// https://github.com/ldayton/Dippy

// cliHandler is the signature every handler implements. It receives the
// full token list (including Args[0] as tokens[0]) and returns:
//   - ok: true if the command is provably safe, false if it should fall
//     through to the LLM;
//   - desc: short label used in the reason string (ignored when ok==false).
//
// Handlers operate on literal strings; callers must pre-check that every
// arg word is substitution-safe. Words whose literal form can't be
// recovered are passed as empty strings — harmless, since handlers match
// flag literals exactly.
type cliHandler func(tokens []string) (ok bool, desc string)

var cliHandlers map[string]cliHandler

func init() {
	// Populated in init() rather than as a literal because handler
	// bodies can transitively call IsLocallySafe (for delegation), which
	// reaches back into this map — Go rejects that as an initialization
	// cycle when declared as a package-level var literal.
	cliHandlers = map[string]cliHandler{
		"find": findHandler,
		"sed":  sedHandler,
		"awk":  awkHandler,
		"gawk": awkHandler,
		"mawk": awkHandler,
		"nawk": awkHandler,
		"tee":  teeHandler,
		"curl": curlHandler,
		"git":  gitHandler,
		"gh":   ghHandler,
		// Cloud CLIs.
		"aws":    awsHandler,
		"gcloud": gcloudHandler,
		"gsutil": gsutilHandler,
		"az":     azHandler,
		// Container / orchestration.
		"docker":         dockerHandler,
		"docker-compose": dockerHandler,
		"podman":         dockerHandler,
		"podman-compose": dockerHandler,
		"kubectl":        kubectlHandler,
		"k":              kubectlHandler,
		"helm":           helmHandler,
		// IaC.
		"terraform": terraformHandler,
		"tofu":      terraformHandler,
		"cdk":       cdkHandler,
		// Package managers.
		"npm":   npmHandler,
		"yarn":  npmHandler,
		"pnpm":  npmHandler,
		"pip":   pipHandler,
		"pip3":  pipHandler,
		"uv":    uvHandler,
		"uvx":   uvHandler,
		"cargo": cargoHandler,
		"brew":  brewHandler,
		// Network.
		"wget": wgetHandler,
		// Dev tooling.
		"black":      blackHandler,
		"isort":      isortHandler,
		"ruff":       ruffHandler,
		"pytest":     pytestHandler,
		"pre-commit": preCommitHandler,
		"openssl":    opensslHandler,
		"yq":         yqHandler,
		"xxd":        xxdHandler,
		"mktemp":     mktempHandler,
		"fd":         fdHandler,
		// Archives.
		"gzip":   gzipHandler,
		"gunzip": gzipHandler,
		"tar":    tarHandler,
		// Delegating wrappers.
		"env":  envHandler,
		"bash": shellHandler,
		"sh":   shellHandler,
		"zsh":  shellHandler,
		"dash": shellHandler,
		"ksh":  shellHandler,
		"fish": shellHandler,
		// macOS.
		"open":         openHandler,
		"defaults":     defaultsHandler,
		"plutil":       plutilHandler,
		"pkgutil":      pkgutilHandler,
		"profiles":     profilesHandler,
		"scutil":       scutilHandler,
		"security":     securityHandler,
		"sips":         sipsHandler,
		"spctl":        spctlHandler,
		"tmutil":       tmutilHandler,
		"textutil":     textutilHandler,
		"xattr":        xattrHandler,
		"codesign":     codesignHandler,
		"dscl":         dsclHandler,
		"hdiutil":      hdiutilHandler,
		"mdimport":     mdimportHandler,
		"networksetup": networksetupHandler,
		"qlmanage":     qlmanageHandler,
		"say":          sayHandler,
		"sample":       sampleHandler,
		"caffeinate":   caffeinateHandler,
		"lipo":         lipoHandler,
		"diskutil":     diskutilHandler,
		"launchctl":    launchctlHandler,
		// Linux/BSD sysadmin.
		"journalctl": journalctlHandler,
		"sysctl":     sysctlHandler,
		"ifconfig":   ifconfigHandler,
		"ip":         ipHandler,
		"dmesg":      dmesgHandler,
		"arch":       archHandler,
		// Dev tooling (Batch 3).
		"prometheus": prometheusHandler,
		"iconv":      iconvHandler,
		"symbols":    symbolsHandler,
		"packer":     packerHandler,
		"script":     scriptHandler,
		"fzf":        fzfHandler,
		"python":     pythonHandler,
		"python3":    pythonHandler,
		"python3.8":  pythonHandler,
		"python3.9":  pythonHandler,
		"python3.10": pythonHandler,
		"python3.11": pythonHandler,
		"python3.12": pythonHandler,
		"python3.13": pythonHandler,
		"python3.14": pythonHandler,
		"python3.15": pythonHandler,
		"python3.16": pythonHandler,
		"python3.17": pythonHandler,
		"python3.18": pythonHandler,
		"python3.19": pythonHandler,
		// ansible family — 11 binaries sharing one dispatcher.
		"ansible":           ansibleHandler,
		"ansible-playbook":  ansibleHandler,
		"ansible-vault":     ansibleHandler,
		"ansible-galaxy":    ansibleHandler,
		"ansible-inventory": ansibleHandler,
		"ansible-doc":       ansibleHandler,
		"ansible-pull":      ansibleHandler,
		"ansible-config":    ansibleHandler,
		"ansible-console":   ansibleHandler,
		"ansible-lint":      ansibleHandler,
		"ansible-test":      ansibleHandler,
		// Text processing with output-file gating.
		"sort": sortHandler,
		// Archives / auth / encoders (Batch 4).
		"unzip":            unzipHandler,
		"7z":               sevenZipHandler,
		"7za":              sevenZipHandler,
		"7zr":              sevenZipHandler,
		"7zz":              sevenZipHandler,
		"binhex":           binhexHandler,
		"applesingle":      binhexHandler,
		"macbinary":        binhexHandler,
		"compression_tool": compressionToolHandler,
		"auth0":            auth0Handler,
		// xargs delegates to inner command — handled separately in
		// isSafeCall via xargsUnwrap, not here.
	}
}

// dispatchHandler is the entry point the analyzer uses. Returns
// (handled=true, ok=true, desc) to say "handler approved"; (handled=true,
// ok=false, _) to say "handler rejected — fall through"; (handled=false,
// _, _) to say "no handler — use default logic".
func dispatchHandler(head string, tokens []string) (handled, ok bool, desc string) {
	h, exists := cliHandlers[head]
	if !exists {
		return false, false, ""
	}
	ok, desc = h(tokens)
	return true, ok, desc
}

// tokenRepr produces a best-effort literal string for a Word. Fully
// literal words become their concatenated text. Words containing
// CmdSubst/ProcSubst/ParamExp that passed substitution-safety checks are
// represented as empty strings — handlers then skip them during flag
// scanning, which is exactly the behavior we want (flags we care about
// are always literal).
//
// Exception: words of the form `--flag=<nonliteral>` (literal prefix up
// to and including `=`, then a substitution tail) preserve the literal
// `--flag=` prefix so hasDangerousFlag can still match on the flag name.
// Without this, `aws --endpoint-url=$EVIL s3 ls` would stringify the
// dangerous flag to "" and bypass the multiplex-flag check.
func tokenRepr(w *syntax.Word) string {
	if v, ok := literalWord(w); ok {
		return v
	}
	return literalFlagPrefix(w)
}

// literalFlagPrefix returns the literal prefix of w up to and including
// the first `=`, but only if that prefix sits entirely in literal parts
// (Lit / SglQuoted / fully-literal DblQuoted) at the head of the word.
// Returns "" when there is no such prefix — the caller's fall-through
// behavior is unchanged for non-flag substitution words.
func literalFlagPrefix(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var sb strings.Builder
	for _, part := range w.Parts {
		var piece string
		switch p := part.(type) {
		case *syntax.Lit:
			piece = p.Value
		case *syntax.SglQuoted:
			piece = p.Value
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return ""
				}
				piece += lit.Value
			}
		default:
			return ""
		}
		if eq := strings.IndexByte(piece, '='); eq >= 0 {
			sb.WriteString(piece[:eq+1])
			return sb.String()
		}
		sb.WriteString(piece)
	}
	return ""
}

// wordsToTokens converts []*syntax.Word → []string for handler use.
func wordsToTokens(ws []*syntax.Word) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = tokenRepr(w)
	}
	return out
}

// -----------------------------------------------------------------------------
// find
//
// Allow reads, block -exec/-execdir (unless inner command re-analyzes
// safe), -delete, -ok/-okdir. Port of src/dippy/cli/find.py.
// -----------------------------------------------------------------------------
func findHandler(tokens []string) (bool, string) {
	for i, tok := range tokens {
		switch tok {
		case "-ok", "-okdir":
			return false, ""
		case "-delete":
			return false, ""
		case "-exec", "-execdir":
			// Extract inner command up to ; or +
			var inner []string
			for j := i + 1; j < len(tokens); j++ {
				if tokens[j] == ";" || tokens[j] == "+" {
					break
				}
				inner = append(inner, tokens[j])
			}
			if len(inner) == 0 {
				return false, ""
			}
			if !analyzeInnerTokens(inner) {
				return false, ""
			}
			// Continue scanning rest of args — another -exec or -delete
			// might follow.
		}
	}
	return true, "find"
}

// -----------------------------------------------------------------------------
// sed
//
// Reject -i (in-place), w command (file write), e command (shell exec).
// Port of src/dippy/cli/sed.py but without the config-redirect matching
// (yolonot doesn't have that feature — unsafe writes fall through).
// -----------------------------------------------------------------------------
func sedHandler(tokens []string) (bool, string) {
	scripts := sedExtractScripts(tokens)

	for _, s := range scripts {
		if sedHasExecuteCommand(s) {
			return false, ""
		}
		if sedHasWriteCommand(s) {
			return false, ""
		}
	}

	for _, t := range tokens[1:] {
		if t == "-i" || strings.HasPrefix(t, "-i") {
			return false, ""
		}
		if t == "--in-place" || strings.HasPrefix(t, "--in-place") {
			return false, ""
		}
	}
	return true, "sed"
}

// sedExtractScripts pulls -e/--expression script arguments plus the first
// bare positional argument (the script when no -e was used).
func sedExtractScripts(tokens []string) []string {
	var scripts []string
	foundScript := false
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		switch {
		case t == "-e" || t == "--expression":
			if i+1 < len(tokens) {
				scripts = append(scripts, tokens[i+1])
				foundScript = true
			}
			i += 2
			continue
		case strings.HasPrefix(t, "--expression="):
			scripts = append(scripts, t[len("--expression="):])
			foundScript = true
			i++
			continue
		case t == "-f" || t == "--file":
			i += 2
			continue
		case strings.HasPrefix(t, "--file="):
			i++
			continue
		}
		if strings.HasPrefix(t, "-") {
			i++
			continue
		}
		if !foundScript && len(scripts) == 0 {
			scripts = append(scripts, t)
			foundScript = true
		}
		i++
	}
	return scripts
}

// sedHasExecuteCommand looks for the `e` command (GNU sed shell exec).
// Matches: `s<D>...<D>...<D>e`, `/pat/e`, standalone `e` at statement start.
// Uses findLastSedDelimiter to handle alternative delimiters (s|...|...|e).
func sedHasExecuteCommand(script string) bool {
	stmts := splitSedStatements(script)
	for _, s := range stmts {
		s = strings.TrimSpace(s)
		// Form 1: standalone e command.
		if s == "e" || strings.HasPrefix(s, "e ") {
			return true
		}
		// Form 2: substitution with e flag — honor the alternative-delimiter
		// form (s|a|b|e, s#a#b#e, etc.), not just s/a/b/e.
		if strings.HasPrefix(s, "s") && len(s) > 1 {
			if idx := findLastSedDelimiter(s); idx > 0 && idx < len(s)-1 {
				flags := s[idx+1:]
				if strings.ContainsRune(flags, 'e') {
					return true
				}
			}
		}
		// Form 3: address-prefixed e — `/pat/e` with any delimiter. The last
		// char is `e` and is preceded by a non-alphanumeric delimiter.
		if strings.HasSuffix(s, "e") && len(s) >= 2 {
			prev := s[len(s)-2]
			if !isAlnum(prev) && prev != ' ' && prev != '\t' {
				return true
			}
		}
	}
	return false
}

// sedHasWriteCommand looks for the `w` command (writes to file).
func sedHasWriteCommand(script string) bool {
	// Any /w <file> pattern or trailing w flag.
	// Conservative: a script with `w ` or `/w ` anywhere is suspicious.
	// Split into statements to avoid false positives inside substitution
	// patterns (s/foo\/w/bar/).
	stmts := splitSedStatements(script)
	for _, s := range stmts {
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, "w ") {
			return true
		}
		// `s/foo/bar/w file` — find last unescaped slash and check for w flag.
		if strings.HasPrefix(s, "s") && len(s) > 1 {
			// Walk backwards: the flags segment is after the last
			// unescaped delimiter. If 'w' appears as a flag with a
			// following whitespace+filename, it's a write.
			if idx := findLastSedDelimiter(s); idx > 0 && idx < len(s)-1 {
				flags := s[idx+1:]
				// Flags can be digits, letters (g, i, p, w, e). A `w `
				// followed by non-empty content is a write.
				for j := 0; j < len(flags); j++ {
					if flags[j] == 'w' {
						rest := strings.TrimSpace(flags[j+1:])
						if rest != "" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// splitSedStatements splits on ; while respecting brackets and escapes.
// Good enough for the shapes we care about.
func splitSedStatements(s string) []string {
	var out []string
	var cur strings.Builder
	inBracket := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if c == '[' {
			inBracket = true
		} else if c == ']' {
			inBracket = false
		}
		if c == ';' && !inBracket {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// findLastSedDelimiter returns the index of the last unescaped `/` (or
// the command-specific delimiter) in an `s` command. Returns -1 if not
// found.
func findLastSedDelimiter(s string) int {
	if len(s) < 2 {
		return -1
	}
	delim := byte('/')
	if len(s) > 1 && s[1] != '/' && !isAlnum(s[1]) {
		delim = s[1]
	}
	last := -1
	for i := 2; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if s[i] == delim {
			last = i
		}
	}
	return last
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// -----------------------------------------------------------------------------
// awk / gawk / mawk / nawk
//
// Reject -f (runs script file — can't analyze), system() calls, pipes
// to commands, file redirects inside the program.
// -----------------------------------------------------------------------------
func awkHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if t == "-f" || strings.HasPrefix(t, "-f") {
			return false, ""
		}
		if t == "--file" || strings.HasPrefix(t, "--file=") {
			return false, ""
		}
	}

	// Locate the awk program (first non-flag positional arg).
	var program string
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			switch t {
			case "-F", "-v", "--field-separator":
				i += 2
				continue
			}
			if strings.HasPrefix(t, "-F") || strings.HasPrefix(t, "-v") {
				i++
				continue
			}
			if strings.HasPrefix(t, "--field-separator=") {
				i++
				continue
			}
			i++
			continue
		}
		program = t
		break
	}

	if program == "" {
		return true, "awk"
	}

	if strings.Contains(program, "system(") {
		return false, ""
	}
	// `cmd | getline var` and `"cmd" | getline` open a shell pipeline from
	// inside awk — equivalent to system(). Reject any getline adjacent to a
	// pipe (either side) and any getline whose argument is not a bare
	// filename literal.
	if hasAwkGetlinePipe(program) {
		return false, ""
	}
	// `cmd` | exec-only form is caught above; also catch `exec(` and the
	// `| & coproc form.
	if strings.Contains(program, "|&") {
		return false, ""
	}
	// Rough pipe detection: | " or | '  (awk pipes to shell command).
	if hasAwkPipe(program) {
		return false, ""
	}
	// File redirect detection: > " / >> " / > $ (dynamic filename).
	if hasAwkFileRedirect(program) {
		return false, ""
	}
	return true, "awk"
}

// hasAwkGetlinePipe returns true if the awk program uses `getline` with a
// pipe on either side. Both `"cmd" | getline x` and `getline x < "file"`
// exist, but the pipe form executes a shell command — we reject it. The
// redirect-from-file form is handled by the file-redirect check.
func hasAwkGetlinePipe(program string) bool {
	idx := 0
	for {
		at := strings.Index(program[idx:], "getline")
		if at < 0 {
			return false
		}
		pos := idx + at
		// Check 128 chars of context on each side for a `|` that is not `||`.
		start := pos - 128
		if start < 0 {
			start = 0
		}
		end := pos + len("getline") + 128
		if end > len(program) {
			end = len(program)
		}
		window := program[start:end]
		// Look for a bare `|` (not `||`) in the window — this covers the
		// standard `"cmd" | getline` form.
		for i := 0; i < len(window); i++ {
			if window[i] != '|' {
				continue
			}
			prev := byte(0)
			if i > 0 {
				prev = window[i-1]
			}
			next := byte(0)
			if i+1 < len(window) {
				next = window[i+1]
			}
			if prev == '|' || next == '|' {
				continue // logical ||
			}
			return true
		}
		idx = pos + len("getline")
	}
}

func hasAwkPipe(program string) bool {
	// Look for "print <anything> | <quote>" pattern.
	for _, kw := range []string{"print", "printf"} {
		idx := strings.Index(program, kw)
		if idx < 0 {
			continue
		}
		rest := program[idx+len(kw):]
		if pipeIdx := strings.Index(rest, "|"); pipeIdx >= 0 {
			tail := strings.TrimLeft(rest[pipeIdx+1:], " \t")
			if tail != "" && (tail[0] == '"' || tail[0] == '\'') {
				return true
			}
		}
	}
	return false
}

func hasAwkFileRedirect(program string) bool {
	// Scan for (print|printf)...>... where > is followed by quote/paren/$.
	// A literal quoted string whose value is a safe redirect target
	// (e.g. "/dev/null") is allowed — it's effectively /dev/null and
	// matches what the shell redirect allowlist would permit.
	for _, kw := range []string{"print", "printf"} {
		start := 0
		for {
			idx := strings.Index(program[start:], kw)
			if idx < 0 {
				break
			}
			segStart := start + idx + len(kw)
			segEnd := strings.Index(program[segStart:], "}")
			end := len(program)
			if segEnd >= 0 {
				end = segStart + segEnd
			}
			seg := program[segStart:end]
			if rIdx := strings.Index(seg, ">"); rIdx >= 0 {
				tail := strings.TrimLeft(seg[rIdx+1:], " \t>")
				if tail == "" {
					start = end
					continue
				}
				if tail[0] == '(' || tail[0] == '$' {
					return true
				}
				if tail[0] == '"' || tail[0] == '\'' {
					q := tail[0]
					closeIdx := strings.IndexByte(tail[1:], q)
					if closeIdx < 0 {
						return true
					}
					path := tail[1 : 1+closeIdx]
					if _, safe := safeRedirectTargets[path]; safe {
						start = end
						continue
					}
					return true
				}
			}
			start = end
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// tee
//
// tee always writes to the files named as positional args. In yolonot's
// world, those writes are only safe if the target is in safeRedirectTargets
// (/dev/null, -, /dev/stdout, etc.). Otherwise fall through.
// -----------------------------------------------------------------------------
func teeHandler(tokens []string) (bool, string) {
	var targets []string
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if t == "--" {
			targets = append(targets, tokens[i+1:]...)
			break
		}
		if strings.HasPrefix(t, "-") {
			i++
			continue
		}
		targets = append(targets, t)
		i++
	}
	if len(targets) == 0 {
		return true, "tee" // tee with no files copies stdin to stdout
	}
	for _, t := range targets {
		if _, safe := safeRedirectTargets[t]; !safe {
			return false, ""
		}
	}
	return true, "tee"
}

// -----------------------------------------------------------------------------
// curl
//
// Reject data-sending flags, -X with non-GET methods, and -o/--output
// targets that aren't safe redirect targets.
// -----------------------------------------------------------------------------
var curlDataFlags = map[string]struct{}{
	"-d": {}, "--data": {}, "--data-binary": {}, "--data-raw": {},
	"--data-ascii": {}, "--data-urlencode": {}, "-F": {}, "--form": {},
	"--form-string": {}, "-T": {}, "--upload-file": {}, "--json": {},
}

var curlUnsafeFlags = map[string]struct{}{
	"-K": {}, "--config": {}, "--ftp-create-dirs": {},
	"--mail-from": {}, "--mail-rcpt": {},
}

var curlSafeMethods = map[string]struct{}{
	"GET": {}, "HEAD": {}, "OPTIONS": {}, "TRACE": {},
}

var curlSafeFTPCommands = map[string]struct{}{
	"PWD": {}, "LIST": {}, "NLST": {}, "STAT": {}, "SIZE": {},
	"MDTM": {}, "NOOP": {}, "HELP": {}, "SYST": {}, "TYPE": {},
	"PASV": {}, "CWD": {}, "CDUP": {}, "FEAT": {},
}

// curlFTPVerbUnsafe returns true if the value given to -Q/--quote is not
// a read-only FTP verb. Matches Dippy's logic:
//
//	ftp_cmd = val.strip().strip("'\"").split()[0].upper()
func curlFTPVerbUnsafe(val string) bool {
	val = strings.TrimSpace(val)
	val = strings.Trim(val, "'\"")
	if val == "" {
		return true
	}
	fields := strings.Fields(val)
	if len(fields) == 0 {
		return true
	}
	verb := strings.ToUpper(fields[0])
	_, ok := curlSafeFTPCommands[verb]
	return !ok
}

func curlHandler(tokens []string) (bool, string) {
	for i, t := range tokens {
		if _, bad := curlUnsafeFlags[t]; bad {
			return false, ""
		}
		if _, bad := curlDataFlags[t]; bad {
			return false, ""
		}
		for flag := range curlDataFlags {
			if strings.HasPrefix(t, flag+"=") {
				return false, ""
			}
		}
		if t == "-X" || t == "--request" {
			if i+1 < len(tokens) {
				if _, safe := curlSafeMethods[strings.ToUpper(tokens[i+1])]; !safe {
					return false, ""
				}
			}
		}
		if strings.HasPrefix(t, "--request=") {
			if _, safe := curlSafeMethods[strings.ToUpper(t[len("--request="):])]; !safe {
				return false, ""
			}
		}
		if strings.HasPrefix(t, "-X") && len(t) > 2 && !strings.HasPrefix(t, "-X=") {
			if _, safe := curlSafeMethods[strings.ToUpper(t[2:])]; !safe {
				return false, ""
			}
		}
		if (t == "-Q" || t == "--quote") && i+1 < len(tokens) {
			if curlFTPVerbUnsafe(tokens[i+1]) {
				return false, ""
			}
		}
	}

	// Check output target.
	if out := curlExtractOutput(tokens); out != "" {
		if _, safe := safeRedirectTargets[out]; !safe {
			return false, ""
		}
	}
	return true, "curl"
}

func curlExtractOutput(tokens []string) string {
	for i, t := range tokens {
		if t == "-o" || t == "--output" {
			if i+1 < len(tokens) {
				return tokens[i+1]
			}
		}
		if strings.HasPrefix(t, "-o") && len(t) > 2 && !strings.HasPrefix(t, "-o=") {
			return t[2:]
		}
		if strings.HasPrefix(t, "--output=") {
			return t[len("--output="):]
		}
	}
	return ""
}

// -----------------------------------------------------------------------------
// git
//
// Full port of src/dippy/cli/git.py — read-only action matrix + per-action
// argument checks for branch/tag/remote/stash/config/notes.
// -----------------------------------------------------------------------------

var gitSafeActions = map[string]struct{}{
	"status": {}, "log": {}, "show": {}, "diff": {}, "blame": {},
	"annotate": {}, "shortlog": {}, "describe": {}, "rev-parse": {},
	"rev-list": {}, "reflog": {}, "whatchanged": {},
	"diff-tree": {}, "diff-files": {}, "diff-index": {}, "range-diff": {},
	"format-patch": {}, "difftool": {},
	"grep":         {},
	"ls-files":     {}, "ls-tree": {}, "ls-remote": {}, "cat-file": {},
	"verify-commit": {}, "verify-tag": {}, "name-rev": {}, "merge-base": {},
	"show-ref":     {}, "show-branch": {},
	"check-ignore": {}, "cherry": {}, "for-each-ref": {}, "count-objects": {},
	"fsck":         {},
	"var":          {},
	"archive":      {},
	"fetch":        {},
	"request-pull": {},
}

var gitGlobalFlagsWithArg = map[string]struct{}{
	"-C": {}, "-c": {}, "--git-dir": {}, "--work-tree": {},
	"--namespace": {}, "--super-prefix": {}, "--config-env": {},
}

var gitGlobalFlagsNoArg = map[string]struct{}{
	"--no-pager": {}, "--paginate": {}, "-p": {},
	"--no-replace-objects": {}, "--bare":            {},
	"--literal-pathspecs":  {}, "--glob-pathspecs":  {},
	"--noglob-pathspecs":   {}, "--icase-pathspecs": {},
	"--no-optional-locks":  {},
}

func gitFindAction(tokens []string) (int, string) {
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if _, ok := gitGlobalFlagsWithArg[t]; ok {
			i += 2
			continue
		}
		combined := false
		for flag := range gitGlobalFlagsWithArg {
			if strings.HasPrefix(t, flag+"=") {
				combined = true
				break
			}
		}
		if combined {
			i++
			continue
		}
		if _, ok := gitGlobalFlagsNoArg[t]; ok {
			i++
			continue
		}
		if !strings.HasPrefix(t, "-") {
			return i, t
		}
		break
	}
	return -1, ""
}

func gitHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	// Reject `-c key=value` and `--config-env key=envvar` — git config can
	// execute arbitrary shell commands via alias.*=!cmd, core.editor,
	// core.pager, core.sshCommand, gpg.program, credential.helper,
	// diff.external, merge.external, etc. Dippy skips -c blindly (same hole);
	// yolonot prefers to fall through to the LLM for any -c invocation.
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if t == "-c" || t == "--config-env" {
			return false, ""
		}
		if strings.HasPrefix(t, "-c=") || strings.HasPrefix(t, "--config-env=") {
			return false, ""
		}
	}
	idx, action := gitFindAction(tokens)
	if action == "" {
		return false, ""
	}
	var rest []string
	if idx+1 < len(tokens) {
		rest = tokens[idx+1:]
	}

	var safe bool
	switch action {
	case "branch":
		safe = gitCheckBranch(rest)
	case "tag":
		safe = gitCheckTag(rest)
	case "remote":
		safe = gitCheckRemote(rest)
	case "stash":
		safe = gitCheckStash(rest)
	case "config":
		safe = gitCheckConfig(rest)
	case "notes":
		safe = gitCheckNotes(rest)
	case "bisect":
		safe = gitCheckBisect(rest)
	case "worktree":
		safe = gitCheckWorktree(rest)
	case "submodule":
		safe = gitCheckSubmodule(rest)
	case "apply":
		safe = gitCheckApply(rest)
	case "sparse-checkout":
		safe = gitCheckSparseCheckout(rest)
	case "bundle":
		safe = gitCheckBundle(rest)
	case "lfs":
		safe = gitCheckLFS(rest)
	case "hash-object":
		safe = gitCheckHashObject(rest)
	case "symbolic-ref":
		safe = gitCheckSymbolicRef(rest)
	case "replace":
		safe = gitCheckReplace(rest)
	case "rerere":
		safe = gitCheckRerere(rest)
	default:
		_, safe = gitSafeActions[action]
	}
	if !safe {
		return false, ""
	}
	return true, "git " + action
}

func gitCheckBranch(rest []string) bool {
	unsafe := map[string]struct{}{
		"-d": {}, "-D": {}, "--delete": {}, "-m": {}, "-M": {},
		"--move": {}, "-c": {}, "-C": {}, "--copy": {},
	}
	listing := map[string]struct{}{
		"--list": {}, "-l": {}, "--contains": {}, "--no-contains": {},
		"--merged": {}, "--no-merged": {}, "--points-at": {},
	}
	for _, t := range rest {
		if _, ok := unsafe[t]; ok {
			return false
		}
		if strings.HasPrefix(t, "--set-upstream-to") || t == "-u" {
			return false
		}
	}
	for _, t := range rest {
		if _, ok := listing[t]; ok {
			return true
		}
		if strings.HasPrefix(t, "--list") {
			return true
		}
	}
	for _, t := range rest {
		if !strings.HasPrefix(t, "-") {
			return false // branch name → creation
		}
	}
	return true
}

func gitCheckTag(rest []string) bool {
	unsafe := map[string]struct{}{"-d": {}, "--delete": {}}
	listing := map[string]struct{}{
		"-l": {}, "--list": {}, "--contains": {}, "--no-contains": {},
		"--merged": {}, "--no-merged": {}, "--points-at": {},
	}
	for _, t := range rest {
		if _, ok := unsafe[t]; ok {
			return false
		}
	}
	for _, t := range rest {
		if _, ok := listing[t]; ok {
			return true
		}
		if strings.HasPrefix(t, "--list") {
			return true
		}
	}
	for _, t := range rest {
		if !strings.HasPrefix(t, "-") {
			return false // tag name → creation
		}
	}
	return true
}

func gitCheckRemote(rest []string) bool {
	if len(rest) == 0 {
		return true
	}
	sub := rest[0]
	if sub == "show" || sub == "-v" || sub == "--verbose" || sub == "get-url" {
		return true
	}
	switch sub {
	case "add", "remove", "rm", "rename", "set-url", "prune", "set-head", "set-branches":
		return false
	}
	return true // unknown → could be remote name for listing
}

func gitCheckStash(rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	sub := rest[0]
	if sub == "list" || sub == "show" {
		return true
	}
	switch sub {
	case "push", "pop", "apply", "drop", "clear", "branch", "create", "store":
		return false
	}
	if strings.HasPrefix(sub, "-") {
		return false
	}
	return false
}

func gitCheckConfig(rest []string) bool {
	unsafeFlags := map[string]struct{}{
		"--unset": {}, "--unset-all": {}, "--add": {},
		"--replace-all": {}, "--remove-section": {}, "--rename-section": {},
		"-e": {}, "--edit": {},
	}
	for _, t := range rest {
		if _, bad := unsafeFlags[t]; bad {
			return false
		}
	}
	safeFlags := map[string]struct{}{
		"--get": {}, "--get-all": {}, "--list": {}, "-l": {},
		"--get-regexp": {}, "--get-urlmatch": {},
	}
	for _, t := range rest {
		if _, good := safeFlags[t]; good {
			return true
		}
	}
	scope := map[string]struct{}{
		"--global": {}, "--local": {}, "--system": {}, "--worktree": {},
	}
	var positional []string
	for _, t := range rest {
		if strings.HasPrefix(t, "-") {
			if _, s := scope[t]; !s {
				continue
			}
		}
		if _, s := scope[t]; s {
			continue
		}
		positional = append(positional, t)
	}
	return len(positional) <= 1
}

func gitCheckNotes(rest []string) bool {
	if len(rest) == 0 {
		return true
	}
	sub := rest[0]
	if sub == "list" || sub == "show" {
		return true
	}
	switch sub {
	case "add", "copy", "append", "edit", "merge", "remove", "prune":
		return false
	}
	return true
}

func gitCheckBisect(rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	switch rest[0] {
	case "log", "visualize", "view":
		return true
	}
	return false
}

func gitCheckWorktree(rest []string) bool {
	return len(rest) > 0 && rest[0] == "list"
}

func gitCheckSubmodule(rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	// `foreach` takes a shell command and executes it in each submodule —
	// it's git's documented escape hatch into the shell. Never safe.
	switch rest[0] {
	case "status", "summary":
		return true
	}
	return false
}

func gitCheckApply(rest []string) bool {
	for _, t := range rest {
		if t == "--check" {
			return true
		}
	}
	return false
}

func gitCheckSparseCheckout(rest []string) bool {
	return len(rest) > 0 && rest[0] == "list"
}

func gitCheckBundle(rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	switch rest[0] {
	case "verify", "list-heads":
		return true
	}
	return false
}

func gitCheckLFS(rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	switch rest[0] {
	case "fetch", "ls-files", "status", "env", "version":
		return true
	}
	return false
}

func gitCheckHashObject(rest []string) bool {
	for _, t := range rest {
		if t == "-w" || t == "--write" {
			return false
		}
	}
	return true
}

func gitCheckSymbolicRef(rest []string) bool {
	positional := 0
	for _, t := range rest {
		if !strings.HasPrefix(t, "-") {
			positional++
		}
	}
	return positional <= 1
}

func gitCheckReplace(rest []string) bool {
	if len(rest) == 0 {
		return true
	}
	for _, t := range rest {
		if t == "-l" || t == "--list" {
			return true
		}
	}
	return false
}

func gitCheckRerere(rest []string) bool {
	if len(rest) == 0 {
		return true
	}
	switch rest[0] {
	case "status", "diff":
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// gh
//
// Read-only subcommands/actions. Port of src/dippy/cli/gh.py.
// -----------------------------------------------------------------------------

var ghSafeActions = map[string]struct{}{
	"list": {}, "view": {}, "status": {}, "diff": {}, "checks": {},
	"get": {}, "search": {}, "download": {}, "watch": {}, "verify": {},
	"verify-asset": {}, "trusted-root": {},
	"token":        {},
	"logs":         {}, "ports": {},
	"field-list": {}, "item-list": {},
	"check":      {},
}

var ghFlagsWithArg = map[string]struct{}{
	"-R": {}, "--repo": {}, "-B": {}, "--branch": {},
}

func ghSubcommand(tokens []string) string {
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if _, ok := ghFlagsWithArg[t]; ok {
			i += 2
			continue
		}
		if strings.HasPrefix(t, "-") {
			i++
			continue
		}
		return t
	}
	return ""
}

func ghAction(tokens []string) string {
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if _, ok := ghFlagsWithArg[t]; ok {
			i += 2
			continue
		}
		if strings.HasPrefix(t, "-") {
			i++
			continue
		}
		if i+1 < len(tokens) {
			next := tokens[i+1]
			if !strings.HasPrefix(next, "-") {
				return next
			}
		}
		return t
	}
	return ""
}

func ghHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	sub := ghSubcommand(tokens)
	if sub == "" {
		return false, ""
	}
	if sub == "api" {
		if ghCheckAPI(tokens) {
			return true, "gh api"
		}
		return false, ""
	}
	if sub == "status" || sub == "browse" || sub == "search" {
		return true, "gh " + sub
	}
	act := ghAction(tokens)
	if _, safe := ghSafeActions[act]; safe {
		return true, "gh " + sub + " " + act
	}
	return false, ""
}

func ghCheckAPI(tokens []string) bool {
	args := tokens[2:]
	method := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-X" || a == "--method":
			if i+1 < len(args) {
				method = strings.ToUpper(args[i+1])
				i++
			}
		case strings.HasPrefix(a, "-X") && len(a) > 2:
			method = strings.ToUpper(a[2:])
		case strings.HasPrefix(a, "--method="):
			method = strings.ToUpper(a[len("--method="):])
		}
	}
	if method != "" && method != "GET" {
		return false
	}
	// Detect mutation flags without explicit GET — but allow -f query=...
	// (GraphQL query detection).
	isGraphQLQuery := false
	for i, a := range args {
		if (a == "-f" || a == "--raw-field") && i+1 < len(args) {
			val := args[i+1]
			if strings.HasPrefix(val, "query=") {
				content := strings.ToLower(val[6:])
				if strings.Contains(content, "mutation") {
					return false
				}
				if strings.Contains(content, "query") || strings.Contains(val, "{") {
					isGraphQLQuery = true
				}
			}
		}
	}
	if isGraphQLQuery {
		return true
	}
	hasMutationFlags := false
	for _, a := range args {
		switch a {
		case "-f", "--raw-field", "-F", "--field", "--input":
			hasMutationFlags = true
		}
		if strings.HasPrefix(a, "--raw-field=") || strings.HasPrefix(a, "--field=") || strings.HasPrefix(a, "--input=") {
			hasMutationFlags = true
		}
	}
	if hasMutationFlags && method != "GET" {
		return false
	}
	return true
}

// -----------------------------------------------------------------------------
// xargs — special: delegates to inner command via xargsUnwrap.
// -----------------------------------------------------------------------------

var xargsFlagsWithArg = map[string]struct{}{
	"-a": {}, "--arg-file": {}, "-d": {}, "--delimiter": {},
	"-E": {}, "-e": {}, "--eof": {}, "-I": {}, "-J": {},
	"--replace": {}, "-L": {}, "-l": {}, "--max-lines": {},
	"-n": {}, "--max-args": {}, "-P": {}, "--max-procs": {},
	"-R": {}, "-s": {}, "-S": {}, "--max-chars": {},
	"--process-slot-var": {},
}

var xargsUnsafeFlags = map[string]struct{}{
	"-p": {}, "--interactive": {}, "-o": {}, "--open-tty": {},
}

// xargsUnwrap splits tokens into xargs's own flags and the inner command.
// Returns (innerTokens, ok). If ok is false, xargs rejects.
func xargsUnwrap(tokens []string) ([]string, bool) {
	if len(tokens) < 2 {
		return nil, false
	}
	for _, t := range tokens[1:] {
		if t == "--" {
			break
		}
		if _, bad := xargsUnsafeFlags[t]; bad {
			return nil, false
		}
		if strings.HasPrefix(t, "--interactive") || strings.HasPrefix(t, "--open-tty") {
			return nil, false
		}
	}
	// Skip flags.
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if t == "--" {
			i++
			break
		}
		if !strings.HasPrefix(t, "-") {
			break
		}
		if _, takesArg := xargsFlagsWithArg[t]; takesArg {
			i += 2
			continue
		}
		if len(t) > 2 && t[0] == '-' && t[1] != '-' {
			baseFlag := t[:2]
			if _, takesArg := xargsFlagsWithArg[baseFlag]; takesArg {
				i++
				continue
			}
		}
		i++
	}
	if i >= len(tokens) {
		return nil, false
	}
	return tokens[i:], true
}

// -----------------------------------------------------------------------------
// Inner-command delegation.
// -----------------------------------------------------------------------------

// analyzeInnerTokens takes a literal token list and re-parses+validates
// it as a single command. Used by find -exec and xargs.
//
// We rejoin tokens with a simple space and call IsLocallySafe on the
// result. Tokens are quoted defensively so shell metachars inside
// extracted substrings don't get re-interpreted.
func analyzeInnerTokens(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	cmd := joinTokens(tokens)
	ok, _ := IsLocallySafe(cmd)
	return ok
}

// joinTokens returns a shell-safe single-command string. Simple literal
// tokens are emitted unquoted; tokens with metachars get single-quoted
// (with '-escape). Good enough for the well-behaved token strings we
// receive here.
func joinTokens(tokens []string) string {
	var sb strings.Builder
	for i, t := range tokens {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(shQuote(t))
	}
	return sb.String()
}

func shQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, c := range s {
		switch c {
		case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'-', '_', '/', '.', '=', '+', ',', ':', '@':
			continue
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
