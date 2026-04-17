package main

import "strings"

// Dev tooling CLI handlers ported from Dippy's src/dippy/cli/*.py.
// Covers prometheus, iconv, symbols, packer, script, fzf, python,
// ansible.
//
// Attribution: Dippy is MIT-licensed by Lily Dayton.
// https://github.com/ldayton/Dippy

// -----------------------------------------------------------------------------
// prometheus — only help and version flags are safe. Running the server
// binds ports, creates lockfiles, and writes data.
// -----------------------------------------------------------------------------

var prometheusSafeFlags = map[string]struct{}{
	"-h": {}, "--help": {}, "--help-long": {}, "--help-man": {}, "--version": {},
}

func prometheusHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	for _, t := range tokens[1:] {
		if _, ok := prometheusSafeFlags[t]; ok {
			return true, "prometheus " + t
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// iconv — text encoding converter. Safe by default (writes to stdout).
// Reject any -o/--output form (yolonot doesn't do config-matched redirects).
// -----------------------------------------------------------------------------

func iconvHandler(tokens []string) (bool, string) {
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if t == "-o" || t == "--output" {
			return false, ""
		}
		if strings.HasPrefix(t, "-o") && len(t) > 2 {
			return false, ""
		}
		if strings.HasPrefix(t, "--output=") {
			return false, ""
		}
	}
	return true, "iconv"
}

// -----------------------------------------------------------------------------
// symbols — macOS symbol info tool. Most ops display info (safe). Reject
// -saveSignature and -symbolsPackageDir (write to disk).
// -----------------------------------------------------------------------------

func symbolsHandler(tokens []string) (bool, string) {
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if t == "-saveSignature" || t == "-symbolsPackageDir" {
			return false, ""
		}
	}
	return true, "symbols"
}

// -----------------------------------------------------------------------------
// packer — HashiCorp machine image builder.
// -----------------------------------------------------------------------------

var packerSafeActions = map[string]struct{}{
	"version": {}, "validate": {}, "inspect": {}, "console": {},
}

var packerSafePluginsSubcommands = map[string]struct{}{
	"installed": {}, "required": {},
}

func packerHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	for _, t := range tokens[1:] {
		if t == "--help" || t == "-help" || t == "-h" {
			return true, "packer --help"
		}
		if t == "--version" || t == "-version" {
			return true, "packer --version"
		}
	}
	actionIdx := 1
	for actionIdx < len(tokens) {
		if strings.HasPrefix(tokens[actionIdx], "-") {
			actionIdx++
			continue
		}
		break
	}
	if actionIdx >= len(tokens) {
		return false, ""
	}
	action := tokens[actionIdx]
	var rest []string
	if actionIdx+1 < len(tokens) {
		rest = tokens[actionIdx+1:]
	}
	if action == "plugins" {
		sub := ""
		for _, t := range rest {
			if !strings.HasPrefix(t, "-") {
				sub = t
				break
			}
		}
		if _, ok := packerSafePluginsSubcommands[sub]; ok {
			return true, "packer plugins " + sub
		}
		return false, ""
	}
	if action == "fmt" {
		for _, t := range rest {
			if t == "-check" || t == "-diff" || strings.HasPrefix(t, "-write=false") {
				return true, "packer fmt"
			}
		}
		return false, ""
	}
	if _, ok := packerSafeActions[action]; ok {
		return true, "packer " + action
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// script — records terminal sessions or runs commands with a pseudo-TTY.
// Delegates to inner command when one is supplied; allows -p playback.
// -----------------------------------------------------------------------------

var scriptFlagsWithArg = map[string]struct{}{"-t": {}, "-T": {}}
var scriptFlagsNoArg = map[string]struct{}{
	"-a": {}, "-d": {}, "-e": {}, "-F": {}, "-k": {},
	"-p": {}, "-q": {}, "-r": {},
}

func scriptHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	flagEnd := 1
	i := 1
	for i < len(tokens) {
		tok := tokens[i]
		if tok == "--" {
			i++
			break
		}
		if strings.HasPrefix(tok, "-") {
			if _, ok := scriptFlagsWithArg[tok]; ok {
				i += 2
				continue
			}
			// FLAGS_NO_ARG or combined-short (e.g. -aq, -dp)
			if _, ok := scriptFlagsNoArg[tok]; ok {
				i++
				continue
			}
			if len(tok) > 1 && tok[1] != '-' {
				i++
				continue
			}
			i++
			continue
		}
		break
	}
	flagEnd = i
	if i >= len(tokens) {
		return false, ""
	}
	// tokens[i] is the recording file; command follows.
	if i+1 >= len(tokens) {
		// No inner command → allow only in -p playback mode.
		for _, t := range tokens[1:flagEnd] {
			if t == "-p" {
				return true, "script -p"
			}
			if strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.ContainsRune(t, 'p') {
				return true, "script -p"
			}
		}
		return false, ""
	}
	inner := tokens[i+1:]
	if analyzeInnerTokens(inner) {
		return true, "script " + inner[0]
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// fzf — fuzzy finder. Safe by default; reject --listen-unsafe and --bind
// values that contain execute/execute-silent/become actions. Delegate to
// inner command when extractable from the bind value.
// -----------------------------------------------------------------------------

var fzfExecBindActions = []string{"execute-silent", "execute", "become"}

func fzfHandler(tokens []string) (bool, string) {
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if t == "--listen-unsafe" || strings.HasPrefix(t, "--listen-unsafe=") {
			return false, ""
		}
		var bindValue string
		var haveBind bool
		if t == "--bind" {
			if i+1 < len(tokens) {
				bindValue = tokens[i+1]
				haveBind = true
			}
		} else if strings.HasPrefix(t, "--bind=") {
			bindValue = t[len("--bind="):]
			haveBind = true
		}
		if !haveBind {
			continue
		}
		if !fzfHasExecBind(bindValue) {
			continue
		}
		inner := fzfExtractExecCommand(bindValue)
		if inner == "" {
			return false, ""
		}
		ok, _ := IsLocallySafe(inner)
		if !ok {
			return false, ""
		}
	}
	return true, "fzf"
}

func fzfHasExecBind(bv string) bool {
	for _, action := range fzfExecBindActions {
		if strings.Contains(bv, action+"(") {
			return true
		}
		if strings.Contains(bv, action+":") {
			return true
		}
	}
	tmp := strings.ReplaceAll(bv, ",", ":")
	tmp = strings.ReplaceAll(tmp, "+", ":")
	for _, p := range strings.Split(tmp, ":") {
		for _, action := range fzfExecBindActions {
			if p == action {
				return true
			}
		}
	}
	return false
}

func fzfExtractExecCommand(bv string) string {
	for _, action := range fzfExecBindActions {
		needle := action + "("
		if idx := strings.Index(bv, needle); idx >= 0 {
			rest := bv[idx+len(needle):]
			if end := strings.LastIndex(rest, ")"); end >= 0 {
				return rest[:end]
			}
			return rest
		}
	}
	for _, action := range fzfExecBindActions {
		needle := action + ":"
		if idx := strings.Index(bv, needle); idx >= 0 {
			rest := bv[idx+len(needle):]
			if end := strings.IndexAny(rest, " \t"); end >= 0 {
				return rest[:end]
			}
			return rest
		}
	}
	return ""
}

// -----------------------------------------------------------------------------
// python / python3 / python3.x — simplified vs Dippy: allow version/help
// flags and `python -m calendar` only. Script safety analysis belongs in
// the LLM layer.
// -----------------------------------------------------------------------------

var pythonSafeFlags = map[string]struct{}{
	"-V": {}, "--version": {}, "-h": {}, "--help": {}, "-VV": {},
}

func pythonHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	head := tokens[0]
	for _, t := range tokens[1:] {
		if _, ok := pythonSafeFlags[t]; ok {
			return true, head + " " + t
		}
	}
	// -c, -m, -i are always unsafe to auto-approve (except -m calendar).
	for i, t := range tokens[1:] {
		if t == "-m" {
			if i+2 < len(tokens) && tokens[i+2] == "calendar" {
				return true, head + " -m calendar"
			}
			return false, ""
		}
		if t == "-c" || t == "-i" {
			return false, ""
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// ansible family — 11 binaries sharing a dispatcher.
// -----------------------------------------------------------------------------

var ansibleAlwaysSafeBinaries = map[string]struct{}{
	"ansible-doc": {}, "ansible-lint": {},
}

var ansibleGalaxySafeActions = map[string]struct{}{
	"list": {}, "search": {}, "info": {}, "verify": {},
}

var ansibleConfigSafeActions = map[string]struct{}{
	"list": {}, "dump": {}, "view": {}, "validate": {},
}

var ansibleTestSafeActions = map[string]struct{}{
	"env": {}, "sanity": {}, "units": {},
}

var ansiblePlaybookSafeFlags = map[string]struct{}{
	"--syntax-check": {}, "--list-hosts": {}, "--list-tasks": {},
	"--list-tags": {}, "--check": {}, "-C": {},
}

var ansibleInventorySafeFlags = map[string]struct{}{
	"--list": {}, "--host": {}, "--graph": {},
}

func ansibleHandler(tokens []string) (bool, string) {
	if len(tokens) == 0 {
		return false, ""
	}
	cmd := tokens[0]

	// Help/version short-circuit — matches Dippy's "any -h/--help/--version
	// in tokens → allow" behaviour, above and beyond isVersionOrHelp.
	for _, t := range tokens {
		if t == "-h" || t == "--help" || t == "--version" {
			return true, cmd
		}
	}

	if _, ok := ansibleAlwaysSafeBinaries[cmd]; ok {
		return true, cmd
	}

	switch cmd {
	case "ansible":
		for _, t := range tokens[1:] {
			if t == "--list-hosts" || t == "--check" || t == "-C" {
				return true, cmd
			}
		}
	case "ansible-playbook":
		for _, t := range tokens[1:] {
			if _, ok := ansiblePlaybookSafeFlags[t]; ok {
				return true, cmd
			}
		}
	case "ansible-vault":
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") {
				continue
			}
			if t == "view" {
				return true, cmd
			}
			return false, ""
		}
	case "ansible-galaxy":
		var typeTok, actionTok string
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") {
				continue
			}
			if typeTok == "" {
				typeTok = t
			} else if actionTok == "" {
				actionTok = t
				break
			}
		}
		if typeTok != "role" && typeTok != "collection" {
			return false, ""
		}
		if _, ok := ansibleGalaxySafeActions[actionTok]; ok {
			return true, cmd
		}
	case "ansible-inventory":
		for _, t := range tokens {
			if t == "--output" {
				return false, ""
			}
		}
		for _, t := range tokens[1:] {
			if _, ok := ansibleInventorySafeFlags[t]; ok {
				return true, cmd
			}
		}
	case "ansible-pull":
		for _, t := range tokens[1:] {
			if t == "--list-hosts" || t == "--check" {
				return true, cmd
			}
		}
	case "ansible-config":
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") {
				continue
			}
			if _, ok := ansibleConfigSafeActions[t]; ok {
				return true, cmd
			}
			return false, ""
		}
	case "ansible-console":
		for _, t := range tokens[1:] {
			if t == "--list-hosts" {
				return true, cmd
			}
		}
	case "ansible-test":
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") {
				continue
			}
			if _, ok := ansibleTestSafeActions[t]; ok {
				return true, cmd
			}
			return false, ""
		}
	}
	return false, ""
}
