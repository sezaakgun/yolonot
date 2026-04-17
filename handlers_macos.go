package main

import "strings"

// macOS CLI handlers ported from Dippy's src/dippy/cli/*.py.
// Commands that are macOS-specific utilities (defaults, plutil, diskutil,
// codesign, etc). Same cliHandler signature as handlers.go.
//
// When Dippy's handler returns "allow" with `redirect_targets` (meaning
// "allow only if the caller has a matching allow-redirect rule"), yolonot
// rejects instead — we don't implement config-matched redirects, so those
// commands fall through to the LLM. This is strictly safer than Dippy.
//
// Attribution: Dippy is MIT-licensed by Lily Dayton.
// https://github.com/ldayton/Dippy

// -----------------------------------------------------------------------------
// defaults — macOS user defaults.
// -----------------------------------------------------------------------------

var defaultsSafeActions = map[string]struct{}{
	"read": {}, "read-type": {}, "domains": {}, "find": {}, "help": {},
}

var defaultsGlobalFlags = map[string]struct{}{
	"-currentHost": {}, "-host": {},
}

func defaultsHandler(tokens []string) (bool, string) {
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if _, ok := defaultsGlobalFlags[t]; ok {
			if t == "-host" {
				i += 2
			} else {
				i++
			}
			continue
		}
		break
	}
	if i >= len(tokens) {
		return false, ""
	}
	action := tokens[i]
	if _, ok := defaultsSafeActions[action]; ok {
		return true, "defaults " + action
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// plutil — macOS property list utility.
// Unsafe actions (-convert/-insert/-replace/-remove) modify files; yolonot
// rejects those because we don't have redirect_targets. Safe actions are
// -p/-lint/-extract (extract just prints).
// -----------------------------------------------------------------------------

var plutilUnsafeActions = map[string]struct{}{
	"-convert": {}, "-insert": {}, "-replace": {}, "-remove": {},
}

func plutilHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if _, bad := plutilUnsafeActions[t]; bad {
			return false, ""
		}
	}
	return true, "plutil"
}

// -----------------------------------------------------------------------------
// pkgutil — macOS package utility.
// -----------------------------------------------------------------------------

var pkgutilSafeCommands = map[string]struct{}{
	"--packages": {}, "--pkgs": {}, "--pkgs-plist": {},
	"--files": {}, "--export-plist": {},
	"--pkg-info": {}, "--pkg-info-plist": {},
	"--pkg-groups": {}, "--groups": {}, "--groups-plist": {}, "--group-pkgs": {},
	"--file-info": {}, "--file-info-plist": {},
	"--payload-files": {}, "--check-signature": {},
	"--help": {}, "-h": {},
}

var pkgutilUnsafeCommands = map[string]struct{}{
	"--forget": {}, "--learn": {}, "--expand": {}, "--flatten": {}, "--bom": {},
}

func pkgutilHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if _, bad := pkgutilUnsafeCommands[t]; bad {
			return false, ""
		}
		if _, good := pkgutilSafeCommands[t]; good {
			return true, "pkgutil " + t
		}
		if strings.HasPrefix(t, "--pkgs=") {
			return true, "pkgutil --pkgs"
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// profiles — macOS configuration profiles.
// -----------------------------------------------------------------------------

var profilesSafeSubcommands = map[string]struct{}{
	"help": {}, "status": {}, "list": {}, "show": {}, "validate": {}, "version": {},
}

func profilesHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	sub := tokens[1]
	if _, ok := profilesSafeSubcommands[sub]; ok {
		return true, "profiles " + sub
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// scutil — system configuration.
// -----------------------------------------------------------------------------

var scutilSafeOptions = map[string]struct{}{
	"--get": {}, "--dns": {}, "--proxy": {}, "-r": {}, "-w": {},
}

func scutilHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	opt := tokens[1]
	if _, ok := scutilSafeOptions[opt]; ok {
		return true, "scutil " + strings.TrimLeft(opt, "-")
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// security — keychain / certificate utility.
// -----------------------------------------------------------------------------

var securitySafeSubcommands = map[string]struct{}{
	"help":                       {},
	"show-keychain-info":         {},
	"dump-keychain":              {},
	"find-generic-password":      {},
	"find-internet-password":     {},
	"find-key":                   {},
	"find-certificate":           {},
	"find-identity":              {},
	"get-identity-preference":    {},
	"dump-trust-settings":        {},
	"verify-cert":                {},
	"error":                      {},
	"leaks":                      {},
	"list-smartcards":            {},
	"translocate-policy-check":   {},
	"translocate-status-check":   {},
	"translocate-original-path":  {},
	"requirement-evaluate":       {},
}

func securityHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	sub := tokens[1]
	if _, ok := securitySafeSubcommands[sub]; ok {
		return true, "security " + sub
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// sips — scriptable image processing.
// Only allow when every flag is in sipsSafeFlags. Modifications with -o
// are rejected (we don't model redirect_targets).
// -----------------------------------------------------------------------------

var sipsSafeFlags = map[string]struct{}{
	"-g": {}, "--getProperty": {}, "--verify": {},
	"-1": {}, "--oneLine": {}, "-h": {}, "--help": {},
}

var sipsSafeFlagsWithArg = map[string]struct{}{
	"-g": {}, "--getProperty": {},
}

func sipsHandler(tokens []string) (bool, string) {
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			if _, ok := sipsSafeFlags[t]; !ok {
				return false, ""
			}
			if _, takesArg := sipsSafeFlagsWithArg[t]; takesArg {
				i += 2
				continue
			}
		}
		i++
	}
	return true, "sips"
}

// -----------------------------------------------------------------------------
// spctl — Gatekeeper assessment.
// -----------------------------------------------------------------------------

var spctlSafeOptions = map[string]struct{}{
	"--assess": {}, "-a": {}, "--status": {}, "--disable-status": {},
}

func spctlHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	for _, t := range tokens[1:] {
		if _, ok := spctlSafeOptions[t]; ok {
			return true, "spctl " + strings.TrimLeft(t, "-")
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// tmutil — Time Machine.
// -----------------------------------------------------------------------------

var tmutilSafeSubcommands = map[string]struct{}{
	"help": {}, "version": {}, "destinationinfo": {}, "isexcluded": {},
	"latestbackup": {}, "listbackups": {},
	"listlocalsnapshotdates": {}, "listlocalsnapshots": {},
	"machinedirectory": {}, "uniquesize": {}, "verifychecksums": {},
	"compare": {}, "calculatedrift": {},
}

func tmutilHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	sub := tokens[1]
	if _, ok := tmutilSafeSubcommands[sub]; ok {
		return true, "tmutil " + sub
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// textutil — macOS text conversion.
// Allow -info/-help, and -convert/-cat when -stdout is present. Any other
// -convert/-cat (in-place or with -output) needs redirect_targets → reject.
// -----------------------------------------------------------------------------

var textutilWriteCommands = map[string]struct{}{
	"-convert": {}, "-cat": {},
}

func textutilHandler(tokens []string) (bool, string) {
	hasWrite := false
	for _, t := range tokens[1:] {
		if _, ok := textutilWriteCommands[t]; ok {
			hasWrite = true
			break
		}
	}
	if !hasWrite {
		return true, "textutil"
	}
	for _, t := range tokens[1:] {
		if t == "-stdout" {
			return true, "textutil"
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// xattr — extended attributes.
// Reject -w/-d/-c individually OR as combined short flags (-wd, -cd, -cr).
// -----------------------------------------------------------------------------

func xattrHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if t == "-w" || t == "-d" || t == "-c" {
			return false, ""
		}
		if strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && len(t) > 1 {
			for _, ch := range t[1:] {
				if ch == 'w' || ch == 'd' || ch == 'c' {
					return false, ""
				}
			}
		}
	}
	return true, "xattr"
}

// -----------------------------------------------------------------------------
// codesign — code signing.
// -----------------------------------------------------------------------------

var codesignUnsafeLong = map[string]struct{}{
	"--sign": {}, "--remove-signature": {},
}

func codesignHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if _, bad := codesignUnsafeLong[t]; bad {
			return false, ""
		}
		if t == "-s" {
			return false, ""
		}
		if strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && len(t) > 1 {
			for _, ch := range t[1:] {
				if ch == 's' {
					return false, ""
				}
			}
		}
	}
	return true, "codesign"
}

// -----------------------------------------------------------------------------
// dscl — Directory Service CLI.
// -----------------------------------------------------------------------------

var dsclSafeCommands = map[string]struct{}{
	"read": {}, "-read": {}, "readall": {}, "-readall": {},
	"readpl": {}, "-readpl": {}, "readpli": {}, "-readpli": {},
	"list": {}, "-list": {}, "search": {}, "-search": {},
	"diff": {}, "-diff": {},
}

var dsclOptions = map[string]struct{}{
	"-p": {}, "-u": {}, "-P": {}, "-f": {}, "-raw": {},
	"-plist": {}, "-url": {}, "-q": {},
}

var dsclOptionsWithArg = map[string]struct{}{
	"-u": {}, "-P": {}, "-f": {},
}

func dsclHandler(tokens []string) (bool, string) {
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if _, ok := dsclOptions[t]; ok {
			if _, takesArg := dsclOptionsWithArg[t]; takesArg {
				i += 2
			} else {
				i++
			}
			continue
		}
		break
	}
	// Skip datasource (e.g. ".", "/Local/Default").
	if i < len(tokens) {
		i++
	}
	if i >= len(tokens) {
		return false, ""
	}
	cmd := tokens[i]
	if _, ok := dsclSafeCommands[cmd]; ok {
		return true, "dscl " + strings.TrimLeft(cmd, "-")
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// hdiutil — disk image utility.
// -----------------------------------------------------------------------------

var hdiutilSafeVerbs = map[string]struct{}{
	"help": {}, "info": {}, "verify": {}, "checksum": {},
	"imageinfo": {}, "isencrypted": {}, "plugins": {}, "pmap": {},
}

func hdiutilHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	verb := tokens[1]
	if _, ok := hdiutilSafeVerbs[verb]; ok {
		return true, "hdiutil " + verb
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// mdimport — Spotlight indexer.
// -----------------------------------------------------------------------------

var mdimportSafeFlags = map[string]struct{}{
	"-t": {}, "-L": {}, "-A": {}, "-X": {},
}

func mdimportHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if _, ok := mdimportSafeFlags[t]; ok {
			return true, "mdimport " + t
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// networksetup — network configuration.
// -----------------------------------------------------------------------------

var networksetupSafePrefixes = []string{"-get", "-list", "-show", "-is"}

var networksetupSafeOptions = map[string]struct{}{
	"-version": {}, "-help": {}, "-printcommands": {},
}

func networksetupHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	opt := strings.ToLower(tokens[1])
	if _, ok := networksetupSafeOptions[opt]; ok {
		return true, "networksetup " + strings.TrimLeft(opt, "-")
	}
	for _, prefix := range networksetupSafePrefixes {
		if strings.HasPrefix(opt, prefix) {
			return true, "networksetup " + strings.TrimLeft(opt, "-")
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// qlmanage — Quick Look server.
// -----------------------------------------------------------------------------

var qlmanageSafeFlags = map[string]struct{}{
	"-m": {}, "-t": {}, "-p": {}, "-h": {},
}

var qlmanageUnsafeFlags = map[string]struct{}{
	"-r": {},
}

func qlmanageHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if _, bad := qlmanageUnsafeFlags[t]; bad {
			return false, ""
		}
		if _, ok := qlmanageSafeFlags[t]; ok {
			return true, "qlmanage " + t
		}
	}
	return true, "qlmanage"
}

// -----------------------------------------------------------------------------
// say — text-to-speech.
// Without -o/--output-file it speaks; with it, we'd need redirect_targets →
// reject.
// -----------------------------------------------------------------------------

func sayHandler(tokens []string) (bool, string) {
	for i, t := range tokens[1:] {
		if t == "-o" || t == "--output-file" {
			_ = i
			return false, ""
		}
		if strings.HasPrefix(t, "--output-file=") {
			return false, ""
		}
	}
	return true, "say"
}

// -----------------------------------------------------------------------------
// sample — process profiler.
// -file to /tmp is safe, elsewhere is ask.
// -----------------------------------------------------------------------------

func sampleHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	for i := 1; i < len(tokens); i++ {
		if tokens[i] == "-file" && i+1 < len(tokens) {
			path := tokens[i+1]
			if strings.HasPrefix(path, "/tmp/") || path == "/tmp" {
				return true, "sample -file /tmp/..."
			}
			return false, ""
		}
	}
	return true, "sample"
}

// -----------------------------------------------------------------------------
// caffeinate — prevents sleep; delegates to inner command if present.
// -----------------------------------------------------------------------------

var caffeinateFlagsNoArg = map[string]struct{}{
	"-d": {}, "-i": {}, "-m": {}, "-s": {}, "-u": {},
}

var caffeinateFlagsWithArg = map[string]struct{}{
	"-t": {}, "-w": {},
}

func caffeinateHandler(tokens []string) (bool, string) {
	if len(tokens) == 1 {
		return true, "caffeinate"
	}
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if _, ok := caffeinateFlagsWithArg[t]; ok {
			i += 2
			continue
		}
		if _, ok := caffeinateFlagsNoArg[t]; ok {
			i++
			continue
		}
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			combined := true
			for _, ch := range t[1:] {
				if !strings.ContainsRune("dismu", ch) {
					combined = false
					break
				}
			}
			if combined {
				i++
				continue
			}
		}
		break
	}
	if i >= len(tokens) {
		return true, "caffeinate"
	}
	inner := tokens[i:]
	if analyzeInnerTokens(inner) {
		return true, "caffeinate " + inner[0]
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// lipo — universal binary tool.
// Safe: -info/-archs/-detailed_info/-verify_arch. Any write operation
// (-create/-extract/etc) requires output file tracking → reject.
// -----------------------------------------------------------------------------

var lipoSafeCommands = map[string]struct{}{
	"-archs": {}, "-info": {}, "-detailed_info": {}, "-verify_arch": {},
}

var lipoWriteCommands = map[string]struct{}{
	"-create": {}, "-extract": {}, "-extract_family": {},
	"-remove": {}, "-replace": {}, "-thin": {},
}

func lipoHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if _, ok := lipoSafeCommands[t]; ok {
			return true, "lipo " + t
		}
	}
	for _, t := range tokens[1:] {
		if _, bad := lipoWriteCommands[t]; bad {
			return false, ""
		}
	}
	return true, "lipo"
}

// -----------------------------------------------------------------------------
// diskutil — disk manager.
// -----------------------------------------------------------------------------

var diskutilSafeVerbs = map[string]struct{}{
	"list": {}, "info": {}, "information": {}, "activity": {}, "listfilesystems": {},
}

func diskutilHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	verb := strings.ToLower(tokens[1])
	if _, ok := diskutilSafeVerbs[verb]; ok {
		return true, "diskutil " + verb
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// launchctl — launchd control.
// -----------------------------------------------------------------------------

var launchctlSafeSubcommands = map[string]struct{}{
	"list": {}, "print": {}, "print-cache": {}, "print-disabled": {},
	"print-token": {}, "plist": {}, "procinfo": {}, "hostinfo": {},
	"resolveport": {}, "blame": {}, "dumpstate": {}, "dump-xsc": {},
	"dumpjpcategory": {}, "managerpid": {}, "manageruid": {}, "managername": {},
	"error": {}, "variant": {}, "version": {}, "help": {}, "getenv": {},
}

func launchctlHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	sub := tokens[1]
	if _, ok := launchctlSafeSubcommands[sub]; ok {
		return true, "launchctl " + sub
	}
	return false, ""
}
