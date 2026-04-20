package fastallow

import "strings"

// Linux/BSD sysadmin CLI handlers ported from Dippy's src/dippy/cli/*.py.
// These commands also work on macOS (ifconfig, sysctl, arch) but mostly
// target Linux hosts.
//
// Attribution: Dippy is MIT-licensed by Lily Dayton.
// https://github.com/ldayton/Dippy

// -----------------------------------------------------------------------------
// journalctl — systemd journal viewer.
// Reject any UNSAFE_FLAGS exact match or "<flag>=<value>" form.
// -----------------------------------------------------------------------------

var journalctlUnsafeFlags = []string{
	"--rotate", "--vacuum-time", "--vacuum-size", "--vacuum-files",
	"--flush", "--sync", "--relinquish-var",
}

func journalctlHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		for _, flag := range journalctlUnsafeFlags {
			if t == flag {
				return false, ""
			}
			if strings.HasPrefix(t, flag+"=") {
				return false, ""
			}
		}
	}
	return true, "journalctl"
}

// -----------------------------------------------------------------------------
// sysctl — kernel state.
// Safe: reads only. Reject on -w, -f, or any non-flag arg containing "=".
// -----------------------------------------------------------------------------

func sysctlHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if t == "-w" || t == "-f" {
			return false, ""
		}
	}
	for _, t := range tokens[1:] {
		if strings.HasPrefix(t, "-") {
			continue
		}
		if strings.Contains(t, "=") {
			return false, ""
		}
	}
	return true, "sysctl"
}

// -----------------------------------------------------------------------------
// ifconfig — view/modify network interfaces.
// Dippy rule: safe iff len(tokens) ≤ 2. Anything else is a modification.
// -----------------------------------------------------------------------------

func ifconfigHandler(tokens []string) (bool, string) {
	if len(tokens) <= 2 {
		return true, "ifconfig"
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// ip — Linux networking swiss army knife.
// Skip global flags and flag-arg pairs, then walk non-flag tokens. First
// non-flag is the subcommand; any modify action (add/del/delete/change/
// replace/set/flush/exec) anywhere in remaining parts means ask.
// -----------------------------------------------------------------------------

var ipGlobalFlagsWithArg = map[string]struct{}{
	"-n": {}, "-netns": {}, "--netns": {},
	"-b": {}, "-batch": {}, "--batch": {},
	"-rc": {}, "-rcvbuf": {}, "--rcvbuf": {},
}

var ipSafeSubcommands = map[string]struct{}{
	"addr": {}, "address": {}, "a": {},
	"link": {}, "l": {},
	"route": {}, "r": {},
	"rule": {}, "ru": {},
	"neigh": {}, "neighbor": {}, "n": {},
	"tunnel": {}, "tuntap": {}, "tunt": {},
	"maddr": {}, "maddress": {}, "m": {},
	"mroute":  {},
	"monitor": {}, "mo": {},
	"netns":   {},
	"netconf": {}, "netc": {},
	"stats": {}, "st": {},
}

var ipModifyActions = map[string]struct{}{
	"add": {}, "del": {}, "delete": {}, "change": {},
	"replace": {}, "set": {}, "flush": {}, "exec": {},
}

func ipHandler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	var parts []string
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if _, ok := ipGlobalFlagsWithArg[t]; ok {
			i += 2
			continue
		}
		if strings.HasPrefix(t, "-") {
			i++
			continue
		}
		parts = append(parts, t)
		i++
	}
	if len(parts) == 0 {
		return true, "ip"
	}
	sub := parts[0]
	for _, p := range parts[1:] {
		if _, ok := ipModifyActions[p]; ok {
			return false, ""
		}
	}
	if _, ok := ipSafeSubcommands[sub]; ok {
		return true, "ip " + sub
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// dmesg — kernel ring buffer.
// Reject -c/--clear/-C/-D/-E/--console-off/--console-on/--console-level, or
// any combined short flag containing c/C/D/E.
// -----------------------------------------------------------------------------

var dmesgUnsafeLongFlags = map[string]struct{}{
	"--clear": {}, "--console-off": {}, "--console-on": {}, "--console-level": {},
}

func dmesgHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if _, bad := dmesgUnsafeLongFlags[t]; bad {
			return false, ""
		}
		if t == "-c" || t == "-C" || t == "-D" || t == "-E" {
			return false, ""
		}
		if strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && len(t) > 1 {
			for _, ch := range t[1:] {
				if ch == 'c' || ch == 'C' || ch == 'D' || ch == 'E' {
					return false, ""
				}
			}
		}
	}
	return true, "dmesg"
}

// -----------------------------------------------------------------------------
// arch — print architecture, or run command under an architecture.
// With no args → allow. With inner command → delegate via analyzeInnerTokens.
// -----------------------------------------------------------------------------

var archFlagsNoArg = map[string]struct{}{
	"-32": {}, "-64": {}, "-c": {}, "-h": {},
}

var archFlagsWithArg = map[string]struct{}{
	"-arch": {}, "--arch": {}, "-d": {}, "-e": {},
}

var archArchFlags = map[string]struct{}{
	"-i386": {}, "-x86_64": {}, "-x86_64h": {}, "-arm64": {}, "-arm64e": {},
}

func archHandler(tokens []string) (bool, string) {
	if len(tokens) == 1 {
		return true, "arch"
	}
	i := 1
	for i < len(tokens) {
		t := tokens[i]
		if _, ok := archFlagsNoArg[t]; ok {
			i++
			continue
		}
		if _, ok := archArchFlags[t]; ok {
			i++
			continue
		}
		if _, ok := archFlagsWithArg[t]; ok {
			i += 2
			continue
		}
		if strings.HasPrefix(t, "-") {
			i++
			continue
		}
		break
	}
	if i >= len(tokens) {
		return true, "arch"
	}
	inner := tokens[i:]
	if analyzeInnerTokens(inner) {
		return true, "arch " + inner[0]
	}
	return false, ""
}
