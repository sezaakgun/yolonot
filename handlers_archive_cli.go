package main

import "strings"

// Archive / identity / delegation CLI handlers ported from Dippy's
// src/dippy/cli/*.py. Batch 4: 7z (unzip/7z/7za/7zr/7zz), binhex
// (binhex/applesingle/macbinary), compression_tool, auth0, xargs.
//
// Where Dippy returns "allow" with redirect_targets, yolonot rejects —
// strictly safer, falls through to the LLM classifier.
//
// Attribution: Dippy is MIT-licensed by Lily Dayton.
// https://github.com/ldayton/Dippy

// -----------------------------------------------------------------------------
// unzip / 7z / 7za / 7zr / 7zz — archive inspection & test only.
// -----------------------------------------------------------------------------

var unzipSafeFlags = map[string]struct{}{
	"-l": {}, "-v": {}, "-t": {}, "-z": {}, "-Z": {},
	"-h": {}, "-hh": {}, "--help": {},
}

var sevenZipSafeCommands = map[string]struct{}{
	"l": {}, "t": {}, "h": {}, "b": {}, "i": {},
}

func unzipHandler(tokens []string) (bool, string) {
	for _, t := range tokens[1:] {
		if _, ok := unzipSafeFlags[t]; ok {
			return true, "unzip " + t
		}
		if !strings.HasPrefix(t, "-") || strings.HasPrefix(t, "--") || len(t) <= 1 {
			continue
		}
		// Combined short flags: allow iff any char maps to a safe flag AND
		// none of the chars are extract-related ('o' overwrite, 'd' dir).
		var safeCharFound bool
		var unsafeCharFound bool
		for _, ch := range t[1:] {
			if ch == 'o' || ch == 'd' {
				unsafeCharFound = true
			}
			short := "-" + string(ch)
			if _, ok := unzipSafeFlags[short]; ok {
				safeCharFound = true
				continue
			}
			if ch == 'l' || ch == 'v' || ch == 't' || ch == 'Z' || ch == 'z' {
				safeCharFound = true
			}
		}
		if safeCharFound && !unsafeCharFound {
			return true, "unzip " + t
		}
		if safeCharFound && unsafeCharFound {
			return false, ""
		}
	}
	return false, ""
}

func sevenZipHandler(tokens []string) (bool, string) {
	head := tokens[0]
	if len(tokens) < 2 {
		return true, head
	}
	sub := tokens[1]
	if sub == "--help" || sub == "-h" {
		return true, head + " " + sub
	}
	if _, ok := sevenZipSafeCommands[sub]; ok {
		return true, head + " " + sub
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// binhex / applesingle / macbinary — macOS file encoding utilities.
// Allow help/version, "probe", and -c/--pipe/--to-stdout (stdout). Writes
// to disk (with or without -o/-C) fall through.
// -----------------------------------------------------------------------------

var binhexHelpFlags = map[string]struct{}{
	"-h": {}, "--help": {}, "-V": {}, "--version": {},
}

var binhexPipeFlags = map[string]struct{}{
	"-c": {}, "--pipe": {}, "--from-stdin": {}, "--to-stdout": {},
}

func binhexHandler(tokens []string) (bool, string) {
	head := tokens[0]
	for _, t := range tokens {
		if _, ok := binhexHelpFlags[t]; ok {
			return true, head
		}
	}
	if len(tokens) > 1 && tokens[1] == "probe" {
		return true, head + " probe"
	}
	for _, t := range tokens {
		if _, ok := binhexPipeFlags[t]; ok {
			return true, head
		}
	}
	return false, ""
}

// -----------------------------------------------------------------------------
// compression_tool — macOS compression utility.
// Allow -h, any invocation with no -encode/-decode operation, or an
// encode/decode that writes to stdout (no -o/--o). Reject when -o is set
// (Dippy returns redirect_targets; we don't support that rule).
// -----------------------------------------------------------------------------

func compressionToolHandler(tokens []string) (bool, string) {
	for _, t := range tokens {
		if t == "-h" || t == "--h" {
			return true, "compression_tool"
		}
	}
	var hasOp bool
	for _, t := range tokens[1:] {
		if t == "-encode" || t == "-decode" || t == "--encode" || t == "--decode" {
			hasOp = true
			break
		}
	}
	if !hasOp {
		return true, "compression_tool"
	}
	for i, t := range tokens {
		if (t == "-o" || t == "--o") && i+1 < len(tokens) {
			return false, ""
		}
	}
	return true, "compression_tool"
}

// -----------------------------------------------------------------------------
// auth0 — Auth0 identity management CLI.
// Extract non-flag parts (keeping --help/-h; skipping global flags with arg).
// "api" subcommand: allow GET (reject on post/put/patch/delete/-d/--data).
// Any other subcommand: allow iff any part is in SAFE_ACTION_KEYWORDS.
// -----------------------------------------------------------------------------

var auth0SafeActions = map[string]struct{}{
	"list": {}, "ls": {}, "show": {}, "get": {},
	"search": {}, "search-by-email": {},
	"tail": {}, "diff": {}, "stats": {},
	"--help": {}, "-h": {},
}

var auth0GlobalFlagsWithArg = map[string]struct{}{
	"--tenant": {}, "-t": {}, "--debug": {},
}

var auth0ApiUnsafeVerbs = map[string]struct{}{
	"post": {}, "put": {}, "patch": {}, "delete": {},
}

func auth0ExtractParts(tokens []string) []string {
	var parts []string
	i := 0
	for i < len(tokens) {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			if t == "--help" || t == "-h" {
				parts = append(parts, t)
				i++
				continue
			}
			if _, ok := auth0GlobalFlagsWithArg[t]; ok && i+1 < len(tokens) {
				i += 2
				continue
			}
			i++
			continue
		}
		parts = append(parts, t)
		i++
	}
	return parts
}

func auth0Handler(tokens []string) (bool, string) {
	if len(tokens) < 2 {
		return false, ""
	}
	parts := auth0ExtractParts(tokens[1:])
	if len(parts) == 0 {
		return false, ""
	}
	sub := parts[0]
	desc := "auth0 " + sub
	if sub == "api" {
		for _, t := range tokens[2:] {
			if _, bad := auth0ApiUnsafeVerbs[t]; bad {
				return false, ""
			}
			if t == "-d" || t == "--data" {
				return false, ""
			}
		}
		return true, desc
	}
	for _, p := range parts {
		if _, ok := auth0SafeActions[p]; ok {
			return true, desc
		}
	}
	return false, ""
}

