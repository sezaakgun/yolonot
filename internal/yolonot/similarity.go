package yolonot

import "strings"

// filterByPrefix returns approved commands that share the same first token
// (executable name) as the new command. This avoids sending unrelated commands
// to the LLM for comparison.
func filterByPrefix(command string, approved []string) []string {
	cmdExe := firstToken(command)
	var matches []string
	for _, a := range approved {
		if firstToken(a) == cmdExe {
			matches = append(matches, a)
		}
	}
	// Limit to last 10 matches
	if len(matches) > 10 {
		matches = matches[len(matches)-10:]
	}
	return matches
}

// firstToken extracts the executable name from a command, handling sudo/env prefixes.
func firstToken(command string) string {
	prefixes := map[string]bool{"sudo": true, "env": true, "nice": true, "nohup": true, "time": true}
	// Flags that take an argument (next token should be skipped)
	flagsWithArg := map[string]bool{"-u": true, "-S": true, "-P": true}
	skipNext := false
	for _, tok := range strings.Fields(command) {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(tok, "-") {
			if flagsWithArg[tok] {
				skipNext = true
			}
			continue // skip flags like -u, -i, --ignore-environment
		}
		// Skip env variable assignments (KEY=value)
		if strings.Contains(tok, "=") {
			continue
		}
		// Strip path
		if idx := strings.LastIndex(tok, "/"); idx >= 0 {
			tok = tok[idx+1:]
		}
		if !prefixes[tok] {
			return tok
		}
	}
	// Fallback: first field
	fields := strings.Fields(command)
	if len(fields) > 0 {
		return fields[0]
	}
	return command
}
