package yolonot

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sezaakgun/yolonot/internal/fastallow"
)

// ProjectSessionID returns a session key scoped to the project directory.
// Uses git root if available, otherwise cwd. Returns plain sessionID if cwd is empty.
func ProjectSessionID(sessionID, cwd string) string {
	if sessionID == "" || cwd == "" {
		return sessionID
	}
	root := gitRoot(cwd)
	if root == "" {
		root = cwd
	}
	h := sha256.Sum256([]byte(root))
	return fmt.Sprintf("%s_%x", sessionID, h[:4])
}

// gitRoot returns the git repository root for the given directory, or empty string.
func gitRoot(dir string) string {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func SessionDir() string {
	return filepath.Join(YolonotDir(), "sessions")
}

func sessionPath(sessionID, suffix string) string {
	return filepath.Join(SessionDir(), sessionID+"."+suffix)
}

// ReadLines reads a session file, deduplicates, and preserves order.
func ReadLines(sessionID, suffix string) []string {
	path := sessionPath(sessionID, suffix)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if _, ok := seen[line]; !ok {
			seen[line] = struct{}{}
			lines = append(lines, line)
		}
	}
	return lines
}

// ContainsLine checks if a session file contains the exact line.
func ContainsLine(sessionID, suffix, line string) bool {
	path := sessionPath(sessionID, suffix)
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024) // handle long lines
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == line {
			return true
		}
	}
	return false
}

// SessionWrappers returns the current list of recognized transparent
// command wrappers — the single source of truth shared with fast_allow.
// Reads from fastallow.Wrappers (which starts with the Dippy-derived
// defaults plus rtk and is extended at hook startup by
// fastallow.AddWrappers(Config.Wrappers...)). Keeping one list means a
// user-registered wrapper is honoured by both fast_allow unwrapping AND
// session-approval cross-form lookup, without two parallel configs.
func SessionWrappers() []string {
	return fastallow.Wrappers()
}

// UnwrapCommand strips a known wrapper prefix off a command string and
// returns the inner command. Returns empty if the head is not a recognized
// wrapper or if there is no inner command left. Skips numeric args (for
// `timeout 30 ls` → `ls`) and flag tokens (for `nice -n 5 ls` → `ls`).
// A bare `--` terminates flag skipping and the rest is taken literally.
// Shell tokenisation is naive (whitespace split) — good enough for the
// wrapped-variant heuristic, which only cares about the head/inner shape.
func UnwrapCommand(command string, wrappers []string) string {
	toks := strings.Fields(command)
	if len(toks) < 2 {
		return ""
	}
	head := toks[0]
	known := false
	for _, w := range wrappers {
		if w == head {
			known = true
			break
		}
	}
	if !known {
		return ""
	}
	rest := toks[1:]
	for len(rest) > 0 {
		t := rest[0]
		if t == "--" {
			rest = rest[1:]
			break
		}
		if strings.HasPrefix(t, "-") {
			rest = rest[1:]
			continue
		}
		if _, err := strconv.ParseFloat(t, 64); err == nil {
			rest = rest[1:]
			continue
		}
		break
	}
	if len(rest) == 0 {
		return ""
	}
	return strings.Join(rest, " ")
}

// MatchesLineOrWrappedVariant returns true when `command` matches a line
// in the session file, considering wrapper equivalence in both directions:
//
//  1. Exact match.
//  2. Forward unwrap: `command` is wrapped (e.g. `rtk ls`), strip the
//     wrapper and look up the inner form (`ls`).
//  3. Backward wrap: `command` is plain (e.g. `curl x`), and the stored
//     line is a wrapped variant whose unwrapped form equals `command`.
//
// Only wrappers in SessionWrappers() are honoured, bounding the trust
// boundary — untrusted text ending in " curl evil.com" cannot launder an
// approval because the head won't be in the wrapper list.
//
// Replaces the older ApprovedAsWrappedVariant (backward-only). The
// symmetric version closes the gap where a user approves `ls` plain and
// the agent subsequently runs `rtk ls` — previously missed by exact
// match, now matches via forward unwrap.
func MatchesLineOrWrappedVariant(sessionID, suffix, command string) bool {
	if command == "" {
		return false
	}
	if ContainsLine(sessionID, suffix, command) {
		return true
	}
	wrappers := SessionWrappers()
	if inner := UnwrapCommand(command, wrappers); inner != "" {
		if ContainsLine(sessionID, suffix, inner) {
			return true
		}
	}
	suffixMatch := " " + command
	for _, line := range ReadLines(sessionID, suffix) {
		if !strings.HasSuffix(line, suffixMatch) {
			continue
		}
		for _, w := range wrappers {
			if strings.HasPrefix(line, w+" ") {
				return true
			}
		}
	}
	return false
}

// ApprovedAsWrappedVariant is the legacy backward-only lookup. Kept as a
// thin shim over MatchesLineOrWrappedVariant so existing call sites in
// hook.go and tests keep compiling, but new code should call the symmetric
// helper directly.
func ApprovedAsWrappedVariant(sessionID, command string) bool {
	return MatchesLineOrWrappedVariant(sessionID, "approved", command)
}

// AppendLine appends a line to a session file, creating dirs as needed.
func AppendLine(sessionID, suffix, line string) error {
	dir := SessionDir()
	os.MkdirAll(dir, 0755)
	path := sessionPath(sessionID, suffix)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

// CleanOldSessions removes session files older than 24 hours.
func CleanOldSessions() {
	dir := SessionDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".approved") || strings.HasSuffix(name, ".asked") || strings.HasSuffix(name, ".denied") {
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				os.Remove(filepath.Join(dir, name))
			}
		}
	}
}

// FindSessionID returns the most recent base session ID from session files.
// Session files may have the format {SESSION_ID}_{HASH}.suffix — in that case,
// the base session ID (before the last underscore+8-hex-char hash) is returned.
func FindSessionID() string {
	dir := SessionDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}

	type fileInfo struct {
		stem    string
		modTime time.Time
	}
	var files []fileInfo
	for _, e := range entries {
		name := e.Name()
		for _, suffix := range []string{".approved", ".asked", ".denied"} {
			if strings.HasSuffix(name, suffix) {
				info, err := e.Info()
				if err != nil {
					continue
				}
				stem := strings.TrimSuffix(name, suffix)
				// Extract base session ID: strip _{8-hex-char hash} suffix
				stem = baseSessionID(stem)
				files = append(files, fileInfo{stem, info.ModTime()})
			}
		}
	}
	if len(files) == 0 {
		return ""
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})
	return files[0].stem
}

// baseSessionID extracts the original session ID from a project-scoped key.
// Format: {SESSION_ID}_{8-hex-char-hash} → returns SESSION_ID.
// If the stem doesn't match the pattern, returns it unchanged.
func baseSessionID(stem string) string {
	idx := strings.LastIndex(stem, "_")
	if idx < 0 {
		return stem
	}
	suffix := stem[idx+1:]
	// Project hash is 4 bytes = 8 hex chars
	if len(suffix) == 8 && isHex(suffix) {
		return stem[:idx]
	}
	return stem
}

// isHex returns true if s contains only hex characters.
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
