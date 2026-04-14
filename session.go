package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
