package main

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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

// FindSessionID returns the most recent session ID from session files.
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
