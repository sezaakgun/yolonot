package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type DecisionEntry struct {
	Timestamp  string  `json:"ts"`
	SessionID  string  `json:"session_id"`
	Command    string  `json:"command"`
	Cwd        string  `json:"cwd"`
	Project    string  `json:"project"`
	Harness    string  `json:"harness,omitempty"` // claude | codex | opencode | gemini
	Layer      string  `json:"layer"`
	Decision   string  `json:"decision"`
	Risk       string  `json:"risk,omitempty"` // safe | low | moderate | high | critical
	Confidence float64 `json:"confidence,omitempty"`
	Short      string  `json:"short,omitempty"` // compact banner label (from LLM)
	Reasoning  string  `json:"reasoning,omitempty"`
	Source     string  `json:"source,omitempty"`
	ReturnedAs string  `json:"returned_as,omitempty"`
	DurationMs int64   `json:"duration_ms,omitempty"`
}

func decisionsPath() string {
	return filepath.Join(YolonotDir(), "decisions.jsonl")
}

// LogDecision appends a decision entry to the JSONL log.
func LogDecision(entry DecisionEntry) {
	if entry.Command == "" {
		return
	}
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if entry.Project == "" && entry.Cwd != "" {
		entry.Project = filepath.Base(entry.Cwd)
	}
	if entry.Harness == "" {
		if h := ActiveHarness(); h != nil {
			entry.Harness = h.Name()
		}
	}

	dir := YolonotDir()
	os.MkdirAll(dir, 0755)

	f, err := os.OpenFile(decisionsPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	f.Write(data)
	f.WriteString("\n")
}

// ReadRecentDecisions reads the last n entries from the decision log.
func ReadRecentDecisions(n int) []DecisionEntry {
	f, err := os.Open(decisionsPath())
	if err != nil {
		return nil
	}
	defer f.Close()

	var all []string
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			all = append(all, line)
		}
	}

	// Take last n
	start := 0
	if len(all) > n {
		start = len(all) - n
	}
	recent := all[start:]

	var entries []DecisionEntry
	for _, line := range recent {
		var e DecisionEntry
		if err := json.Unmarshal([]byte(line), &e); err == nil {
			entries = append(entries, e)
		}
	}
	return entries
}

// cmdLog shows recent decisions.
func cmdLog(n int) {
	entries := ReadRecentDecisions(n)
	if len(entries) == 0 {
		fmt.Println("No decision log found.")
		return
	}

	fmt.Printf("Recent decisions (last %d):\n\n", len(entries))
	for _, e := range entries {
		ts := e.Timestamp
		if idx := len("2006-01-02T"); idx < len(ts) && len(ts) > idx+8 {
			ts = ts[idx : idx+8]
		}
		extra := ""
		if e.Confidence > 0 {
			extra = fmt.Sprintf("  (%.1f", e.Confidence)
			if e.Reasoning != "" {
				r := e.Reasoning
				if len(r) > 40 {
					r = r[:40]
				}
				extra += " " + r
			}
			extra += ")"
		} else if e.Reasoning != "" {
			r := e.Reasoning
			if len(r) > 50 {
				r = r[:50]
			}
			extra = "  (" + r + ")"
		}
		dur := ""
		if e.DurationMs > 0 {
			dur = fmt.Sprintf("  %dms", e.DurationMs)
		}
		cmd := e.Command
		if len(cmd) > 60 {
			cmd = cmd[:57] + "..."
		}
		fmt.Printf("  %s  %-6s %-14s %s%s%s\n", ts, e.Decision, e.Layer, cmd, extra, dur)
	}

	// Total count
	f, err := os.Open(decisionsPath())
	if err == nil {
		total := 0
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			total++
		}
		f.Close()
		fmt.Printf("\nTotal: %d decisions logged.\n", total)
	}
}
