package yolonot

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	decisionLogMu       sync.Mutex
	maxDecisionLogBytes int64 = 16 << 20 // 16 MiB per log file before rotating to decisions.jsonl.1
)

type DecisionEntry struct {
	Timestamp      string   `json:"ts"`
	SessionID      string   `json:"session_id"`
	Command        string   `json:"command"`
	Cwd            string   `json:"cwd"`
	Project        string   `json:"project"`
	Harness        string   `json:"harness,omitempty"`         // claude | codex | opencode | gemini
	PermissionMode string   `json:"permission_mode,omitempty"` // Claude Code only
	BypassSandbox  bool     `json:"bypass_sandbox,omitempty"`  // agent requested unsandboxed execution
	AgentID        string   `json:"agent_id,omitempty"`        // subagent or teammate the call came from
	AgentType      string   `json:"agent_type,omitempty"`
	ToolUseID      string   `json:"tool_use_id,omitempty"` // joins an ask to the human answer that followed
	Attached       []string `json:"attached,omitempty"`    // scripts the judge saw
	Withheld       []string `json:"withheld,omitempty"`    // scripts referenced but not shown, with the reason
	Layer          string   `json:"layer"`
	Decision       string   `json:"decision"`
	OrigDecision   string   `json:"orig_decision,omitempty"`
	Risk           string   `json:"risk,omitempty"` // safe | low | moderate | high | critical
	Confidence     float64  `json:"confidence,omitempty"`
	Short          string   `json:"short,omitempty"` // compact banner label (from LLM)
	Reasoning      string   `json:"reasoning,omitempty"`
	Source         string   `json:"source,omitempty"`
	DurationMs     int64    `json:"duration_ms,omitempty"` // primary LLM call only; escalation time is escalation_ms

	// Escalation fields — set only when the escalation layer was configured
	// and consulted (or deliberately skipped). Unattended runs have no
	// terminal to read, so the JSONL must carry the full second-opinion
	// forensics: which model, what it said, how it failed, what changed.
	Escalated           bool   `json:"escalated,omitempty"` // the escalation call fired
	EscalationModel     string `json:"escalation_model,omitempty"`
	EscalationDecision  string `json:"escalation_decision,omitempty"`
	EscalationRisk      string `json:"escalation_risk,omitempty"`
	EscalationReasoning string `json:"escalation_reasoning,omitempty"` // truncated
	EscalationMs        int64  `json:"escalation_ms,omitempty"`
	EscalationError     string `json:"escalation_error,omitempty"`   // timeout | api | transport | parse
	EscalationOutcome   string `json:"escalation_outcome,omitempty"` // rescued | hardened | kept | error | skipped:<reason>
	PrimaryRisk         string `json:"primary_risk,omitempty"`       // pre-adoption tier (risk holds the adopted one)
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
		dir := entry.Cwd
		if root := findRepoRoot(canonicalDirectory(entry.Cwd)); root != "" {
			if main := resolveWorktreeMainRoot(root); main != "" {
				dir = main
			} else {
				dir = root
			}
		}
		entry.Project = filepath.Base(dir)
	}
	if entry.Harness == "" {
		if h := ActiveHarness(); h != nil {
			entry.Harness = h.Name()
		}
	}
	if entry.PermissionMode == "" {
		entry.PermissionMode = currentPermissionMode
	}
	if !entry.BypassSandbox {
		entry.BypassSandbox = currentBypassSandbox
	}
	if entry.AgentID == "" {
		entry.AgentID = currentAgentID
	}
	if entry.AgentType == "" {
		entry.AgentType = currentAgentType
	}
	if entry.ToolUseID == "" {
		entry.ToolUseID = currentToolUseID
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	decisionLogMu.Lock()
	defer decisionLogMu.Unlock()

	dir := YolonotDir()
	os.MkdirAll(dir, 0700)

	path := decisionsPath()
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return
		}
		if maxDecisionLogBytes > 0 && info.Size() >= maxDecisionLogBytes {
			backup := path + ".1"
			if binfo, berr := os.Lstat(backup); berr != nil || binfo.Mode().IsRegular() {
				_ = os.Rename(path, backup)
			}
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	// OpenFile's perm arg applies only on creation. Fix legacy 0644 files
	// that pre-date the 0600 default — every classified command lands here,
	// and commands frequently embed secrets (Bearer tokens, DB URIs).
	os.Chmod(path, 0600)

	// One write per record: O_APPEND makes a single write atomic, two
	// writes from concurrent hooks interleave into a glued line + a blank.
	f.Write(append(data, '\n'))
}

// ReadRecentDecisions reads the last n entries from the decision log.
func ReadRecentDecisions(n int) []DecisionEntry {
	if n <= 0 {
		return nil
	}
	path := decisionsPath()
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil
	}
	// Fast path for small tail reads (e.g. FindSessionID(50), cmdLog(20)) on large logs.
	if n <= 200 {
		if entries, ok := readTailDecisionsFromFile(path, n); ok {
			return entries
		}
	}

	lines := readDecisionLinesFromFile(path)
	if len(lines) < n {
		if prev := readDecisionLinesFromFile(path + ".1"); len(prev) > 0 {
			lines = append(prev, lines...)
		}
	}
	if len(lines) == 0 {
		return nil
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	entries := make([]DecisionEntry, 0, len(lines))
	for _, line := range lines {
		var e DecisionEntry
		if err := json.Unmarshal([]byte(line), &e); err == nil {
			entries = append(entries, e)
		}
	}
	return entries
}

func readTailDecisionsFromFile(path string, n int) ([]DecisionEntry, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	window := int64(256 * 1024)
	if want := int64(n) * 4096; want > window {
		window = want
	}
	if fi.Size() <= window {
		return nil, false
	}
	if _, err := f.Seek(fi.Size()-window, io.SeekStart); err != nil {
		return nil, false
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	// Discard first partial line after seeking into the middle of the file.
	if !scanner.Scan() {
		return nil, false
	}
	var lines []string
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) < n {
		return nil, false
	}
	lines = lines[len(lines)-n:]
	entries := make([]DecisionEntry, 0, len(lines))
	for _, line := range lines {
		var e DecisionEntry
		if err := json.Unmarshal([]byte(line), &e); err == nil {
			entries = append(entries, e)
		}
	}
	if len(entries) < n {
		return nil, false
	}
	return entries, true
}

func readDecisionLinesFromFile(path string) []string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func countDecisionLinesFromFile(path string) int {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return 0
	}
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if len(scanner.Bytes()) > 0 {
			count++
		}
	}
	return count
}

// cmdLog shows the last n decisions, optionally only one session's
// (session is an id or an id prefix).
func cmdLog(n int, session ...string) {
	var entries []DecisionEntry
	sessionFilter := ""
	sessionTotal := 0
	if len(session) > 0 && session[0] != "" {
		sessionFilter = session[0]
		entries = filterDecisions(ReadRecentDecisions(1000000), statsFilter{session: sessionFilter})
		sessionTotal = len(entries)
		if len(entries) > n {
			entries = entries[len(entries)-n:]
		}
	} else {
		entries = ReadRecentDecisions(n)
	}
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
				if len([]rune(r)) > 40 {
					r = string([]rune(r)[:40])
				}
				extra += " " + r
			}
			extra += ")"
		} else if e.Reasoning != "" {
			r := e.Reasoning
			if len([]rune(r)) > 50 {
				r = string([]rune(r)[:50])
			}
			extra = "  (" + r + ")"
		}
		dur := ""
		if e.DurationMs > 0 {
			dur = fmt.Sprintf("  %dms", e.DurationMs)
		}
		esc := ""
		if e.Escalated {
			esc = "  ⤴esc"
			if e.EscalationMs > 0 {
				esc = fmt.Sprintf("  ⤴esc %dms", e.EscalationMs)
			}
			switch {
			case e.EscalationError != "":
				esc += " " + e.EscalationError
			case e.EscalationOutcome != "":
				esc += " " + e.EscalationOutcome
			}
		}
		if e.AgentType != "" {
			esc += "  [" + e.AgentType + "]"
		} else if e.AgentID != "" {
			esc += "  [subagent]"
		}
		if e.BypassSandbox {
			esc += "  [unsandboxed]"
		}
		cmd := truncateStr(strings.ReplaceAll(e.Command, "\n", " ⏎ "), 60)
		fmt.Printf("  %s  %-6s %-18s %s%s%s%s\n", ts, e.Decision, e.Layer, cmd, extra, dur, esc)
	}

	// Total count
	if sessionFilter != "" {
		fmt.Printf("\nTotal: %d decisions logged (session %s).\n", sessionTotal, sessionFilter)
		return
	}
	total := countDecisionLinesFromFile(decisionsPath()) + countDecisionLinesFromFile(decisionsPath()+".1")
	if total > 0 {
		fmt.Printf("\nTotal: %d decisions logged.\n", total)
	}
}
