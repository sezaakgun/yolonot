package yolonot

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// statsFilter narrows the decision log to one session, project or window.
type statsFilter struct {
	session string
	project string
	since   time.Time
}

func parseStatsArgs(args []string) (statsFilter, error) {
	var f statsFilter
	for i := 0; i < len(args); i++ {
		a := args[i]
		value := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", a)
			}
			i++
			return args[i], nil
		}
		switch a {
		case "--session":
			v, err := value()
			if err != nil {
				return f, err
			}
			if v == "current" {
				v = FindSessionID()
				if v == "" {
					return f, fmt.Errorf("no current session found")
				}
			}
			f.session = v
		case "--project":
			v, err := value()
			if err != nil {
				return f, err
			}
			f.project = v
		case "--since":
			v, err := value()
			if err != nil {
				return f, err
			}
			t, err := parseSince(v, time.Now())
			if err != nil {
				return f, err
			}
			f.since = t
		default:
			return f, fmt.Errorf("unknown flag %s (use --session <id|current>, --since today|24h|7d, --project <name>)", a)
		}
	}
	return f, nil
}

// parseSince accepts "today" (local midnight) or a duration with an
// optional d suffix.
func parseSince(v string, now time.Time) (time.Time, error) {
	if v == "today" {
		y, m, d := now.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, now.Location()), nil
	}
	if strings.HasSuffix(v, "d") {
		var days int
		if _, err := fmt.Sscanf(v, "%dd", &days); err == nil && days > 0 {
			return now.Add(-time.Duration(days) * 24 * time.Hour), nil
		}
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return time.Time{}, fmt.Errorf("--since wants today, 24h or 7d, got %q", v)
	}
	return now.Add(-d), nil
}

func (f statsFilter) empty() bool {
	return f.session == "" && f.project == "" && f.since.IsZero()
}

func (f statsFilter) keep(e DecisionEntry) bool {
	if f.session != "" && !strings.HasPrefix(e.SessionID, f.session) {
		return false
	}
	if f.project != "" && e.Project != f.project {
		return false
	}
	if !f.since.IsZero() {
		t, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil || t.Before(f.since) {
			return false
		}
	}
	return true
}

func filterDecisions(entries []DecisionEntry, f statsFilter) []DecisionEntry {
	if f.empty() {
		return entries
	}
	var out []DecisionEntry
	for _, e := range entries {
		if f.keep(e) {
			out = append(out, e)
		}
	}
	return out
}

func (f statsFilter) describe() string {
	var parts []string
	if f.session != "" {
		parts = append(parts, "session "+shortID(f.session))
	}
	if f.project != "" {
		parts = append(parts, "project "+f.project)
	}
	if !f.since.IsZero() {
		parts = append(parts, "since "+f.since.Format("2006-01-02 15:04"))
	}
	return strings.Join(parts, ", ")
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// escalationStats answers "is the second model answering in time": error
// kinds, skipped fires and the latency of the calls that did answer.
type escalationStats struct {
	fired, timeouts, otherErrors, skipped int
	errorsByKind                          map[string]int
	skippedByReason                       map[string]int
	latencies                             []int64 // ms of successful calls, sorted
}

func collectEscalationStats(entries []DecisionEntry) escalationStats {
	s := escalationStats{errorsByKind: map[string]int{}, skippedByReason: map[string]int{}}
	for _, e := range entries {
		if strings.HasPrefix(e.EscalationOutcome, "skipped:") {
			s.skipped++
			s.skippedByReason[strings.TrimPrefix(e.EscalationOutcome, "skipped:")]++
			continue
		}
		if !e.Escalated || e.EscalationOutcome == "" {
			continue
		}
		s.fired++
		if e.EscalationOutcome == "error" {
			kind := e.EscalationError
			if kind == "" {
				kind = "unknown"
			}
			s.errorsByKind[kind]++
			if kind == "timeout" {
				s.timeouts++
			} else {
				s.otherErrors++
			}
			continue
		}
		if e.EscalationMs > 0 {
			s.latencies = append(s.latencies, e.EscalationMs)
		}
	}
	sort.Slice(s.latencies, func(i, j int) bool { return s.latencies[i] < s.latencies[j] })
	return s
}

// percentile returns the p-th percentile (0-100) of sorted values.
func percentile(sorted []int64, p int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	i := (len(sorted) - 1) * p / 100
	return sorted[i]
}

// escalationLatencyWarning compares the measured latency with the
// configured timeout in the same unit (milliseconds) and returns a short
// warning when the second model is near or past it, "" otherwise.
func escalationLatencyWarning(s escalationStats, timeoutSeconds int) string {
	if s.fired < 5 {
		return ""
	}
	timeoutMs := int64(timeoutSeconds) * 1000
	p90 := percentile(s.latencies, 90)
	timeoutRate := pct(s.timeouts, s.fired)
	switch {
	case timeoutRate >= 20:
		return fmt.Sprintf("%d of %d escalations timed out (%d%%)", s.timeouts, s.fired, int(timeoutRate))
	case timeoutMs > 0 && p90*10 >= timeoutMs*8:
		return fmt.Sprintf("p90 %dms is within 20%% of the %ds timeout", p90, timeoutSeconds)
	}
	return ""
}

// askShape is normalizeCommand applied after one leading literal cd, so
// every command run inside the same worktree does not collapse into one
// "cd <dir> &&" bucket.
func askShape(command string) string {
	segs := splitSimpleCommands(command)
	if len(segs) > 1 && (segs[0].term == "&&" || segs[0].term == ";" || segs[0].term == "\n") {
		if words := strings.Fields(segs[0].text); len(words) == 2 && words[0] == "cd" {
			rest := strings.TrimLeft(command[len(segs[0].text)+len(segs[0].term):], " \t")
			return normalizeCommand(rest)
		}
	}
	return normalizeCommand(command)
}

// askKey groups asks of the same command shape within one session.
func askKey(e DecisionEntry) string {
	return e.SessionID + "\x00" + askShape(e.Command)
}

func isAgentEntry(e DecisionEntry) bool { return e.AgentID != "" || e.AgentType != "" }

// repeatedAsks lists command shapes asked more than once in one session.
type repeatedAsk struct {
	session string
	pattern string
	count   int
	agents  int // how many of them came from a subagent
}

func collectRepeatedAsks(entries []DecisionEntry) []repeatedAsk {
	counts := map[string]*repeatedAsk{}
	for _, e := range entries {
		if e.Decision != "ask" || e.Layer == "human" {
			continue
		}
		pat := askShape(e.Command)
		if pat == "" {
			continue
		}
		k := askKey(e)
		r, ok := counts[k]
		if !ok {
			r = &repeatedAsk{session: e.SessionID, pattern: pat}
			counts[k] = r
		}
		r.count++
		if isAgentEntry(e) {
			r.agents++
		}
	}
	var out []repeatedAsk
	for _, r := range counts {
		if r.count >= 2 {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].pattern < out[j].pattern
	})
	return out
}

// inconsistentVerdict is one command shape the escalation model answered
// differently within one session.
type inconsistentVerdict struct {
	session  string
	pattern  string
	verdicts []string
}

func collectInconsistentVerdicts(entries []DecisionEntry) []inconsistentVerdict {
	seen := map[string]map[string]bool{}
	for _, e := range entries {
		if !e.Escalated || e.EscalationDecision == "" {
			continue
		}
		pat := askShape(e.Command)
		if pat == "" {
			continue
		}
		k := askKey(e)
		if seen[k] == nil {
			seen[k] = map[string]bool{}
		}
		seen[k][e.EscalationDecision+"/"+e.EscalationRisk] = true
	}
	var out []inconsistentVerdict
	for k, set := range seen {
		if len(set) < 2 {
			continue
		}
		var vs []string
		for v := range set {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		parts := strings.SplitN(k, "\x00", 2)
		out = append(out, inconsistentVerdict{session: parts[0], pattern: parts[1], verdicts: vs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pattern < out[j].pattern })
	return out
}

// withheldScriptCounts counts, over asks only, how often each referenced
// script was not shown to the judge.
func withheldScriptCounts(entries []DecisionEntry) (asks int, byPath map[string]int) {
	byPath = map[string]int{}
	for _, e := range entries {
		if e.Decision != "ask" || len(e.Withheld) == 0 {
			continue
		}
		asks++
		for _, w := range e.Withheld {
			path := w
			if i := strings.Index(w, ": "); i > 0 {
				path = w[:i]
			}
			byPath[path]++
		}
	}
	return asks, byPath
}

// askResolution is what the human did with an ask: approved, rejected,
// once (a one-time native grant), or unanswered. The exact join uses the
// tool_use_id; without one, the next human answer for the same command
// shape in the same session within askResolutionWindow counts.
const askResolutionWindow = 10 * time.Minute

type askResolution struct {
	ask        DecisionEntry
	resolution string // approved | rejected | once | unanswered
	exact      bool
}

func humanResolution(h DecisionEntry) string {
	switch {
	case h.Source == "allow_once":
		return "once"
	case h.Decision == "allow":
		return "approved"
	case h.Decision == "deny":
		return "rejected"
	}
	return ""
}

func collectAskResolutions(entries []DecisionEntry) []askResolution {
	byTool := map[string]DecisionEntry{}
	byKey := map[string][]DecisionEntry{}
	for _, e := range entries {
		if e.Layer != "human" || humanResolution(e) == "" {
			continue
		}
		if e.ToolUseID != "" {
			byTool[e.ToolUseID] = e
		}
		k := askKey(e)
		byKey[k] = append(byKey[k], e)
	}
	var out []askResolution
	for _, e := range entries {
		if e.Decision != "ask" || e.Layer == "human" {
			continue
		}
		r := askResolution{ask: e, resolution: "unanswered"}
		if e.ToolUseID != "" {
			if h, ok := byTool[e.ToolUseID]; ok {
				r.resolution, r.exact = humanResolution(h), true
				out = append(out, r)
				continue
			}
		}
		askTime, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err == nil {
			for _, h := range byKey[askKey(e)] {
				ht, err := time.Parse(time.RFC3339Nano, h.Timestamp)
				if err != nil || ht.Before(askTime) || ht.Sub(askTime) > askResolutionWindow {
					continue
				}
				r.resolution = humanResolution(h)
				break
			}
		}
		out = append(out, r)
	}
	return out
}

// resolutionTable tallies resolutions under a grouping key.
type resolutionTable map[string]map[string]int

func (t resolutionTable) add(group, resolution string) {
	if t[group] == nil {
		t[group] = map[string]int{}
	}
	t[group][resolution]++
	t[group]["total"]++
}

func (t resolutionTable) sortedGroups() []string {
	var keys []string
	for k := range t {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if t[keys[i]]["total"] != t[keys[j]]["total"] {
			return t[keys[i]]["total"] > t[keys[j]]["total"]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// sessionAskCount ranks sessions by how often they were asked.
type sessionAskCount struct {
	session  string
	project  string
	asks     int
	timeouts int
}

func collectSessionAskCounts(entries []DecisionEntry) []sessionAskCount {
	m := map[string]*sessionAskCount{}
	for _, e := range entries {
		if e.Decision != "ask" || e.Layer == "human" || e.SessionID == "" {
			continue
		}
		s, ok := m[e.SessionID]
		if !ok {
			s = &sessionAskCount{session: e.SessionID, project: e.Project}
			m[e.SessionID] = s
		}
		s.asks++
		if e.EscalationError == "timeout" {
			s.timeouts++
		}
	}
	var out []sessionAskCount
	for _, s := range m {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].asks != out[j].asks {
			return out[i].asks > out[j].asks
		}
		return out[i].session < out[j].session
	})
	return out
}

// todayAnomaly is the one line the bare `yolonot` prints when today's
// asks or escalation timeouts cross a threshold.
const (
	anomalyAsks     = 10
	anomalyTimeouts = 5
)

func todayAnomaly(entries []DecisionEntry, now time.Time) string {
	since, _ := parseSince("today", now)
	asks, timeouts := 0, 0
	for _, e := range filterDecisions(entries, statsFilter{since: since}) {
		if e.Decision == "ask" && e.Layer != "human" {
			asks++
		}
		if e.EscalationError == "timeout" {
			timeouts++
		}
	}
	if asks < anomalyAsks && timeouts < anomalyTimeouts {
		return ""
	}
	return fmt.Sprintf("today: %d asks, %d escalation timeouts — yolonot stats --since today", asks, timeouts)
}
