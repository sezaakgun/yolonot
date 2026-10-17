package yolonot

import (
	"os"
	"strings"
	"testing"
	"time"
)

// incidentEntries mirrors one noisy session: timeouts, a repeated ask from
// a subagent then the main thread, a flipped escalation verdict, a script
// the judge could not see, and the human answers that followed.
func incidentEntries() []DecisionEntry {
	const s1, s2 = "0eaefeff-1111", "ffffffff-2222"
	at := func(min int) string { return time.Date(2026, 10, 16, 8, min, 0, 0, time.UTC).Format(time.RFC3339Nano) }
	ask := func(session, cmd string, min int) DecisionEntry {
		return DecisionEntry{Timestamp: at(min), SessionID: session, Command: cmd, Cwd: "/w/" + session, Project: "proj-" + session[:1], Layer: "gemini", Decision: "ask", Risk: "moderate"}
	}
	gates := "cd /w && .local-ci/run-gates.sh --stage pre-commit 2>&1 | tail"
	e := []DecisionEntry{}
	// 3 timeouts, 2 answered (14s, 20s) in session 1
	for i, min := range []int{1, 2, 3} {
		x := ask(s1, "cat > .claude/settings.json <<'EOF'\n{\"hooks\": "+strings.Repeat("x", i)+"}\nEOF", min)
		x.Escalated, x.EscalationOutcome, x.EscalationError, x.EscalationMs = true, "error", "timeout", 30001
		e = append(e, x)
	}
	a := ask(s1, gates, 10)
	a.Escalated, a.EscalationOutcome, a.EscalationDecision, a.EscalationRisk, a.EscalationMs = true, "kept", "ask", "moderate", 14000
	a.AgentID, a.AgentType = "agent-1", "Explore"
	a.Withheld = []string{".local-ci/run-gates.sh: not provably the file this command executes"}
	a.ToolUseID = "tu-1"
	e = append(e, a)
	// the human approved it once in the native dialog, exact join
	e = append(e, DecisionEntry{Timestamp: at(11), SessionID: s1, Command: gates, Cwd: "/w/" + s1, Project: "proj-0", Layer: "human", Decision: "allow", Source: "allow_once", ToolUseID: "tu-1"})
	// main thread asks the same command again, escalation flips to allow/low but kept
	b := ask(s1, gates, 12)
	b.Escalated, b.EscalationOutcome, b.EscalationDecision, b.EscalationRisk, b.EscalationMs = true, "kept", "allow", "moderate", 20000
	b.Withheld = a.Withheld
	e = append(e, b)
	// fallback join: approved by the CLI 3 minutes later, no tool_use_id
	e = append(e, DecisionEntry{Timestamp: at(15), SessionID: s1, Command: gates, Cwd: "/w/" + s1, Project: "proj-0", Layer: "human", Decision: "allow", Source: "ask_approved"})
	// an ask nobody answered within the window
	e = append(e, ask(s1, "docker rm -f box", 30))
	e = append(e, DecisionEntry{Timestamp: at(50), SessionID: s1, Command: "docker rm -f box", Cwd: "/w/" + s1, Project: "proj-0", Layer: "human", Decision: "deny", Source: "ask_rejected"})
	// a skipped escalation and a quiet second session
	c := ask(s2, "aws s3 ls", 5)
	c.EscalationOutcome = "skipped:budget"
	e = append(e, c)
	e = append(e, DecisionEntry{Timestamp: at(6), SessionID: s2, Command: "ls", Cwd: "/w/" + s2, Project: "proj-f", Layer: "rule", Decision: "allow"})
	return e
}

func TestStatsFilterSessionPrefixSinceProject(t *testing.T) {
	entries := incidentEntries()
	if got := len(filterDecisions(entries, statsFilter{session: "0eaefeff"})); got != 9 {
		t.Errorf("session prefix filter kept %d, want 9", got)
	}
	if got := len(filterDecisions(entries, statsFilter{project: "proj-f"})); got != 2 {
		t.Errorf("project filter kept %d, want 2", got)
	}
	since := time.Date(2026, 10, 16, 8, 12, 0, 0, time.UTC)
	if got := len(filterDecisions(entries, statsFilter{since: since})); got != 4 {
		t.Errorf("since filter kept %d, want 4", got)
	}
	now := time.Date(2026, 10, 16, 23, 30, 0, 0, time.FixedZone("plus3", 3*3600))
	if got, _ := parseSince("today", now); got.Hour() != 0 || got.Day() != 16 {
		t.Errorf("today = %v, want local midnight", got)
	}
	if got, _ := parseSince("7d", now); now.Sub(got) != 7*24*time.Hour {
		t.Errorf("7d = %v", got)
	}
	if _, err := parseSince("yesterday", now); err == nil {
		t.Error("unknown --since value should error")
	}
	if _, err := parseStatsArgs([]string{"--bogus"}); err == nil {
		t.Error("unknown flag should error")
	}
}

func TestEscalationStatsAndLatencyWarning(t *testing.T) {
	es := collectEscalationStats(incidentEntries())
	if es.fired != 5 || es.timeouts != 3 || es.errorsByKind["timeout"] != 3 || es.skipped != 1 || es.skippedByReason["budget"] != 1 {
		t.Errorf("stats: %+v", es)
	}
	if p := percentile(es.latencies, 50); p != 14000 {
		t.Errorf("p50 = %d", p)
	}
	// 3 of 5 timed out: the rate warning wins regardless of latency.
	if w := escalationLatencyWarning(es, 30); !strings.Contains(w, "3 of 5 escalations timed out (60%)") {
		t.Errorf("warning = %q", w)
	}
	// Latency compared in milliseconds against a timeout given in seconds:
	// p90 25s against 30s is within 20%; against 60s it is not.
	slow := escalationStats{fired: 10, latencies: []int64{1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 25000, 26000}}
	if w := escalationLatencyWarning(slow, 30); !strings.Contains(w, "p90 25000ms is within 20% of the 30s timeout") {
		t.Errorf("latency warning = %q", w)
	}
	if w := escalationLatencyWarning(slow, 60); w != "" {
		t.Errorf("no warning expected at 60s, got %q", w)
	}
	if w := escalationLatencyWarning(escalationStats{fired: 4, timeouts: 4}, 30); w != "" {
		t.Errorf("fewer than 5 fires must not warn, got %q", w)
	}
}

func TestRepeatedInconsistentAndWithheld(t *testing.T) {
	entries := incidentEntries()
	rep := collectRepeatedAsks(entries)
	if len(rep) != 2 || rep[0].count != 3 || rep[1].count != 2 || rep[1].agents != 1 || rep[1].pattern != ".local-ci/run-gates.sh --stage pre-commit" {
		t.Errorf("repeats: %+v", rep)
	}
	flips := collectInconsistentVerdicts(entries)
	if len(flips) != 1 || strings.Join(flips[0].verdicts, ",") != "allow/moderate,ask/moderate" {
		t.Errorf("flips: %+v", flips)
	}
	asks, byPath := withheldScriptCounts(entries)
	if asks != 2 || byPath[".local-ci/run-gates.sh"] != 2 {
		t.Errorf("withheld: %d %v", asks, byPath)
	}
}

func TestAskResolutionsJoinExactThenWindow(t *testing.T) {
	entries := incidentEntries()
	res := collectAskResolutions(entries)
	got := map[string]string{}
	for _, r := range res {
		got[r.ask.Timestamp[11:16]+" "+r.resolution] = map[bool]string{true: "exact", false: "window"}[r.exact]
	}
	for want, how := range map[string]string{
		"08:10 once":       "exact",  // tool_use_id join to the allow_once
		"08:12 approved":   "window", // CLI approve 3 minutes later
		"08:30 unanswered": "window", // the rejection came 20 minutes later
		"08:05 unanswered": "window",
	} {
		if got[want] != how {
			t.Errorf("resolution %q: want %s, got %q (all: %v)", want, how, got[want], got)
		}
	}
	// The window join is reporting only: neither the ask nor the one-time
	// grant it joined becomes a precedent.
	for _, e := range entries {
		if e.Decision == "ask" && isPrecedent(e) {
			t.Errorf("an ask must never be a precedent: %+v", e)
		}
		if e.Source == "allow_once" && isPrecedent(e) {
			t.Errorf("allow_once must stay out of precedents: %+v", e)
		}
	}
	sessions := collectSessionAskCounts(entries)
	if len(sessions) != 2 || sessions[0].asks != 6 || sessions[0].timeouts != 3 {
		t.Errorf("sessions: %+v", sessions)
	}
}

func TestTodayAnomalyLine(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	if line := todayAnomaly(incidentEntries(), now); line != "" {
		t.Errorf("6 asks and 3 timeouts are under the thresholds, got %q", line)
	}
	var many []DecisionEntry
	for i := 0; i < anomalyAsks; i++ {
		many = append(many, DecisionEntry{Timestamp: now.Format(time.RFC3339Nano), SessionID: "s", Command: "x", Layer: "gemini", Decision: "ask"})
	}
	if line := todayAnomaly(many, now); !strings.Contains(line, "today: 10 asks, 0 escalation timeouts") {
		t.Errorf("line = %q", line)
	}
	if line := todayAnomaly(many, now.Add(24*time.Hour)); line != "" {
		t.Errorf("yesterday's asks must not count, got %q", line)
	}
}

func TestCmdStatsSessionReport(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	writeTestDecisions(t, incidentEntries())
	out := captureStdout(func() { cmdStats("--session", "0eaefeff") })
	for _, want := range []string{
		"session 0eaefeff",
		"timeout          3",
		"Asks by caller:    5 main thread, 1 subagent",
		"Asked more than once in one session:",
		"3x  cat > .claude/settings.json",
		"2x  .local-ci/run-gates.sh --stage pre-commit",
		"Escalation answered the same command differently:",
		"allow/moderate vs ask/moderate",
		"Asks where a referenced script was not shown to the judge: 2",
		"2x  .local-ci/run-gates.sh",
		"What you did with the asks",
		"6:  1 / 1 / 0 / 4",
		"2:  1 / 1 / 0 / 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stats output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Sessions with most asks") {
		t.Error("a session-filtered report must not rank sessions")
	}
	all := captureStdout(func() { cmdStats() })
	if !strings.Contains(all, "Sessions with most asks") || !strings.Contains(all, "6 asks  0eaefeff  proj-0  (3 escalation timeouts)") {
		t.Errorf("unfiltered report should rank sessions:\n%s", all)
	}
	if none := captureStdout(func() { cmdStats("--project", "nope") }); !strings.Contains(none, "No decisions match project nope") {
		t.Errorf("empty filter message:\n%s", none)
	}
}

func TestCmdLogSessionFilterAndEscalationColumn(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	writeTestDecisions(t, incidentEntries())
	out := captureStdout(func() { cmdLog(50, "ffffffff") })
	if strings.Contains(out, "run-gates") || !strings.Contains(out, "aws s3 ls") {
		t.Errorf("session filter:\n%s", out)
	}
	out = captureStdout(func() { cmdLog(50, "0eaefeff") })
	if !strings.Contains(out, "⤴esc 30001ms timeout") || !strings.Contains(out, "⤴esc 14000ms kept  [Explore]") {
		t.Errorf("escalation column:\n%s", out)
	}
}

func TestLogDecisionRoundTripsAgentAndScriptFields(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	currentAgentID, currentAgentType, currentToolUseID = "agent-9", "security-reviewer", "tu-9"
	t.Cleanup(func() { currentAgentID, currentAgentType, currentToolUseID = "", "", "" })
	LogDecision(DecisionEntry{SessionID: "s", Command: "./x.sh", Cwd: "/w", Layer: "gemini", Decision: "ask",
		Attached: []string{"./x.sh"}, Withheld: []string{"y.sh: not provably the file this command executes"}})
	got := ReadRecentDecisions(1)
	if len(got) != 1 {
		t.Fatal("no entry logged")
	}
	e := got[0]
	if e.AgentID != "agent-9" || e.AgentType != "security-reviewer" || e.ToolUseID != "tu-9" ||
		len(e.Attached) != 1 || e.Attached[0] != "./x.sh" || len(e.Withheld) != 1 || !strings.HasPrefix(e.Withheld[0], "y.sh: ") {
		t.Errorf("round trip lost fields: %+v", e)
	}
}

func TestDoctorEscalationLatencyAndRuleLint(t *testing.T) {
	c, ok := escalationLatencyCheck(incidentEntries(), 30)
	if !ok || c.Status != "warning" || !strings.Contains(c.Detail, "3 of 5 escalations timed out") || !strings.Contains(c.Detail, "timeout 30s") {
		t.Errorf("latency check: %+v", c)
	}
	if _, ok := escalationLatencyCheck(nil, 30); ok {
		t.Error("no fires, no check")
	}

	rules := []Rule{
		{Action: "deny", Type: "cmd", Pattern: "*rm -rf /*"},
		{Action: "deny", Type: "cmd", Pattern: "*rm -rf /"},
		{Action: "deny", Type: "cmd", Pattern: "*rm -rf /?"},
		{Action: "allow", Type: "cmd", Pattern: "ls /*"},
		{Action: "deny", Type: "path", Pattern: "/*"},
	}
	checks := ruleLintChecks(rules)
	if len(checks) != 1 || !strings.Contains(checks[0].Detail, `also matches "rm -rf /tmp/probe"`) ||
		!strings.Contains(checks[0].Detail, "`deny-cmd *rm -rf /` and `deny-cmd *rm -rf /?`") {
		t.Fatalf("lint: %+v", checks)
	}
	// The suggested narrow forms must match the root and nothing under it.
	probe := "rm -rf /tmp/probe"
	for _, narrow := range []string{"*rm -rf /", "*rm -rf /?"} {
		if matchCmd(narrow, probe, "rm") {
			t.Errorf("%q must not match %q", narrow, probe)
		}
	}
	if !matchCmd("*rm -rf /", "rm -rf /", "rm") || !matchCmd("*rm -rf /?", "rm -rf /*", "rm") {
		t.Error("the narrow forms must still catch the root")
	}
}

func TestDefaultAskHintsCoverHookBypassAndNestedAgents(t *testing.T) {
	joined := strings.Join(builtinClassifierAskHints, "\n")
	for _, want := range []string{"--no-verify", "core.hooksPath", "claude -p", "codex exec"} {
		if !strings.Contains(joined, want) {
			t.Errorf("default ask hints lack %q", want)
		}
	}
}

func TestLogHumanLearningCandidates(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	proj := t.TempDir()
	os.MkdirAll(proj+"/.git", 0755)
	t.Chdir(proj)
	cwd, _ := os.Getwd()
	cmd := "make -C build test"
	entries := []DecisionEntry{
		{Timestamp: "2026-10-16T08:00:00Z", SessionID: "s", Command: cmd, Cwd: cwd, Layer: "gemini", Decision: "ask"},
		{Timestamp: "2026-10-16T08:01:00Z", SessionID: "s", Command: cmd, Cwd: cwd, Layer: "human", Decision: "allow", Source: "allow_once"},
		{Timestamp: "2026-10-16T08:02:00Z", SessionID: "s", Command: cmd, Cwd: cwd, Layer: "gemini", Decision: "ask"},
		{Timestamp: "2026-10-16T08:03:00Z", SessionID: "s", Command: cmd, Cwd: cwd, Layer: "human", Decision: "allow", Source: "allow_once"},
		{Timestamp: "2026-10-16T08:04:00Z", SessionID: "s", Command: "once only", Cwd: cwd, Layer: "gemini", Decision: "ask"},
		{Timestamp: "2026-10-16T08:05:00Z", SessionID: "s", Command: "once only", Cwd: cwd, Layer: "human", Decision: "allow", Source: "allow_once"},
		{Timestamp: "2026-10-16T08:06:00Z", SessionID: "s", Command: "denied once", Cwd: cwd, Layer: "gemini", Decision: "ask"},
		{Timestamp: "2026-10-16T08:06:10Z", SessionID: "s", Command: "denied once", Cwd: cwd, Layer: "human", Decision: "allow", Source: "allow_once"},
		{Timestamp: "2026-10-16T08:06:20Z", SessionID: "s", Command: "denied once", Cwd: cwd, Layer: "gemini", Decision: "ask"},
		{Timestamp: "2026-10-16T08:06:30Z", SessionID: "s", Command: "denied once", Cwd: cwd, Layer: "human", Decision: "allow", Source: "allow_once"},
		{Timestamp: "2026-10-16T08:06:40Z", SessionID: "s", Command: "denied once", Cwd: cwd, Layer: "gemini", Decision: "ask"},
		{Timestamp: "2026-10-16T08:06:50Z", SessionID: "s", Command: "denied once", Cwd: cwd, Layer: "human", Decision: "deny", Source: "ask_rejected"},
		{Timestamp: "2026-10-16T08:07:00Z", SessionID: "s", Command: cmd, Cwd: t.TempDir(), Layer: "gemini", Decision: "ask"},
	}
	out := captureStdout(func() { printLearningCandidates(cwd, entries) })
	if !strings.Contains(out, "2x asked, 2x allowed:  yolonot approve \"make -C build test\"") || strings.Contains(out, "once only") || strings.Contains(out, "denied once") {
		t.Errorf("candidates:\n%s", out)
	}
	recordPrecedent(DecisionEntry{Layer: "human", Source: "ask_approved", Decision: "allow", Cwd: cwd, Command: cmd, Timestamp: "2026-10-16T09:00:00Z"})
	if out := captureStdout(func() { printLearningCandidates(cwd, entries) }); out != "" {
		t.Errorf("a command that is already a precedent is not a candidate:\n%s", out)
	}
}

func TestSuggestBucketsWithheldAndTimeoutSeparately(t *testing.T) {
	entries := incidentEntries()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for i := range entries {
		entries[i].Timestamp = now
	}
	findings := collectEvolveFindings(entries, nil)
	cats := map[string]evolveFinding{}
	for _, f := range findings {
		cats[f.Category] = f
	}
	if f, ok := cats["SCRIPT NOT SHOWN"]; !ok || f.Pattern != ".local-ci/run-gates.sh" || f.Count != 2 {
		t.Errorf("withheld bucket: %+v", cats)
	}
	if f, ok := cats["ESCALATION TIMEOUT"]; !ok || f.Count != 3 {
		t.Errorf("timeout bucket: %+v", cats)
	}
	if f, ok := cats["REPEATED ASK"]; ok {
		t.Errorf("timeouts and unseen scripts must not also count as plain repeated asks: %+v", f)
	}
	prompt := buildSuggestUserPrompt(cats["SCRIPT NOT SHOWN"])
	if !strings.Contains(prompt, "SCRIPT NOT SHOWN") || !strings.Contains(prompt, "not shown: .local-ci/run-gates.sh") || !strings.Contains(prompt, "from a subagent") {
		t.Errorf("prompt lacks judge context:\n%s", prompt)
	}
	a, b := cats["SCRIPT NOT SHOWN"], cats["SCRIPT NOT SHOWN"]
	b.Context = []string{"different"}
	if suggestCacheKey(a) == suggestCacheKey(b) {
		t.Error("a different prompt must not reuse the cached answer")
	}
}
