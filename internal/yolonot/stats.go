package yolonot

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) * 100.0 / float64(total)
}

type projectStats struct {
	name  string
	total int
	allow int
	ask   int
	deny  int
}

func cmdStats(args ...string) {
	filter, err := parseStatsArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "yolonot stats:", err)
		os.Exit(2)
	}
	entries := filterDecisions(ReadRecentDecisions(1000000), filter)
	if len(entries) == 0 {
		if filter.empty() {
			fmt.Println("No decisions logged yet.")
		} else {
			fmt.Printf("No decisions match %s.\n", filter.describe())
		}
		return
	}

	// Parse date range
	firstTS := entries[0].Timestamp
	lastTS := entries[len(entries)-1].Timestamp
	dateRange := formatDateRange(firstTS, lastTS)

	// Counts by decision
	total := len(entries)
	allowCount := 0
	askCount := 0
	denyCount := 0
	passthroughCount := 0
	riskPassthroughCount := 0

	// Counts by layer
	layerCounts := map[string]int{}

	// LLM latency tracking
	llmCallCount := 0
	var llmTotalMs int64

	// Escalation tracking
	escFired := 0
	escRescued := 0
	escHardened := 0
	escErrors := 0
	var escTotalMs int64

	// Instant allows (rule/session/cache with allow decision)
	instantAllows := 0

	// Human ask resolutions (layer "human"). Counted separately — they are
	// labels for what the user answered, not gate decisions, and the deny
	// side is always logged alongside a session_deny gate entry (counting
	// both would double-count).
	humanApproved := 0
	humanRejected := 0
	pausedSkipped := 0
	unsandboxedCount := 0

	// Asked commands for "top asked" grouping
	askedCmds := map[string]int{}

	// Project breakdown
	projectMap := map[string]*projectStats{}

	for _, e := range entries {
		if e.Layer == "pause" {
			pausedSkipped++
			continue
		}
		if e.Layer == "human" {
			switch e.Decision {
			case "allow":
				humanApproved++
			case "deny":
				humanRejected++
			}
			continue
		}
		if e.BypassSandbox {
			unsandboxedCount++
		}
		switch e.Decision {
		case "allow":
			allowCount++
		case "ask":
			askCount++
		case "deny":
			denyCount++
		case "passthrough", "":
			passthroughCount++
			if e.OrigDecision != "" {
				riskPassthroughCount++
			}
		}

		layer := e.Layer
		if layer == "" {
			layer = "unknown"
		}
		layerCounts[layer]++

		// LLM latency
		if e.DurationMs > 0 {
			llmCallCount++
			llmTotalMs += e.DurationMs
		}

		// Escalation (cache replays carry Escalated without an outcome —
		// count only live fires here)
		if e.Escalated && e.EscalationOutcome != "" {
			escFired++
			escTotalMs += e.EscalationMs
			switch e.EscalationOutcome {
			case "rescued":
				escRescued++
			case "hardened":
				escHardened++
			case "error":
				escErrors++
			}
		}

		// Instant allows
		if e.Decision == "allow" && (layer == "rule" || layer == "pre_check" || strings.HasPrefix(layer, "exec:") || layer == "fast_allow" || layer == "session" || layer == "cache") {
			instantAllows++
		}

		// Asked commands
		if (e.Decision == "ask" || e.OrigDecision == "ask") && e.Command != "" {
			key := askShape(e.Command)
			if key != "" {
				askedCmds[key]++
			}
		}

		// Project breakdown
		proj := e.Project
		if proj == "" {
			proj = "unknown"
		}
		ps, ok := projectMap[proj]
		if !ok {
			ps = &projectStats{name: proj}
			projectMap[proj] = ps
		}
		ps.total++
		switch e.Decision {
		case "allow":
			ps.allow++
		case "ask":
			ps.ask++
		case "deny":
			ps.deny++
		}
	}

	// Human and pause entries were skipped by the loop; keep them out of the
	// decision percentages too.
	total -= humanApproved + humanRejected + pausedSkipped

	// Print header
	if filter.empty() {
		fmt.Printf("yolonot stats (%s)\n\n", dateRange)
	} else {
		fmt.Printf("yolonot stats (%s; %s)\n\n", dateRange, filter.describe())
	}

	printImpactSummary(entries, total, allowCount, instantAllows, escRescued, escHardened, denyCount, layerCounts["session_deny"], humanRejected, llmCallCount, llmTotalMs)

	// Decision counts
	fmt.Printf("  Total decisions:   %d\n", total)
	fmt.Printf("  Allowed:           %3d (%d%%)\n", allowCount, int(pct(allowCount, total)))
	fmt.Printf("  Asked:             %3d (%d%%)\n", askCount, int(pct(askCount, total)))
	fmt.Printf("  Denied:            %3d (%d%%)\n", denyCount, int(pct(denyCount, total)))
	if passthroughCount > 0 {
		label := "LLM unavailable"
		if riskPassthroughCount == passthroughCount {
			label = "risk map"
		} else if riskPassthroughCount > 0 {
			label = "risk map / LLM unavailable"
		}
		fmt.Printf("  Passthrough:       %3d (%s)\n", passthroughCount, label)
	}
	if unsandboxedCount > 0 {
		fmt.Printf("  Unsandboxed:       %3d\n", unsandboxedCount)
	}
	if humanApproved > 0 || humanRejected > 0 {
		fmt.Printf("\n  Ask resolutions:   %d approved, %d rejected by user\n", humanApproved, humanRejected)
	}

	// Layer breakdown
	fmt.Printf("\n  By layer:\n")
	layerOrder := sortedLayerKeys(layerCounts)
	for _, layer := range layerOrder {
		count := layerCounts[layer]
		fmt.Printf("    %-18s %3d (%d%%)\n", layer, count, int(pct(count, total)))
	}

	// LLM latency
	fmt.Println()
	if llmCallCount > 0 {
		avgMs := llmTotalMs / int64(llmCallCount)
		fmt.Printf("  LLM calls:         %3d (avg %dms)\n", llmCallCount, avgMs)
	}
	fmt.Printf("  Instant allows:    %3d (rule/session/cache — no LLM needed)\n", instantAllows)

	// Escalation — the counter that answers "is the second model earning
	// its keep": how often it fired, how often it spared an ask, and
	// whether it answers before its own timeout.
	if escFired > 0 {
		avgEscMs := escTotalMs / int64(escFired)
		fmt.Printf("\n  Escalation:        %3d fired, %d rescued (%d%%), %d hardened, avg %dms\n",
			escFired, escRescued, int(pct(escRescued, escFired)), escHardened, avgEscMs)
		es := collectEscalationStats(entries)
		if len(es.latencies) > 0 {
			fmt.Printf("    Answered:        %3d (p50 %dms, p90 %dms)\n", len(es.latencies), percentile(es.latencies, 50), percentile(es.latencies, 90))
		}
		if escErrors > 0 {
			fmt.Printf("    Errors:          %3d (provider failures — the primary verdict stood)\n", escErrors)
			for _, kind := range sortedKeys(es.errorsByKind) {
				fmt.Printf("      %-14s %3d\n", kind, es.errorsByKind[kind])
			}
		}
		if es.skipped > 0 {
			fmt.Printf("    Skipped:         %3d (%s)\n", es.skipped, joinCounts(es.skippedByReason))
		}
		if esc := GetEscalationConfig(); esc.Model != "" {
			timeout := resolveTimeoutSeconds(esc, 10)
			if warn := escalationLatencyWarning(es, timeout); warn != "" {
				fmt.Printf("    ⚠ %s — raise its timeout or pick a faster model (yolonot models)\n", warn)
			}
		}
	}

	// Top asked
	if len(askedCmds) > 0 {
		fmt.Printf("\n  Top asked (rule candidates):\n")
		type cmdCount struct {
			cmd   string
			count int
		}
		var sorted []cmdCount
		for cmd, count := range askedCmds {
			sorted = append(sorted, cmdCount{cmd, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].count != sorted[j].count {
				return sorted[i].count > sorted[j].count
			}
			return sorted[i].cmd < sorted[j].cmd
		})
		limit := 5
		if len(sorted) < limit {
			limit = len(sorted)
		}
		for _, sc := range sorted[:limit] {
			fmt.Printf("    %dx  %s\n", sc.count, sc.cmd)
		}
	}

	printAskDiagnostics(entries, filter)

	// Project breakdown
	if len(projectMap) > 0 {
		fmt.Printf("\n  By project:\n")
		var projects []projectStats
		for _, ps := range projectMap {
			projects = append(projects, *ps)
		}
		sort.Slice(projects, func(i, j int) bool {
			if projects[i].total != projects[j].total {
				return projects[i].total > projects[j].total
			}
			return projects[i].name < projects[j].name
		})
		maxProjects := 10
		shown := projects
		if len(shown) > maxProjects {
			shown = shown[:maxProjects]
		}
		for _, ps := range shown {
			fmt.Printf("    %-18s %3d (allow: %d, ask: %d, deny: %d)\n",
				ps.name, ps.total, ps.allow, ps.ask, ps.deny)
		}
		if len(projects) > maxProjects {
			fmt.Printf("    … and %d more projects\n", len(projects)-maxProjects)
		}
	}
}

func formatDateRange(first, last string) string {
	layout := time.RFC3339Nano
	t1, err1 := time.Parse(layout, first)
	t2, err2 := time.Parse(layout, last)
	if err1 != nil || err2 != nil {
		// Fallback: try to extract date portion
		d1 := extractDate(first)
		d2 := extractDate(last)
		if d1 != "" && d2 != "" {
			return d1 + " → " + d2
		}
		return "all time"
	}
	return t1.Format("2006-01-02") + " → " + t2.Format("2006-01-02")
}

func extractDate(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ""
}

func sortedLayerKeys(m map[string]int) []string {
	// Preferred order for known layers
	preferred := []string{"rule", "fast_allow", "pre_check", "session", "session_llm", "cache", "llm", "session_deny"}
	var result []string
	seen := map[string]bool{}
	for _, k := range preferred {
		if _, ok := m[k]; ok {
			result = append(result, k)
			seen[k] = true
		}
	}
	// Append any unknown layers alphabetically
	var extra []string
	for k := range m {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	result = append(result, extra...)
	return result
}

func sortedKeys(m map[string]int) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinCounts(m map[string]int) string {
	var parts []string
	for _, k := range sortedKeys(m) {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// printAskDiagnostics is the part of stats that explains a noisy session:
// who asked, what was asked twice, where the second model contradicted
// itself, which scripts the judge could not see, and what the human did
// with each ask.
func printAskDiagnostics(entries []DecisionEntry, filter statsFilter) {
	mainAsks, agentAsks := 0, 0
	for _, e := range entries {
		if (e.Decision != "ask" && e.OrigDecision != "ask") || e.Layer == "human" {
			continue
		}
		if isAgentEntry(e) {
			agentAsks++
		} else {
			mainAsks++
		}
	}
	if agentAsks > 0 {
		fmt.Printf("\n  Asks by caller:    %d main thread, %d subagent\n", mainAsks, agentAsks)
	}

	if repeats := collectRepeatedAsks(entries); len(repeats) > 0 {
		fmt.Printf("\n  Asked more than once in one session:\n")
		for i, r := range repeats {
			if i == 5 {
				fmt.Printf("    … %d more\n", len(repeats)-5)
				break
			}
			from := ""
			if r.agents > 0 {
				from = fmt.Sprintf(", %d from subagents", r.agents)
			}
			fmt.Printf("    %dx  %s  (session %s%s)\n", r.count, r.pattern, shortID(r.session), from)
		}
	}

	if flips := collectInconsistentVerdicts(entries); len(flips) > 0 {
		fmt.Printf("\n  Escalation answered the same command differently:\n")
		for i, f := range flips {
			if i == 5 {
				fmt.Printf("    … %d more\n", len(flips)-5)
				break
			}
			fmt.Printf("    %s → %s  (session %s)\n", f.pattern, strings.Join(f.verdicts, " vs "), shortID(f.session))
		}
	}

	if asks, byPath := withheldScriptCounts(entries); asks > 0 {
		fmt.Printf("\n  Asks where a referenced script was not shown to the judge: %d\n", asks)
		paths := sortedKeys(byPath)
		sort.SliceStable(paths, func(i, j int) bool { return byPath[paths[i]] > byPath[paths[j]] })
		for i, p := range paths {
			if i == 5 {
				break
			}
			fmt.Printf("    %dx  %s\n", byPath[p], p)
		}
		fmt.Printf("    (yolonot check '<command>' prints why; an allow-hint can describe routine scripts)\n")
	}

	if res := collectAskResolutions(entries); len(res) > 0 {
		byLayer, byOutcome := resolutionTable{}, resolutionTable{}
		for _, r := range res {
			byLayer.add(r.ask.Layer, r.resolution)
			if r.ask.Escalated && r.ask.EscalationOutcome != "" {
				byOutcome.add("escalation "+r.ask.EscalationOutcome, r.resolution)
			}
		}
		fmt.Printf("\n  What you did with the asks (approved / once / rejected / unanswered):\n")
		for _, g := range byLayer.sortedGroups() {
			c := byLayer[g]
			fmt.Printf("    %-24s %3d:  %d / %d / %d / %d\n", g, c["total"], c["approved"], c["once"], c["rejected"], c["unanswered"])
		}
		for _, g := range byOutcome.sortedGroups() {
			c := byOutcome[g]
			fmt.Printf("    %-24s %3d:  %d / %d / %d / %d\n", g, c["total"], c["approved"], c["once"], c["rejected"], c["unanswered"])
		}
	}

	if filter.session == "" {
		if sessions := collectSessionAskCounts(entries); len(sessions) > 1 {
			fmt.Printf("\n  Sessions with most asks (yolonot stats --session <id>):\n")
			for i, s := range sessions {
				if i == 5 {
					break
				}
				fmt.Printf("    %3d asks  %s  %s  (%d escalation timeouts)\n", s.asks, shortID(s.session), s.project, s.timeouts)
			}
		}
	}
}

func printImpactSummary(entries []DecisionEntry, total, allowCount, instantAllows, escRescued, escHardened, denyCount, repeatBlocked, humanRejected, llmCallCount int, llmTotalMs int64) {
	judgeAllows := allowCount - instantAllows
	if judgeAllows < 0 {
		judgeAllows = 0
	}
	rescuedPart := ""
	if escRescued > 0 {
		rescuedPart = fmt.Sprintf(", %d rescued by 2nd model", escRescued)
	}
	fmt.Printf("  Impact:\n")
	fmt.Printf("    Auto-approved:   %d (%d%% — %d instant 0ms, %d AI judge%s)\n",
		allowCount, int(pct(allowCount, total)), instantAllows, judgeAllows, rescuedPart)
	if llmCallCount > 0 && instantAllows > 0 {
		avgMs := llmTotalMs / int64(llmCallCount)
		savedSec := float64(int64(instantAllows)*avgMs) / 1000.0
		fmt.Printf("    Speed saved:     %d LLM calls skipped (~%.1fs saved at %dms avg)\n", instantAllows, savedSec, avgMs)
	} else {
		fmt.Printf("    Speed saved:     %d LLM calls skipped (instant local allow)\n", instantAllows)
	}

	autoDenied := denyCount - repeatBlocked
	if autoDenied < 0 {
		autoDenied = 0
	}
	hardenedAsks := 0
	for _, e := range entries {
		if e.Escalated && e.EscalationOutcome == "hardened" && e.Decision == "ask" {
			hardenedAsks++
		}
	}
	threatsTotal := autoDenied + hardenedAsks + humanRejected
	if threatsTotal == 0 && repeatBlocked > 0 {
		threatsTotal = repeatBlocked
	}
	var parts []string
	if autoDenied > 0 {
		parts = append(parts, fmt.Sprintf("%d auto-denied", autoDenied))
	}
	if escHardened > 0 {
		parts = append(parts, fmt.Sprintf("%d hardened by 2nd model", escHardened))
	}
	if humanRejected > 0 {
		parts = append(parts, fmt.Sprintf("%d rejected by user", humanRejected))
	}
	if repeatBlocked > 0 {
		parts = append(parts, fmt.Sprintf("%d repeat blocked", repeatBlocked))
	}
	if len(parts) > 0 {
		fmt.Printf("    Threats stopped: %d (%s)\n", threatsTotal, strings.Join(parts, ", "))
	} else {
		fmt.Printf("    Threats stopped: 0\n")
	}
	for _, inc := range collectThreatIncidents(entries) {
		cmd := truncateStr(strings.ReplaceAll(inc.command, "\n", " ⏎ "), 60)
		mult := ""
		if inc.count > 1 {
			mult = fmt.Sprintf("%dx ", inc.count)
		}
		reason := ""
		if inc.reason != "" {
			reason = " " + truncateStr(inc.reason, 70)
		}
		fmt.Printf("      ✗ %s%s  [%s]%s\n", mult, cmd, inc.tag, reason)
	}
	fmt.Println()
}
