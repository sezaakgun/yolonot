package main

import (
	"fmt"
	"sort"
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

func cmdStats() {
	entries := ReadRecentDecisions(1000000)
	if len(entries) == 0 {
		fmt.Println("No decisions logged yet.")
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

	// Counts by layer
	layerCounts := map[string]int{}

	// LLM latency tracking
	llmCallCount := 0
	var llmTotalMs int64

	// Instant allows (rule/session/cache with allow decision)
	instantAllows := 0

	// Asked commands for "top asked" grouping
	askedCmds := map[string]int{}

	// Project breakdown
	projectMap := map[string]*projectStats{}

	for _, e := range entries {
		switch e.Decision {
		case "allow":
			allowCount++
		case "ask":
			askCount++
		case "deny":
			denyCount++
		case "passthrough":
			passthroughCount++
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

		// Instant allows
		if e.Decision == "allow" && (layer == "rule" || layer == "pre_check" || layer == "session" || layer == "cache") {
			instantAllows++
		}

		// Asked commands
		if e.Decision == "ask" && e.Command != "" {
			key := normalizeCommand(e.Command)
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

	// Print header
	fmt.Printf("yolonot stats (%s)\n\n", dateRange)

	// Decision counts
	fmt.Printf("  Total decisions:   %d\n", total)
	fmt.Printf("  Allowed:           %3d (%d%%)\n", allowCount, int(pct(allowCount, total)))
	fmt.Printf("  Asked:             %3d (%d%%)\n", askCount, int(pct(askCount, total)))
	fmt.Printf("  Denied:            %3d (%d%%)\n", denyCount, int(pct(denyCount, total)))
	if passthroughCount > 0 {
		fmt.Printf("  Passthrough:       %3d (LLM unavailable)\n", passthroughCount)
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
		for _, ps := range projects {
			fmt.Printf("    %-18s %3d (allow: %d, ask: %d, deny: %d)\n",
				ps.name, ps.total, ps.allow, ps.ask, ps.deny)
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
	preferred := []string{"rule", "pre_check", "session", "session_llm", "cache", "llm", "session_deny"}
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
