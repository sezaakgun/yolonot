package yolonot

import (
	"fmt"
	"strconv"
)

func projectRoot(cwd string) string {
	if cwd == "" {
		return ""
	}
	cwd = canonicalDirectory(cwd)
	if root := gitRoot(cwd); root != "" {
		return root
	}
	return cwd
}

type learningCandidate struct {
	Command string `json:"command"`
	Asks    int    `json:"asks"`
	Allows  int    `json:"allows"`
}

func filterEntriesByProject(cwd string, entries []DecisionEntry) []DecisionEntry {
	root := projectRoot(cwd)
	if root == "" {
		return entries
	}
	rootByCwd := map[string]string{}
	out := make([]DecisionEntry, 0, len(entries))
	for _, e := range entries {
		if e.Cwd == "" {
			out = append(out, e)
			continue
		}
		r, ok := rootByCwd[e.Cwd]
		if !ok {
			r = projectRoot(e.Cwd)
			rootByCwd[e.Cwd] = r
		}
		if r == root {
			out = append(out, e)
		}
	}
	return out
}

func collectLearningCandidates(cwd string, entries []DecisionEntry, existingRules []Rule) []learningCandidate {
	root := projectRoot(cwd)
	type tally struct {
		asks, allows, denies int
		sessionApproved      bool
	}
	byCommand := map[string]*tally{}
	var order []string
	rootByCwd := map[string]string{}
	for _, e := range entries {
		if e.BypassSandbox || e.Cwd == "" {
			continue
		}
		if root != "" {
			r, ok := rootByCwd[e.Cwd]
			if !ok {
				r = projectRoot(e.Cwd)
				rootByCwd[e.Cwd] = r
			}
			if r != root {
				continue
			}
		}
		t, ok := byCommand[e.Command]
		if !ok {
			t = &tally{}
			byCommand[e.Command] = t
			order = append(order, e.Command)
		}
		switch {
		case e.Layer == "human" && e.Decision == "allow":
			t.allows++
			if e.Source == "ask_approved" {
				t.sessionApproved = true
			}
		case e.Layer == "human" && e.Decision == "deny":
			t.denies++
			t.sessionApproved = false
		case e.Layer == "human":
		case e.Decision == "ask" || e.OrigDecision == "ask":
			t.asks++
		}
	}
	var out []learningCandidate
	for _, c := range order {
		t := byCommand[c]
		if t.asks >= 2 && t.allows >= 2 && t.denies == 0 && !t.sessionApproved && MatchRuleWith(c, existingRules, nil) == nil {
			out = append(out, learningCandidate{Command: c, Asks: t.asks, Allows: t.allows})
		}
	}
	return out
}

// printLearningCandidates lists commands this project keeps asking about
// and the human keeps allowing (e.g. via allow-once), so `yolonot suggest`
// can surface exact session/rule candidates alongside aggregated patterns.
func printLearningCandidates(cwd string, entries []DecisionEntry) {
	printLearningCandidateList(collectLearningCandidates(cwd, entries, LoadRules(cwd)))
}

func printLearningCandidateList(candidates []learningCandidate) {
	if len(candidates) == 0 {
		return
	}
	fmt.Printf("\nAsked at least twice and allowed each time:\n\n")
	for _, c := range candidates {
		fmt.Printf("  %dx asked, %dx allowed:  yolonot approve %s\n", c.Asks, c.Allows, strconv.Quote(c.Command))
	}
}
