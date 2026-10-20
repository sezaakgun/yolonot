package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProjectRootScoping(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".git"), 0755)
	sub := filepath.Join(root, "pkg")
	os.MkdirAll(sub, 0755)
	other := t.TempDir()

	if projectRoot(sub) != projectRoot(root) || projectRoot(other) == projectRoot(root) {
		t.Fatal("projectRoot must group subdirectories under the same git root and separate other dirs")
	}
}

func TestSuggestEnrichesFindingsWithHumanResolutionsAndCandidates(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	proj := t.TempDir()
	os.MkdirAll(filepath.Join(proj, ".git"), 0755)
	t.Chdir(proj)
	cwd, _ := os.Getwd()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	entries := []DecisionEntry{
		{Timestamp: now, SessionID: "s1", Command: "kubectl get pods -n staging", Cwd: cwd, Layer: "gemini", Decision: "ask"},
		{Timestamp: now, SessionID: "s1", Command: "kubectl get pods -n staging", Cwd: cwd, Layer: "human", Decision: "allow", Source: "allow_once"},
		{Timestamp: now, SessionID: "s1", Command: "kubectl get pods -n prod", Cwd: cwd, Layer: "gemini", Decision: "ask"},
		{Timestamp: now, SessionID: "s1", Command: "kubectl get pods -n prod", Cwd: cwd, Layer: "human", Decision: "allow", Source: "ask_approved"},
		{Timestamp: now, SessionID: "s1", Command: "kubectl get pods -n staging", Cwd: cwd, Layer: "gemini", Decision: "ask"},
		{Timestamp: now, SessionID: "s1", Command: "kubectl get pods -n staging", Cwd: cwd, Layer: "human", Decision: "allow", Source: "allow_once"},
	}
	writeTestDecisions(t, entries)

	listOut := captureStdout(func() { cmdEvolve([]string{"--list", "--basic"}) })
	for _, want := range []string{
		"REPEATED ASK",
		"kubectl get",
		"human: 1 approved, 2 once",
		"Asked at least twice and allowed each time:",
		`yolonot approve "kubectl get pods -n staging"`,
	} {
		if !strings.Contains(listOut, want) {
			t.Errorf("suggest --list missing %q:\n%s", want, listOut)
		}
	}

	jsonOut := captureStdout(func() { cmdEvolve([]string{"--json", "--basic"}) })
	var parsed struct {
		Analyzed   int                 `json:"analyzed"`
		Findings   []evolveFinding     `json:"findings"`
		Candidates []learningCandidate `json:"candidates"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &parsed); err != nil {
		t.Fatalf("invalid suggest --json output: %v\n%s", err, jsonOut)
	}
	if len(parsed.Findings) != 1 || parsed.Findings[0].Approved != 1 || parsed.Findings[0].Once != 2 {
		t.Fatalf("unexpected findings in JSON: %+v", parsed.Findings)
	}
	if len(parsed.Candidates) != 1 || parsed.Candidates[0].Command != "kubectl get pods -n staging" {
		t.Fatalf("unexpected candidates in JSON: %+v", parsed.Candidates)
	}

	// Entries from another project root must not pollute default project-scoped suggest,
	// but must be included when --all is passed.
	otherProj := t.TempDir()
	os.MkdirAll(filepath.Join(otherProj, ".git"), 0755)
	entries = append(entries,
		DecisionEntry{Timestamp: now, SessionID: "s2", Command: "terraform plan -out=tfplan", Cwd: otherProj, Layer: "gemini", Decision: "ask"},
		DecisionEntry{Timestamp: now, SessionID: "s2", Command: "terraform plan -out=tfplan", Cwd: otherProj, Layer: "gemini", Decision: "ask"},
		DecisionEntry{Timestamp: now, SessionID: "s2", Command: "terraform plan -out=tfplan", Cwd: otherProj, Layer: "gemini", Decision: "ask"},
	)
	writeTestDecisions(t, entries)

	scopedOut := captureStdout(func() { cmdEvolve([]string{"--list", "--basic"}) })
	if strings.Contains(scopedOut, "terraform plan") {
		t.Fatalf("default suggest --list should filter out other project roots:\n%s", scopedOut)
	}
	allOut := captureStdout(func() { cmdEvolve([]string{"--list", "--basic", "--all"}) })
	if !strings.Contains(allOut, "terraform plan") {
		t.Fatalf("suggest --list --all should include other project roots:\n%s", allOut)
	}
}
