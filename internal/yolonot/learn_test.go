package yolonot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordPrecedentKeepsOnlyRememberedHumanAnswers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cwd := t.TempDir()
	recordPrecedent(DecisionEntry{Layer: "human", Source: "ask_approved", Decision: "allow", Cwd: cwd, Command: "wget a"})
	recordPrecedent(DecisionEntry{Layer: "human", Source: "ask_rejected", Decision: "deny", Cwd: cwd, Command: "wget b"})
	recordPrecedent(DecisionEntry{Layer: "human", Source: "allow_once", Decision: "allow", Cwd: cwd, Command: "wget once"})
	recordPrecedent(DecisionEntry{Layer: "rule", Decision: "allow", Cwd: cwd, Command: "ls"})
	ps := loadPrecedents()
	if len(ps) != 2 || ps[0].Command != "wget a" || ps[1].Decision != "deny" {
		t.Fatalf("got %+v", ps)
	}
}

func TestProjectPrecedentsScopeAndLatestWins(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	sub := filepath.Join(root, "pkg")
	os.MkdirAll(sub, 0755)
	other := t.TempDir()
	recordPrecedent(DecisionEntry{Layer: "human", Source: "ask_rejected", Decision: "deny", Cwd: root, Command: "wget a"})
	recordPrecedent(DecisionEntry{Layer: "human", Source: "ask_approved", Decision: "allow", Cwd: sub, Command: "wget a"})
	recordPrecedent(DecisionEntry{Layer: "human", Source: "ask_approved", Decision: "allow", Cwd: other, Command: "wget elsewhere"})
	ps := projectPrecedents(root)
	if len(ps) != 1 || ps[0].Decision != "allow" {
		t.Fatalf("want the latest verdict for wget a only, got %+v", ps)
	}
}

func TestPrecedentsRankBySimilarity(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cwd := t.TempDir()
	recordPrecedent(DecisionEntry{Layer: "human", Source: "ask_approved", Decision: "allow", Cwd: cwd, Command: "wget -q https://example.com -O /tmp/a.html"})
	recordPrecedent(DecisionEntry{Layer: "human", Source: "ask_rejected", Decision: "deny", Cwd: cwd, Command: "wget -q https://evil.example -O /tmp/b.html"})
	recordPrecedent(DecisionEntry{Layer: "human", Source: "ask_approved", Decision: "allow", Cwd: cwd, Command: "ls -la"})
	allowed, rejected := Precedents("wget -q https://example.com -O /tmp/c.html", cwd)
	if len(allowed) != 1 || len(rejected) != 1 || strings.Contains(allowed[0], "ls") {
		t.Fatalf("allowed=%v rejected=%v", allowed, rejected)
	}
	var h WalkupHints
	addPrecedentHints(&h, "wget -q https://example.com -O /tmp/c.html", cwd)
	if len(h.AllowHints) != 1 || len(h.AskHints) != 1 || !strings.Contains(h.AskHints[0], "rejected") {
		t.Fatalf("hints %+v", h)
	}
	if cmdSimilarity("ls -la", "wget x") >= precedentMinScore {
		t.Fatal("unrelated commands must not score")
	}
}

func TestCmdLogHumanListsProjectAnswers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	os.Chdir(t.TempDir())
	cwd, _ := os.Getwd()
	recordPrecedent(DecisionEntry{Layer: "human", Source: "ask_approved", Decision: "allow", Cwd: cwd, Command: "wget -q https://example.com -O /tmp/a.html", Timestamp: "2026-10-13T10:00:00Z"})
	recordPrecedent(DecisionEntry{Layer: "human", Source: "ask_rejected", Decision: "deny", Cwd: t.TempDir(), Command: "wget elsewhere", Timestamp: "2026-10-13T10:00:00Z"})

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	cmdLogHuman()
	w.Close()
	os.Stdout = stdout
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	if !strings.Contains(out, "2026-10-13  allow wget -q https://example.com -O /tmp/a.html") || strings.Contains(out, "elsewhere") {
		t.Fatalf("output:\n%s", out)
	}
}
