package yolonot

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Concurrent hooks append to the same file; every line must stay one record.
func TestLogDecisionConcurrentLinesStayWhole(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			LogDecision(DecisionEntry{Command: "echo " + string(make([]byte, 2000)), Decision: "allow", Layer: "fast_allow"})
		}()
	}
	wg.Wait()
	f, err := os.Open(filepath.Join(YolonotDir(), "decisions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		var e DecisionEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %d is not one record: %v", n, err)
		}
	}
	if n != 40 {
		t.Fatalf("want 40 lines, got %d", n)
	}
}

func TestLogDecisionRotationTailReadAndSymlinkGuard(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	origMax := maxDecisionLogBytes
	defer func() { maxDecisionLogBytes = origMax }()

	// 1. Rotation when decisions.jsonl exceeds maxDecisionLogBytes (rotates once after ~4 entries).
	maxDecisionLogBytes = 500
	for i := 0; i < 6; i++ {
		LogDecision(DecisionEntry{
			Command:  "echo entry-" + string(rune('A'+i)),
			Decision: "allow",
			Layer:    "fast_allow",
		})
	}
	if _, err := os.Stat(decisionsPath() + ".1"); err != nil {
		t.Fatalf("expected rotated decisions.jsonl.1 to exist: %v", err)
	}
	recentAll := ReadRecentDecisions(6)
	if len(recentAll) != 6 || recentAll[0].Command != "echo entry-A" || recentAll[5].Command != "echo entry-F" {
		t.Fatalf("expected ReadRecentDecisions(6) to span rotated + active files, got %d: %+v", len(recentAll), recentAll)
	}
	out := captureStdout(func() { cmdLog(2) })
	if !strings.Contains(out, "Total: 6 decisions logged.") {
		t.Fatalf("expected cmdLog total across .1 and active log to be 6, got:\n%s", out)
	}

	// 1b. Rotation refuses to clobber a symlinked decisions.jsonl.1 backup.
	backupTarget := filepath.Join(t.TempDir(), "backup-victim.jsonl")
	if err := os.WriteFile(backupTarget, []byte("keep-me\n"), 0600); err != nil {
		t.Fatal(err)
	}
	os.Remove(decisionsPath() + ".1")
	if err := os.Symlink(backupTarget, decisionsPath()+".1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		LogDecision(DecisionEntry{Command: "echo rotate-guard", Decision: "allow", Layer: "fast_allow"})
	}
	if gotBackup, _ := os.ReadFile(backupTarget); string(gotBackup) != "keep-me\n" {
		t.Fatalf("rotation overwrote symlinked decisions.jsonl.1 target: %q", string(gotBackup))
	}
	os.Remove(decisionsPath() + ".1")

	// 2. Fast tail-read path on a >256 KB decisions.jsonl file.
	maxDecisionLogBytes = 16 << 20
	os.Remove(decisionsPath())
	pad := string(make([]byte, 600)) // marshals \u0000 to ~3600 bytes per entry
	for i := 0; i < 100; i++ {
		LogDecision(DecisionEntry{
			Command:  "cmd-" + pad,
			Decision: "allow",
			Layer:    "fast_allow",
			Source:   string(rune('0' + (i % 10))),
		})
	}
	tailEntries := ReadRecentDecisions(5)
	if len(tailEntries) != 5 || tailEntries[4].Source != "9" {
		t.Fatalf("unexpected tail entries from >256KB log: len=%d, last=%+v", len(tailEntries), tailEntries)
	}

	// 3. Symlink refusal on decisions.jsonl (including >256KB tail-read path and LogDecision write path).
	bigTarget := filepath.Join(t.TempDir(), "big-victim.jsonl")
	if err := os.Rename(decisionsPath(), bigTarget); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bigTarget, decisionsPath()); err != nil {
		t.Fatal(err)
	}
	if entries := ReadRecentDecisions(5); len(entries) != 0 {
		t.Fatalf("expected ReadRecentDecisions(5) tail path to refuse >256KB symlink, got %d entries", len(entries))
	}

	os.Remove(decisionsPath())
	target := filepath.Join(t.TempDir(), "victim.jsonl")
	if err := os.WriteFile(target, []byte("initial\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, decisionsPath()); err != nil {
		t.Fatal(err)
	}
	LogDecision(DecisionEntry{Command: "echo pwn", Decision: "allow", Layer: "fast_allow"})
	got, _ := os.ReadFile(target)
	if string(got) != "initial\n" {
		t.Fatalf("LogDecision wrote through a symlink: %q", string(got))
	}
}
