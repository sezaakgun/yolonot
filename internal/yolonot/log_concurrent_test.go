package yolonot

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
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
