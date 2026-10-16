package yolonot

import (
	"strings"
	"testing"
)

func TestReadLinesKeepsEntriesAfterLongLine(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	long := "cat <<EOF\n" + strings.Repeat("x", 80*1024) + "\nEOF"
	for _, l := range []string{"curl example.com", long, "rm -rf ./data"} {
		if err := AppendLine("s1", "denied", l); err != nil {
			t.Fatal(err)
		}
	}
	if got := ReadLines("s1", "denied"); len(got) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(got))
	}
	if !ContainsLine("s1", "denied", "rm -rf ./data") {
		t.Fatal("entry after a long line must still be found")
	}
}
