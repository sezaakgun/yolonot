package yolonot

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestUpdateCacheRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	writeUpdateCache("v1.2.3")
	cached, ok := readUpdateCache()
	if !ok {
		t.Fatal("cache should be fresh after write")
	}
	if cached.Version != "v1.2.3" {
		t.Errorf("Version = %q, want v1.2.3", cached.Version)
	}
}

func TestUpdateCacheExpiresAfterTTL(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Write a cache entry with a stale timestamp by bypassing writeUpdateCache.
	old := updateCheckCache{Version: "v0.0.1", CheckedAt: time.Now().Add(-2 * updateCheckTTL)}
	data, _ := json.Marshal(old)
	_ = os.MkdirAll(YolonotDir(), 0755)
	if err := os.WriteFile(updateCachePath(), data, 0644); err != nil {
		t.Fatal(err)
	}

	if _, ok := readUpdateCache(); ok {
		t.Fatal("stale cache entry should not count as fresh")
	}
}

func TestUpdateCacheMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if _, ok := readUpdateCache(); ok {
		t.Fatal("missing cache file should not count as fresh")
	}
}

func TestUpdateCacheCorruptIsMiss(t *testing.T) {
	// Corrupt cache file (e.g. partial write) must be treated as a miss
	// rather than crashing the status display.
	t.Setenv("HOME", t.TempDir())
	_ = os.MkdirAll(YolonotDir(), 0755)
	os.WriteFile(updateCachePath(), []byte("{not json"), 0644)
	if _, ok := readUpdateCache(); ok {
		t.Fatal("corrupt cache should not count as fresh")
	}
}

func TestCheckForUpdateReturnsEmptyForDev(t *testing.T) {
	// The dev-build short-circuit prevents a sandboxed unit-test binary
	// (where Version defaults to "dev") from talking to api.github.com.
	orig := Version
	Version = "dev"
	defer func() { Version = orig }()

	if got := checkForUpdate(); got != "" {
		t.Errorf("dev build should skip update check; got %q", got)
	}
}

func TestCheckForUpdateUsesCache(t *testing.T) {
	// Regression guard for the GitHub-API rate-limit fix (2026-04-21): a
	// fresh cache entry must satisfy checkForUpdate without hitting the
	// network. We verify this indirectly — set a cache with a newer version
	// than Version, get it back; set with an older version, get empty.
	t.Setenv("HOME", t.TempDir())
	orig := Version
	Version = "v0.10.0"
	defer func() { Version = orig }()

	writeUpdateCache("v99.0.0")
	if got := checkForUpdate(); got != "v99.0.0" {
		t.Errorf("cache hit should return newer version; got %q", got)
	}

	writeUpdateCache("v0.1.0")
	if got := checkForUpdate(); got != "" {
		t.Errorf("older cached version should return empty; got %q", got)
	}

	writeUpdateCache("v0.10.0")
	if got := checkForUpdate(); got != "" {
		t.Errorf("same-version cache should return empty; got %q", got)
	}
}

func TestCheckForUpdateCachesEmptyOnError(t *testing.T) {
	// When the network fails (or GitHub rate-limits us), we cache an empty
	// Version so subsequent calls inside the TTL window don't re-hammer
	// GitHub. This is the core rate-limit mitigation — without it, a user
	// running `yolonot` 60+ times/hr burns through the 60/hr unauthenticated
	// limit and sees the error banner on every invocation.
	t.Setenv("HOME", t.TempDir())
	orig := Version
	Version = "v0.10.0"
	defer func() { Version = orig }()

	// No real network call here — we only assert that after a failure
	// (simulated by pre-seeding an empty-Version cache), checkForUpdate
	// returns empty without clearing the cache.
	writeUpdateCache("")
	if got := checkForUpdate(); got != "" {
		t.Errorf("empty cache should return empty; got %q", got)
	}
	if _, fresh := readUpdateCache(); !fresh {
		t.Error("cache should still be fresh after a cached empty read — TTL governs backoff")
	}
}

func TestNewerThanCurrent(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	cases := []struct {
		version string
		latest  string
		want    string
	}{
		{"v0.10.0", "v0.11.0", "v0.11.0"},
		{"v0.10.0", "v0.10.0", ""},
		{"v0.11.0", "v0.10.0", ""},
		{"v0.11.0+dirty", "v0.12.0", "v0.12.0"},
		{"v0.10.0", "", ""},
	}
	for _, c := range cases {
		Version = c.version
		if got := newerThanCurrent(c.latest); got != c.want {
			t.Errorf("newerThanCurrent(%q) with Version=%q = %q, want %q", c.latest, c.version, got, c.want)
		}
	}
}
