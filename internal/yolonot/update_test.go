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
		{"1.0.0", "v1.0.0", ""},
		{"1.0.0", "v1.0.1", "v1.0.1"},
		{"v1.2.0", "v1.10.0", "v1.10.0"},
		{"v1.10.0", "v1.2.0", ""},
		{"v0.10.0", "", ""},
	}
	for _, c := range cases {
		Version = c.version
		if got := newerThanCurrent(c.latest); got != c.want {
			t.Errorf("newerThanCurrent(%q) with Version=%q = %q, want %q", c.latest, c.version, got, c.want)
		}
	}
}

func TestHealthChecksIsolatesOpencodeCapabilitiesAcrossHarnesses(t *testing.T) {
	_, _ = withFakeHome(t)
	binDir := t.TempDir()
	writeStub := func(name, ver string) {
		full := binDir + "/" + name
		if err := os.WriteFile(full, []byte("#!/bin/sh\necho '"+ver+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeStub("opencode", "2.1.0")
	writeStub("kilo", "1.4.0")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("YOLONOT_OPENCODE_API", "")

	targets := []Harness{GetHarness("opencode"), GetHarness("kilo")}
	checks := healthChecks(LoadConfig(), targets, false)

	gotAsk := map[string]string{}
	for _, c := range checks {
		if c.Name == "native_ask" {
			gotAsk[c.Harness] = c.Detail
		}
	}
	if got := gotAsk["opencode"]; len(got) < 4 || got[:4] != "true" {
		t.Fatalf("expected opencode 2.x native_ask true, got %q", got)
	}
	if got := gotAsk["kilo"]; len(got) < 5 || got[:5] != "false" {
		t.Fatalf("expected kilo 1.x native_ask false (no env leak from opencode), got %q", got)
	}
}

func TestApplyEvolveChangesProjectRootHeadersAndSymlinkRejection(t *testing.T) {
	home, _ := withFakeHome(t)
	repo := t.TempDir()
	if err := os.MkdirAll(repo+"/.git", 0o755); err != nil {
		t.Fatal(err)
	}
	sub := repo + "/pkg/sub"
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// Seed global rules WITHOUT a trailing newline to ensure we never glue onto the last line.
	if err := os.MkdirAll(home+"/.yolonot", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(home+"/.yolonot/rules", []byte("allow-cmd echo ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	applyEvolveChanges(sub, []evolveChange{
		{Rule: "allow-cmd go test*", Scope: "p"},
		{Rule: "allow-cmd npm test*", Scope: "p"},
		{Rule: "deny-cmd *rm -rf /*", Scope: "g"},
	}, "2026-11-11")

	if _, err := os.Stat(sub + "/.yolonot"); !os.IsNotExist(err) {
		t.Fatalf("expected no .yolonot in subdirectory %s", sub)
	}
	projBytes, err := os.ReadFile(repo + "/.yolonot")
	if err != nil {
		t.Fatalf("expected repo root .yolonot: %v", err)
	}
	wantProj := "# Suggested by yolonot (2026-11-11)\nallow-cmd go test*\nallow-cmd npm test*\n"
	if string(projBytes) != wantProj {
		t.Fatalf("project .yolonot = %q, want %q", string(projBytes), wantProj)
	}

	globBytes, err := os.ReadFile(home + "/.yolonot/rules")
	if err != nil {
		t.Fatal(err)
	}
	wantGlob := "allow-cmd echo ok\n\n# Suggested by yolonot (2026-11-11)\ndeny-cmd *rm -rf /*\n"
	if string(globBytes) != wantGlob {
		t.Fatalf("global rules = %q, want %q", string(globBytes), wantGlob)
	}

	// Replace repo/.yolonot with a symlink and verify applyEvolveChanges refuses to follow it.
	victim := t.TempDir() + "/victim.txt"
	if err := os.WriteFile(victim, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(repo + "/.yolonot")
	if err := os.Symlink(victim, repo+"/.yolonot"); err != nil {
		t.Fatal(err)
	}
	applyEvolveChanges(sub, []evolveChange{{Rule: "allow-cmd ls*", Scope: "p"}}, "2026-11-11")
	victimBytes, _ := os.ReadFile(victim)
	if string(victimBytes) != "untouched\n" {
		t.Fatalf("symlink target was modified: %q", string(victimBytes))
	}
}

func TestRefreshSkillsWithBinaryUsesUpgradedExecutable(t *testing.T) {
	_, _ = withFakeHome(t)
	h := GetHarness("claude")
	if err := h.Install("/tmp/fake-yolonot"); err != nil {
		t.Fatal(err)
	}
	skillDir, err := h.InstallSkill()
	if err != nil {
		t.Fatal(err)
	}
	skillPath := skillDir + "/SKILL.md"
	fakeBin := t.TempDir() + "/yolonot-new"
	script := "#!/bin/sh\nif [ \"$1\" = \"install\" ] && [ \"$2\" = \"--skill-only\" ] && [ \"$3\" = \"--harness\" ] && [ \"$4\" = \"claude\" ]; then\n  mkdir -p \"" + skillDir + "\"\n  printf 'UPGRADED-SKILL\\n' > \"" + skillPath + "\"\n  printf 'Skill bundle refreshed.\\n  claude → %s\\n' \"" + skillDir + "\"\n  exit 0\nfi\nexit 1\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	refreshed := refreshSkillsWithBinary(fakeBin)
	if len(refreshed) != 1 {
		t.Fatalf("expected 1 refreshed skill, got %v", refreshed)
	}
	got, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "UPGRADED-SKILL\n" {
		t.Fatalf("skill content = %q, want UPGRADED-SKILL", string(got))
	}
}
