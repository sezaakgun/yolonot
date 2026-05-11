package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withMockSuggestLLM(t *testing.T, response string, err error) {
	t.Helper()
	orig := suggestCallLLM
	suggestCallLLM = func(cfg LLMConfig, system, user string, maxTokens int) (string, error) {
		return response, err
	}
	t.Cleanup(func() { suggestCallLLM = orig })
}

// TestParseSmartSuggestionAcceptsValidJSON locks the happy path.
func TestParseSmartSuggestionAcceptsValidJSON(t *testing.T) {
	in := `{"action":"allow-hint","text":"kubectl get on staging-* is read-only","reason":"varied namespaces but always get"}`
	s, ok := parseSmartSuggestion(in)
	if !ok {
		t.Fatal("expected valid JSON to parse")
	}
	if s.Action != "allow-hint" {
		t.Errorf("Action: got %q, want allow-hint", s.Action)
	}
	if !strings.Contains(s.Text, "staging-*") {
		t.Errorf("Text missing expected content: %q", s.Text)
	}
}

// TestParseSmartSuggestionStripsCodeFence covers models that wrap their
// JSON in ```json fences.
func TestParseSmartSuggestionStripsCodeFence(t *testing.T) {
	in := "```json\n{\"action\":\"ask-cmd\",\"text\":\"*git push --force*\",\"reason\":\"\"}\n```"
	s, ok := parseSmartSuggestion(in)
	if !ok {
		t.Fatal("expected fenced JSON to parse")
	}
	if s.Action != "ask-cmd" {
		t.Errorf("Action: got %q, want ask-cmd", s.Action)
	}
}

// TestParseSmartSuggestionToleratesPreamble covers models that add
// prose before the JSON.
func TestParseSmartSuggestionToleratesPreamble(t *testing.T) {
	in := `Here is my recommendation:
{"action":"deny-cmd","text":"*rm -rf /*","reason":"never"}`
	s, ok := parseSmartSuggestion(in)
	if !ok {
		t.Fatal("expected JSON-with-preamble to parse")
	}
	if s.Action != "deny-cmd" {
		t.Errorf("Action: got %q, want deny-cmd", s.Action)
	}
}

// TestParseSmartSuggestionRejectsInvalidAction guards against the
// model inventing a new action name. Unknown action → caller falls
// back to manual TUI rather than the cache poisoning with garbage.
func TestParseSmartSuggestionRejectsInvalidAction(t *testing.T) {
	in := `{"action":"frobnicate","text":"x","reason":"y"}`
	if _, ok := parseSmartSuggestion(in); ok {
		t.Error("expected unknown action to be rejected")
	}
}

// TestParseSmartSuggestionRejectsNonJSON returns ok=false so caller
// doesn't try to apply a free-text response as a rule.
func TestParseSmartSuggestionRejectsNonJSON(t *testing.T) {
	if _, ok := parseSmartSuggestion("looks risky to me"); ok {
		t.Error("expected non-JSON to be rejected")
	}
	if _, ok := parseSmartSuggestion(""); ok {
		t.Error("expected empty string to be rejected")
	}
}

// TestSmartActionToRule covers the mapping from a SmartSuggestion back
// to the literal text appended to a rule file. Verifies hint actions
// quote their prose and cmd actions don't.
func TestSmartActionToRule(t *testing.T) {
	cases := []struct {
		s    SmartSuggestion
		want string
	}{
		{SmartSuggestion{Action: "allow-hint", Text: "x is fine"}, `allow-hint "x is fine"`},
		{SmartSuggestion{Action: "ask-hint", Text: "y mutates"}, `ask-hint "y mutates"`},
		{SmartSuggestion{Action: "allow-cmd", Text: "kubectl get *"}, "allow-cmd kubectl get *"},
		{SmartSuggestion{Action: "deny-cmd", Text: "*rm -rf /*"}, "deny-cmd *rm -rf /*"},
		{SmartSuggestion{Action: "ask-cmd", Text: "*git push*"}, "ask-cmd *git push*"},
		{SmartSuggestion{Action: "skip", Text: ""}, ""},
		{SmartSuggestion{Action: "allow-hint", Text: ""}, ""}, // empty text drops
		{SmartSuggestion{Action: "unknown", Text: "x"}, ""},   // unknown action drops
	}
	for _, tc := range cases {
		got := smartActionToRule(tc.s)
		if got != tc.want {
			t.Errorf("smartActionToRule(%+v) = %q, want %q", tc.s, got, tc.want)
		}
	}
}

// TestSuggestCacheRoundtrip exercises load + save + re-load. Critical
// because a corrupted cache file would silently regress smart-suggest
// to "always re-call LLM" — annoying not catastrophic, but worth a
// regression guard.
func TestSuggestCacheRoundtrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".yolonot"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	c := suggestCache{Patterns: map[string]cachedSuggestion{
		"kubectl get pods": {
			Action: "allow-hint",
			Text:   "test prose",
			Reason: "varied namespaces",
			TS:     time.Now().UTC().Format(time.RFC3339),
		},
	}}
	saveSuggestCache(c)

	got := loadSuggestCache()
	if got.Patterns == nil {
		t.Fatal("loaded patterns map is nil")
	}
	entry, ok := got.Patterns["kubectl get pods"]
	if !ok {
		t.Fatal("entry missing after round-trip")
	}
	if entry.Action != "allow-hint" || entry.Text != "test prose" {
		t.Errorf("entry corrupted: %+v", entry)
	}
}

// TestSuggestCacheLoadMissingFile returns an empty (but non-nil) map.
// Caller iterates over it without a nil check.
func TestSuggestCacheLoadMissingFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	c := loadSuggestCache()
	if c.Patterns == nil {
		t.Fatal("empty cache must initialize Patterns map")
	}
	if len(c.Patterns) != 0 {
		t.Errorf("missing-file cache should be empty; got %d entries", len(c.Patterns))
	}
}

// TestIsCacheFreshTTL covers the 30-day cutoff. Older entries must be
// re-fetched; new ones reused. Anchored on a fixed time so the test
// stays deterministic.
func TestIsCacheFreshTTL(t *testing.T) {
	now := time.Now().UTC()
	if !isCacheFresh(now.Format(time.RFC3339)) {
		t.Error("just-now entry should be fresh")
	}
	if !isCacheFresh(now.Add(-15 * 24 * time.Hour).Format(time.RFC3339)) {
		t.Error("15-day-old entry should be fresh")
	}
	if isCacheFresh(now.Add(-31 * 24 * time.Hour).Format(time.RFC3339)) {
		t.Error("31-day-old entry should be stale")
	}
	if isCacheFresh("") {
		t.Error("empty TS should not be fresh")
	}
	if isCacheFresh("not a timestamp") {
		t.Error("malformed TS should not be fresh")
	}
}

// TestSuggestSmartFailsClosedWithoutProvider returns ok=false when no
// provider is configured, so the user falls back to manual TUI rather
// than a panic.
func TestSuggestSmartFailsClosedWithoutProvider(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	// No config.json -> empty LLM config
	_, ok := suggestSmart(evolveFinding{Pattern: "kubectl get pods"})
	if ok {
		t.Error("smart-suggest should fail closed without provider")
	}
}

// TestCachedOrSmartReusesFreshEntry confirms a fresh cached entry
// short-circuits the LLM call. We swap suggestCallLLM with a panic
// to prove it never runs.
func TestCachedOrSmartReusesFreshEntry(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".yolonot"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	c := suggestCache{Patterns: map[string]cachedSuggestion{
		"kubectl get pods": {
			Action: "allow-hint",
			Text:   "cached prose",
			Reason: "from cache",
			TS:     time.Now().UTC().Format(time.RFC3339),
		},
	}}

	orig := suggestCallLLM
	suggestCallLLM = func(cfg LLMConfig, system, user string, maxTokens int) (string, error) {
		t.Fatal("LLM call must not happen when cache hit is fresh")
		return "", nil
	}
	t.Cleanup(func() { suggestCallLLM = orig })

	s, ok := cachedOrSmart(evolveFinding{Pattern: "kubectl get pods"}, &c)
	if !ok {
		t.Fatal("expected ok=true on cache hit")
	}
	if s.Text != "cached prose" {
		t.Errorf("Text: got %q, want 'cached prose'", s.Text)
	}
}

// TestBuildSuggestUserPromptStructure confirms the meta-prompt
// includes pattern + occurrences + example bullets so the model has
// what it needs to make a sensible recommendation.
func TestBuildSuggestUserPromptStructure(t *testing.T) {
	f := evolveFinding{
		Pattern:  "kubectl get pods",
		Count:    42,
		Weighted: 25.5,
		Examples: []string{
			"kubectl get pods -n staging",
			"kubectl get pods -n dev",
		},
	}
	out := buildSuggestUserPrompt(f)
	for _, want := range []string{
		`"kubectl get pods"`,
		"Occurrences: 42",
		"25.5",
		"- kubectl get pods -n staging",
		"- kubectl get pods -n dev",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("user prompt missing %q\nfull:\n%s", want, out)
		}
	}
}

// TestSuggestSmartParsesLLMResponse is the end-to-end happy path:
// real LLM provider env, mocked transport, valid JSON response, and
// the SmartSuggestion lands intact.
func TestSuggestSmartParsesLLMResponse(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".yolonot"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg := Config{
		Provider: ProviderConfig{URL: "http://localhost", Model: "x"},
	}
	SaveConfig(cfg)

	withMockSuggestLLM(t,
		`{"action":"allow-hint","text":"kubectl get is read-only","reason":"clean"}`,
		nil,
	)

	s, ok := suggestSmart(evolveFinding{Pattern: "kubectl get", Examples: []string{"kubectl get pods"}})
	if !ok {
		t.Fatal("expected ok=true on valid LLM response")
	}
	if s.Action != "allow-hint" {
		t.Errorf("Action: got %q, want allow-hint", s.Action)
	}
}

// TestSuggestSmartHandlesLLMError returns ok=false so caller falls
// back to manual TUI. Transport failures shouldn't crash suggest.
func TestSuggestSmartHandlesLLMError(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".yolonot"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg := Config{
		Provider: ProviderConfig{URL: "http://localhost", Model: "x"},
	}
	SaveConfig(cfg)

	withMockSuggestLLM(t, "", fmt.Errorf("simulated 503"))

	_, ok := suggestSmart(evolveFinding{Pattern: "x"})
	if ok {
		t.Error("expected ok=false on transport error")
	}
}

// TestTruncateForDisplay covers the TUI label-shortening helper.
func TestTruncateForDisplay(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 100, "short"},
		{"exactlyten", 10, "exactlyten"},
		{"abcdefghij", 7, "abcd..."},
		{"x", 0, ""},
	}
	for _, tc := range cases {
		got := truncateForDisplay(tc.in, tc.max)
		if got != tc.want {
			t.Errorf("truncateForDisplay(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}

// TestSuggestCacheMissingPatternsField handles legacy/corrupted cache
// files that lack the "patterns" key. loadSuggestCache must initialize
// the map rather than returning nil — without it cmdEvolve would
// panic on the first cache write.
func TestSuggestCacheMissingPatternsField(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".yolonot"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Cache file with no "patterns" field
	if err := os.WriteFile(filepath.Join(tmp, ".yolonot", "suggest-cache.json"),
		[]byte(`{}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := loadSuggestCache()
	if c.Patterns == nil {
		t.Error("Patterns must initialize even when JSON is empty object")
	}
}

// TestSuggestCacheRoundtripJSONShape locks the on-disk format so a
// later refactor doesn't silently change the schema and invalidate
// every existing user's cache.
func TestSuggestCacheRoundtripJSONShape(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".yolonot"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	c := suggestCache{Patterns: map[string]cachedSuggestion{
		"x": {Action: "allow-hint", Text: "y", Reason: "z", TS: "2026-01-01T00:00:00Z"},
	}}
	saveSuggestCache(c)
	data, err := os.ReadFile(filepath.Join(tmp, ".yolonot", "suggest-cache.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("file is not valid JSON: %v", err)
	}
	patterns, ok := parsed["patterns"].(map[string]any)
	if !ok {
		t.Fatal("top-level 'patterns' key missing or wrong type")
	}
	entry, ok := patterns["x"].(map[string]any)
	if !ok {
		t.Fatal("entry missing")
	}
	for _, k := range []string{"action", "text", "reason", "ts"} {
		if _, present := entry[k]; !present {
			t.Errorf("entry missing key %q", k)
		}
	}
}
