package yolonot

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The redacted shape of a real v0.23 config: provider + decision +
// classifier hints + pre_check + custom profile + escalation.
const goldenV0 = `{
  "provider": {"name": "OpenRouter", "url": "https://openrouter.ai/api/v1/chat/completions", "model": "google/gemini-2.5-flash-lite", "env_key": "OPENROUTER_API_KEY", "timeout": 30},
  "classifier": {"context": ["$defaults"], "allow_hints": ["$defaults", "plugin cache scripts are trusted"], "ask_hints": ["$defaults"]},
  "decision": {"name": "OpenRouter", "url": "https://openrouter.ai/api/v1/systemone", "model": "typesafe/jev-1.13", "env_key": "OPENROUTER_API_KEY", "timeout": 10},
  "pre_check": ["fast-allow", "/home/u/.yolonot/bin/yolonot-bert"],
  "attach_outside_root": true,
  "profile": "yolomsu",
  "custom_profiles": {"yolomsu": {"critical": "deny", "high": "allow", "low": "allow", "moderate": "allow", "safe": "allow"}},
  "profile_override": {"codex": "strict"},
  "risk_maps": {"codex": {"high": "deny"}},
  "escalation": {"provider": {"name": "OpenRouter", "url": "https://openrouter.ai/api/v1/chat/completions", "model": "deepseek/deepseek-v4-flash", "env_key": "OPENROUTER_API_KEY", "timeout": 30}, "unresolved": "deny"}
}`

func TestGoldenV0FoldsAndRoundTrips(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	if err := os.WriteFile(configPath(), []byte(goldenV0), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := LoadConfig()
	if !cfg.Legacy {
		t.Fatal("v0 file must be flagged Legacy")
	}
	if got := judgeNames(cfg.Judges); got != "fast_allow → exec:/home/u/.yolonot/bin/yolonot-bert → jev-1.13 → gemini-2.5-flash-lite" {
		t.Fatalf("judges: %q", got)
	}
	if cfg.kindOf(cfg.Judges[2]) != judgeTyped || cfg.kindOf(cfg.Judges[3]) != judgeChat {
		t.Fatalf("kinds: %+v", cfg.Models)
	}
	if cfg.Escalation == nil || cfg.Escalation.Model != "deepseek-v4-flash" || cfg.Escalation.Unresolved != "deny" {
		t.Fatalf("escalation: %+v", cfg.Escalation)
	}
	if len(cfg.Prompt.AllowHints) != 2 || cfg.Policy.Profile != "yolomsu" || cfg.Policy.Profiles["yolomsu"]["critical"] != "deny" {
		t.Fatalf("prompt/policy: %+v / %+v", cfg.Prompt, cfg.Policy)
	}
	if hp := cfg.harnessPolicy("codex"); hp.Profile != "strict" || hp.RiskMap["high"] != "deny" {
		t.Fatalf("harness policy: %+v", hp)
	}
	if !cfg.AttachOutsideRoot {
		t.Fatal("attach_outside_root lost")
	}
	// Loading never writes.
	if data, _ := os.ReadFile(configPath()); string(data) != goldenV0 {
		t.Fatal("LoadConfig rewrote the file")
	}

	SaveConfig(cfg)
	written, _ := os.ReadFile(configPath())
	for _, bad := range []string{`"provider"`, `"decision"`, `"classifier"`, `"pre_check"`, `"custom_profiles"`, `"profile_override"`, `"risk_maps"`, `"local_allow"`} {
		if strings.Contains(string(written), bad) {
			t.Errorf("v0 key %s written: %s", bad, written)
		}
	}
	if !strings.Contains(string(written), `"config_version": 1`) {
		t.Errorf("config_version missing: %s", written)
	}
	again := LoadConfig()
	if again.Legacy {
		t.Fatal("v1 file flagged Legacy")
	}
	SaveConfig(again)
	second, _ := os.ReadFile(configPath())
	if string(second) != string(written) {
		t.Fatalf("second save differs:\n%s\n---\n%s", written, second)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(written, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["models"]; !ok {
		t.Fatal("models block missing")
	}
}

func TestSaveConfigDoesNotScrubCallerModelsMap(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	cfg := Config{Models: map[string]ModelConfig{"m": {URL: "https://x/v1/chat/completions", Model: "m", APIKey: "secret"}}, Judges: JudgeList{{Use: "m"}}}
	SaveConfig(cfg)
	if cfg.Models["m"].APIKey != "secret" {
		t.Fatal("SaveConfig must scrub a copy, not the caller's map")
	}
	if data, _ := os.ReadFile(configPath()); strings.Contains(string(data), "secret") {
		t.Fatal("api key written to disk")
	}
}

func TestValidModelName(t *testing.T) {
	for _, ok := range []string{"jev", "gemini-2.5-flash-lite", "gemma4:e4b", "x_1"} {
		if err := ValidModelName(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"fast_allow", "llm", "Jev", "a b", "", "-x"} {
		if ValidModelName(bad) == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestPutModelOnFreshConfig(t *testing.T) {
	var cfg Config
	cfg.putModel("m", ModelConfig{URL: "https://x/v1/chat/completions", Model: "m"})
	if cfg.Models["m"].Model != "m" || cfg.kindOf(JudgeSpec{Use: "m"}) != judgeChat {
		t.Fatalf("got %+v", cfg.Models)
	}
}

func TestModelKey(t *testing.T) {
	or := "https://openrouter.ai/api/v1/chat/completions"
	cases := []struct{ url, model, want string }{
		{or, "google/gemini-2.5-flash-lite", "gemini-2.5-flash-lite"},
		{or, "apodex/apodex-1.1-mini:free", "apodex-1.1-mini"},
		{or, "typesafe/jev-1.13", "jev-1.13"},
		{"http://localhost:11434/v1/chat/completions", "gemma4:e4b", "gemma4:e4b"},
		{"https://api.typesafe.ai/v1/systemone", "jev-latest", "jev-latest"},
		{"claude-cli", "claude-haiku-5-5", "claude-haiku-5-5"},
		{or, "x/llm", "model"},
	}
	for _, c := range cases {
		if got := modelKey(ModelConfig{URL: c.url, Model: c.model}); got != c.want {
			t.Errorf("%s @ %s: got %q want %q", c.model, c.url, got, c.want)
		}
	}
}
