package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateEscalationEnv blanks every env var the escalation resolvers read
// so host-machine settings can't leak into assertions.
func isolateEscalationEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LLM_URL", "LLM_MODEL", "LLM_TIMEOUT",
		"LLM_ESCALATION_URL", "LLM_ESCALATION_MODEL", "LLM_ESCALATION_TIMEOUT",
		"YOLONOT_ESCALATION", "YOLONOT_ESCALATION_UNRESOLVED",
	} {
		t.Setenv(k, "")
	}
}

// A config without an escalation block must round-trip through
// LoadConfig+SaveConfig with no "escalation" key appearing — upgrading
// yolonot must not rewrite existing users' configs.
func TestEscalationAbsentBlockRoundTrip(t *testing.T) {
	isolateEscalationEnv(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	dir := filepath.Join(tmp, ".yolonot")
	os.MkdirAll(dir, 0700)
	original := `{
  "provider": {
    "name": "Ollama",
    "url": "http://localhost:11434/v1/chat/completions",
    "model": "small-model",
    "timeout": 10
  },
  "classifier": "llm"
}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	c := LoadConfig()
	if c.Escalation != nil {
		t.Fatalf("absent escalation block should load as nil, got %+v", c.Escalation)
	}
	SaveConfig(c)

	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "escalation") {
		t.Errorf("saved config must not grow an escalation key:\n%s", data)
	}
}

// Disabled=false and Unresolved="" must vanish from disk (omitempty), so
// `escalation on` leaves the minimal block {"provider":{...}}.
func TestEscalationConfigMarshalShape(t *testing.T) {
	b, err := json.Marshal(EscalationConfig{Provider: ProviderConfig{Model: "big-model"}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "disabled") || strings.Contains(s, "unresolved") {
		t.Errorf("zero-value fields should be omitted, got %s", s)
	}

	b, _ = json.Marshal(EscalationConfig{Disabled: true, Unresolved: "deny", Provider: ProviderConfig{Model: "big-model"}})
	s = string(b)
	if !strings.Contains(s, `"disabled":true`) || !strings.Contains(s, `"unresolved":"deny"`) {
		t.Errorf("set fields should marshal, got %s", s)
	}
}

// SaveConfig must scrub the escalation API key from disk WITHOUT erasing
// the caller's in-memory copy — Escalation is a pointer, and setup uses the
// key for its connection test right after saving.
func TestSaveConfigScrubsEscalationKeyViaCopy(t *testing.T) {
	isolateEscalationEnv(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	cfg := Config{
		Provider: ProviderConfig{URL: "http://localhost/v1", Model: "small-model"},
		Escalation: &EscalationConfig{
			Provider: ProviderConfig{URL: "https://api.example.com/v1", Model: "big-model", APIKey: "sk-test-escalation"},
		},
	}
	SaveConfig(cfg)

	if cfg.Escalation.Provider.APIKey != "sk-test-escalation" {
		t.Errorf("caller's in-memory escalation key was erased by SaveConfig")
	}
	data, err := os.ReadFile(filepath.Join(tmp, ".yolonot", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sk-test-escalation") {
		t.Errorf("escalation API key persisted to disk:\n%s", data)
	}
}

// Inheritance: model-only escalation runs on the primary endpoint with the
// primary's credentials and timeout; an explicit URL inherits nothing.
func TestGetEscalationConfigInheritance(t *testing.T) {
	isolateEscalationEnv(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("PRIMARY_KEY_ENV", "primary-secret")

	write := func(c Config) {
		SaveConfig(c)
	}

	primary := ProviderConfig{URL: "https://api.example.com/v1/chat/completions", Model: "small-model", EnvKey: "PRIMARY_KEY_ENV", Timeout: 12}

	// Case 1: model-only → inherit URL, credential, timeout.
	write(Config{Provider: primary, Escalation: &EscalationConfig{Provider: ProviderConfig{Model: "big-model"}}})
	esc := GetEscalationConfig()
	if esc.URL != primary.URL {
		t.Errorf("model-only should inherit primary URL, got %q", esc.URL)
	}
	if esc.Model != "big-model" {
		t.Errorf("model should be the escalation model, got %q", esc.Model)
	}
	if esc.APIKey != "primary-secret" {
		t.Errorf("model-only should inherit primary credential, got %q", esc.APIKey)
	}
	if esc.Timeout != 12 {
		t.Errorf("model-only should inherit primary timeout, got %d", esc.Timeout)
	}
	if esc.TimeoutEnvKey != "LLM_ESCALATION_TIMEOUT" {
		t.Errorf("escalation config must carry its own timeout env key, got %q", esc.TimeoutEnvKey)
	}

	// Case 2: explicit URL → inherit NOTHING; primary credential must not
	// leak to the different endpoint.
	write(Config{Provider: primary, Escalation: &EscalationConfig{Provider: ProviderConfig{URL: "https://other.example.org/v1", Model: "big-model"}}})
	esc = GetEscalationConfig()
	if esc.URL != "https://other.example.org/v1" {
		t.Errorf("explicit URL should win, got %q", esc.URL)
	}
	if esc.APIKey != "" {
		t.Errorf("primary credential must not be inherited across endpoints, got %q", esc.APIKey)
	}
	if esc.Timeout != 0 {
		t.Errorf("explicit URL should not inherit timeout, got %d", esc.Timeout)
	}

	// Case 3: escalation with its own EnvKey keeps its own credential even
	// when inheriting the primary URL.
	t.Setenv("ESC_KEY_ENV", "esc-secret")
	write(Config{Provider: primary, Escalation: &EscalationConfig{Provider: ProviderConfig{Model: "big-model", EnvKey: "ESC_KEY_ENV"}}})
	esc = GetEscalationConfig()
	if esc.APIKey != "esc-secret" {
		t.Errorf("own EnvKey should win over inherited credential, got %q", esc.APIKey)
	}
}

// Env-only setups (no escalation block in config.json) must resolve and
// enable, mirroring the primary's LLM_URL/LLM_MODEL semantics.
func TestEscalationEnvOnlyEnablement(t *testing.T) {
	isolateEscalationEnv(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	SaveConfig(Config{Provider: ProviderConfig{URL: "http://localhost/v1", Model: "small-model"}})

	t.Setenv("LLM_ESCALATION_URL", "https://api.example.com/v1")
	t.Setenv("LLM_ESCALATION_MODEL", "big-model")

	cfg := LoadConfig()
	esc := GetEscalationConfig()
	if esc.URL != "https://api.example.com/v1" || esc.Model != "big-model" {
		t.Fatalf("env-only resolution failed: %+v", esc)
	}
	if !EscalationEnabled(cfg, esc) {
		t.Errorf("env-only escalation should be enabled")
	}

	// Model-only env + configured primary inherits the primary endpoint.
	t.Setenv("LLM_ESCALATION_URL", "")
	esc = GetEscalationConfig()
	if esc.URL != "http://localhost/v1" {
		t.Errorf("model-only env should inherit primary URL, got %q", esc.URL)
	}
}

// The kill switches: YOLONOT_ESCALATION=off and config disabled:true both
// gate the feature off; missing URL/model gates it off implicitly.
func TestEscalationEnabledGates(t *testing.T) {
	isolateEscalationEnv(t)

	esc := LLMConfig{URL: "https://api.example.com/v1", Model: "big-model"}

	if !EscalationEnabled(Config{}, esc) {
		t.Errorf("resolvable provider with no config block should be enabled")
	}
	if EscalationEnabled(Config{}, LLMConfig{URL: "https://api.example.com/v1"}) {
		t.Errorf("missing model should disable")
	}
	if EscalationEnabled(Config{}, LLMConfig{Model: "big-model"}) {
		t.Errorf("missing URL should disable")
	}
	if EscalationEnabled(Config{Escalation: &EscalationConfig{Disabled: true}}, esc) {
		t.Errorf("disabled:true should gate off")
	}

	t.Setenv("YOLONOT_ESCALATION", "off")
	if EscalationEnabled(Config{}, esc) {
		t.Errorf("YOLONOT_ESCALATION=off should gate off")
	}
}

// Unresolved policy: env wins over config; only "deny" (case-insensitive)
// switches the policy; everything else keeps ask.
func TestEscalationUnresolvedPolicy(t *testing.T) {
	isolateEscalationEnv(t)

	if got := EscalationUnresolved(Config{}); got != ActionAsk {
		t.Errorf("default should be ask, got %q", got)
	}
	cfg := Config{Escalation: &EscalationConfig{Unresolved: "deny"}}
	if got := EscalationUnresolved(cfg); got != ActionDeny {
		t.Errorf("config deny should apply, got %q", got)
	}
	if got := EscalationUnresolved(Config{Escalation: &EscalationConfig{Unresolved: "bogus"}}); got != ActionAsk {
		t.Errorf("unknown value should fall back to ask, got %q", got)
	}
	t.Setenv("YOLONOT_ESCALATION_UNRESOLVED", "DENY")
	if got := EscalationUnresolved(Config{}); got != ActionDeny {
		t.Errorf("env DENY should apply case-insensitively, got %q", got)
	}
	t.Setenv("YOLONOT_ESCALATION_UNRESOLVED", "ask")
	if got := EscalationUnresolved(cfg); got != ActionAsk {
		t.Errorf("env ask should override config deny, got %q", got)
	}
}
