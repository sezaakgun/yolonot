package yolonot

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCatalogDeduplicatesOnlyEquivalentCallSettings(t *testing.T) {
	base := ModelConfig{Name: "Primary", URL: "https://chat.invalid", Model: "same-model", Timeout: 30, EnvKey: "PRIMARY_KEY", APIKey: "primary-test-key"}
	for _, tc := range []struct {
		name   string
		change func(*ModelConfig)
		same   bool
	}{
		{"identical", func(*ModelConfig) {}, true},
		{"display name only", func(m *ModelConfig) { m.Name = "Escalation" }, true},
		{"timeout", func(m *ModelConfig) { m.Timeout = 2 }, false},
		{"environment key", func(m *ModelConfig) { m.EnvKey = "ESCALATION_KEY" }, false},
		{"inline key", func(m *ModelConfig) { m.APIKey = "escalation-test-key" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			primary := cfg.addModel(base)
			other := base
			tc.change(&other)
			escalation := cfg.addModel(other)
			if (primary == escalation) != tc.same {
				t.Fatalf("same catalog entry=%t, want %t", primary == escalation, tc.same)
			}
			if !tc.same && cfg.Models[escalation] != other {
				t.Fatal("catalog discarded explicit call settings")
			}
			if again := cfg.addModel(other); again != escalation {
				t.Fatal("equivalent second insertion must reuse its entry")
			}
		})
	}
}

func TestLegacySameModelEscalationPreservesTimeoutAndAuth(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	legacy, err := json.Marshal(Config{
		Provider: ProviderConfig{URL: "https://chat.invalid", Model: "same-model", Timeout: 30, EnvKey: "PRIMARY_KEY"},
		Escalation: &EscalationConfig{Provider: ProviderConfig{
			Model: "same-model", Timeout: 2, EnvKey: "ESCALATION_KEY",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath(), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	check := func(cfg Config) {
		t.Helper()
		primaryName := cfg.ChatModelName()
		if primaryName == cfg.Escalation.Model || len(cfg.Models) != 2 {
			t.Fatal("migration merged primary and escalation with different call settings")
		}
		primary, escalation := cfg.Models[primaryName], cfg.Models[cfg.Escalation.Model]
		if primary.Timeout != 30 || primary.EnvKey != "PRIMARY_KEY" {
			t.Fatal("primary call settings changed")
		}
		if escalation.Timeout != 2 || escalation.EnvKey != "ESCALATION_KEY" || escalation.URL != primary.URL {
			t.Fatal("explicit escalation timeout/auth or inherited endpoint lost")
		}
	}
	cfg := LoadConfig()
	check(cfg)
	if original, _ := os.ReadFile(configPath()); string(original) != string(legacy) {
		t.Fatal("loading legacy config rewrote the source")
	}
	SaveConfig(cfg)
	check(LoadConfig())
}
