package yolonot

import (
	"strings"
	"testing"
)

func TestProfileUseResetCanonicaliseHarnessAlias(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	SaveConfig(Config{})

	captureStdout(func() { cmdProfileUse([]string{"strict", "--harness=agy"}) })
	cfg := LoadConfig()
	if _, ok := cfg.Policy.Harness["agy"]; ok {
		t.Fatalf("alias key written: %+v", cfg.Policy.Harness)
	}
	if got := cfg.Policy.Harness["antigravity"].Profile; got != "strict" {
		t.Fatalf("want antigravity pinned to strict, got %q (%+v)", got, cfg.Policy.Harness)
	}

	captureStdout(func() { cmdProfileReset([]string{"--harness=agy"}) })
	if hp, ok := LoadConfig().Policy.Harness["antigravity"]; ok {
		t.Fatalf("reset via alias must clear the canonical pin, got %+v", hp)
	}
}

func TestValidateConfigRejectsHarnessAliasKey(t *testing.T) {
	cfg := Config{Policy: PolicyConfig{Harness: map[string]HarnessPolicy{"agy": {Profile: "strict"}}}}
	err := ValidateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), `"antigravity"`) {
		t.Fatalf("want an error naming the canonical harness, got %v", err)
	}
	cfg.Policy.Harness = map[string]HarnessPolicy{"antigravity": {Profile: "strict"}}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("canonical key must validate: %v", err)
	}
}
