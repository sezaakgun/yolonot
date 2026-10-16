package yolonot

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// A config in the shape v0.23.0 wrote: only keys that release's Config
// struct had (no `decision`, no `judges`), an inline escalation key included.
const releasedV0Config = `{
  "provider": {"name": "OpenRouter", "url": "https://openrouter.ai/api/v1/chat/completions", "model": "google/gemini-2.5-flash-lite", "env_key": "OPENROUTER_API_KEY", "timeout": 20},
  "classifier": {"context": ["$defaults", "github.com/yourorg/* is ours"], "allow_hints": ["$defaults"], "ask_hints": ["$defaults", "never touch prod buckets"]},
  "risk_maps": {"codex": {"high": "deny"}},
  "pre_check": ["fast-allow", "/opt/homebrew/bin/dippy"],
  "quiet_on_allow": true,
  "wrappers": ["corp-shim"],
  "attach_outside_root": true,
  "profile": "careful",
  "profile_override": {"codex": "strict"},
  "custom_profiles": {"careful": {"safe": "allow", "low": "allow", "moderate": "ask", "high": "ask", "critical": "deny"}},
  "escalation": {"provider": {"url": "https://api.deepseek.example.com/v1/chat/completions", "model": "deepseek-v4-flash", "api_key": "sk-inline-fixture"}, "unresolved": "deny"}
}
`

func TestMigrateCommandFlow(t *testing.T) {
	productControlHome(t)
	if err := os.WriteFile(configPath(), []byte(releasedV0Config), 0600); err != nil {
		t.Fatal(err)
	}
	folded := LoadConfig()
	if folded.LoadError != nil || !folded.Legacy {
		t.Fatalf("v0.23 config did not fold: legacy=%v err=%v", folded.Legacy, folded.LoadError)
	}
	cli := func(args ...string) string {
		t.Helper()
		out, err := productCLI(t, nil, append([]string{"migrate"}, args...)...)
		if err != nil {
			t.Fatalf("migrate %v: %v\n%s", args, err, out)
		}
		return string(out)
	}

	out := cli("--dry-run")
	if data, _ := os.ReadFile(configPath()); string(data) != releasedV0Config {
		t.Fatal("--dry-run wrote the config")
	}
	if strings.Contains(out, "sk-inline-fixture") || !strings.Contains(out, `"config_version": 1`) {
		t.Fatalf("dry-run output: %s", out)
	}

	out = cli()
	if !strings.Contains(out, "Migrated to v1") || !strings.Contains(out, "inline api_key") {
		t.Fatalf("migrate output: %s", out)
	}
	if bak, _ := os.ReadFile(configPath() + ".bak"); string(bak) != releasedV0Config {
		t.Fatal(".bak is not the original file")
	}
	written, _ := os.ReadFile(configPath())
	var raw map[string]any
	if err := json.Unmarshal(written, &raw); err != nil || raw["config_version"] != float64(1) {
		t.Fatalf("written config: %s", written)
	}
	for _, old := range []string{"provider", "classifier", "pre_check", "risk_maps", "profile", "profile_override", "custom_profiles", "local_allow"} {
		if _, ok := raw[old]; ok {
			t.Errorf("0.x key %q kept after migrate", old)
		}
	}
	if strings.Contains(string(written), "sk-inline-fixture") {
		t.Error("inline api_key written to disk")
	}

	migrated := LoadConfig()
	if migrated.LoadError != nil || migrated.Legacy {
		t.Fatalf("migrated file: legacy=%v err=%v", migrated.Legacy, migrated.LoadError)
	}
	if judgeNames(migrated.Judges) != judgeNames(folded.Judges) || !strings.HasPrefix(judgeNames(migrated.Judges), "fast_allow → exec:/opt/homebrew/bin/dippy → ") {
		t.Errorf("judges: folded %q, migrated %q", judgeNames(folded.Judges), judgeNames(migrated.Judges))
	}
	if migrated.Escalation == nil || migrated.Escalation.Model != folded.Escalation.Model || migrated.Escalation.Unresolved != "deny" {
		t.Errorf("escalation: %+v", migrated.Escalation)
	}
	if migrated.Policy.Profile != "careful" || migrated.harnessPolicy("codex").Profile != "strict" || migrated.harnessPolicy("codex").RiskMap["high"] != "deny" {
		t.Errorf("policy: %+v", migrated.Policy)
	}
	if !migrated.QuietOnAllow || len(migrated.Wrappers) != 1 || !migrated.AttachOutsideRoot || len(migrated.Prompt.AskHints) != 2 {
		t.Errorf("settings lost: quiet=%v wrappers=%v attach=%v hints=%v", migrated.QuietOnAllow, migrated.Wrappers, migrated.AttachOutsideRoot, migrated.Prompt.AskHints)
	}
	if err := ValidateConfig(migrated); err != nil {
		t.Errorf("migrated config does not validate: %v", err)
	}

	if out = cli(); !strings.Contains(out, "already v1") {
		t.Fatalf("second migrate: %s", out)
	}
	cli("--undo")
	if data, _ := os.ReadFile(configPath()); string(data) != releasedV0Config {
		t.Fatal("--undo did not restore the original")
	}
}

func TestWriteCommandsOnV0WithoutTerminalLeaveTheFile(t *testing.T) {
	productControlHome(t)
	if err := os.WriteFile(configPath(), []byte(releasedV0Config), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"quiet", "off"}, {"profile", "use", "strict"}, {"escalation", "off"}} {
		out, err := productCLI(t, nil, args...)
		if err == nil || !strings.Contains(string(out), "Run `yolonot migrate` first") {
			t.Errorf("%v: err=%v out=%s", args, err, out)
		}
		if data, _ := os.ReadFile(configPath()); string(data) != releasedV0Config {
			t.Fatalf("%v rewrote a v0 config without migrating", args)
		}
	}
}
