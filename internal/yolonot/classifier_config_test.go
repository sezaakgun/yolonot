package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestClassifierConfigUnmarshalLegacyString locks in the load-time backward-
// compat invariant: every prior yolonot version wrote `classifier: "<impl>"`
// as a JSON string, and those configs must still parse without manual
// migration. If this test fails, existing user configs break on upgrade.
func TestClassifierConfigUnmarshalLegacyString(t *testing.T) {
	cases := []struct {
		input string
		want  ClassifierConfig
	}{
		{`"llm"`, ClassifierConfig{Impl: "llm"}},
		{`"heuristic"`, ClassifierConfig{Impl: "heuristic"}},
		{`""`, ClassifierConfig{}},
	}
	for _, tc := range cases {
		var got ClassifierConfig
		if err := json.Unmarshal([]byte(tc.input), &got); err != nil {
			t.Fatalf("unmarshal %q: %v", tc.input, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("unmarshal %q: got %+v, want %+v", tc.input, got, tc.want)
		}
	}
}

// TestClassifierConfigUnmarshalObject covers the new object form with
// hint slices and the $defaults sentinel.
func TestClassifierConfigUnmarshalObject(t *testing.T) {
	in := `{
		"impl": "llm",
		"context": ["$defaults", "trusted: *.example.com"],
		"allow_hints": ["kubectl get on prod-* is read-only"],
		"ask_hints": ["never touch billing schema"]
	}`
	var got ClassifierConfig
	if err := json.Unmarshal([]byte(in), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := ClassifierConfig{
		Impl:       "llm",
		Context:    []string{"$defaults", "trusted: *.example.com"},
		AllowHints: []string{"kubectl get on prod-* is read-only"},
		AskHints:   []string{"never touch billing schema"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// TestClassifierConfigUnmarshalNullAndMissing covers the two no-op shapes
// — explicit null and a parent object with no "classifier" key — and
// confirms the zero value works (no panic on Impl access).
func TestClassifierConfigUnmarshalNullAndMissing(t *testing.T) {
	var c ClassifierConfig
	if err := json.Unmarshal([]byte(`null`), &c); err != nil {
		t.Fatalf("null unmarshal: %v", err)
	}
	if c.Impl != "" || c.Context != nil || c.AllowHints != nil || c.AskHints != nil {
		t.Errorf("null produced non-zero: %+v", c)
	}

	var parent struct {
		Other      string           `json:"other"`
		Classifier ClassifierConfig `json:"classifier,omitempty"`
	}
	if err := json.Unmarshal([]byte(`{"other":"x"}`), &parent); err != nil {
		t.Fatalf("missing-key unmarshal: %v", err)
	}
	if parent.Classifier.Impl != "" {
		t.Errorf("missing key produced non-zero impl: %q", parent.Classifier.Impl)
	}
}

// TestClassifierConfigMarshalRoundTripLegacy locks in the save-time
// backward-compat invariant: a config that loaded as a legacy string
// re-serializes as a legacy string, so simply running yolonot once doesn't
// silently rewrite the user's config.json into the new shape.
func TestClassifierConfigMarshalRoundTripLegacy(t *testing.T) {
	in := `"llm"`
	var c ClassifierConfig
	if err := json.Unmarshal([]byte(in), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(out) != `"llm"` {
		t.Errorf("legacy round-trip: got %s, want %q", out, `"llm"`)
	}
}

// TestClassifierConfigMarshalObjectShapeWithHints confirms that once a
// user adds any hints the marshaler switches to the object form rather
// than dropping the new fields.
func TestClassifierConfigMarshalObjectShapeWithHints(t *testing.T) {
	c := ClassifierConfig{Impl: "llm", Context: []string{"trusted: x"}}
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), `"context"`) || !strings.Contains(string(out), `"impl":"llm"`) {
		t.Errorf("object-shape marshal missing fields: %s", out)
	}
}

// TestExpandDefaultsSentinel covers $defaults expansion, no-sentinel
// passthrough, and the surrounding-entries-preserved property.
func TestExpandDefaultsSentinel(t *testing.T) {
	builtin := []string{"BUILTIN-A", "BUILTIN-B"}
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty input → nil", nil, nil},
		{"sentinel only → builtins", []string{"$defaults"}, builtin},
		{"no sentinel → user list verbatim", []string{"u1", "u2"}, []string{"u1", "u2"}},
		{"sentinel preserves ordering",
			[]string{"u1", "$defaults", "u2"},
			[]string{"u1", "BUILTIN-A", "BUILTIN-B", "u2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expandDefaults(tc.in, builtin)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBuildSystemPromptDefaultByteEqual is the core backward-compat
// invariant for the LLM call path: with no user customization, the system
// prompt sent to the model must be byte-equal to the SystemPrompt const.
// If this fails, every existing user's classifier behavior may shift on
// upgrade — even users who never touched the new feature.
func TestBuildSystemPromptDefaultByteEqual(t *testing.T) {
	got := BuildSystemPrompt(ClassifierConfig{}, WalkupHints{})
	if got != SystemPrompt {
		t.Fatalf("default BuildSystemPrompt diverged from SystemPrompt const")
	}
}

// TestBuildSystemPromptIncludesUserHints checks the assembly: each user
// section is labeled, hints render as bullets, and the base prompt is
// preserved as a prefix so the model still gets the canonical instructions.
func TestBuildSystemPromptIncludesUserHints(t *testing.T) {
	cfg := ClassifierConfig{
		Context:    []string{"trusted: *.example.com"},
		AllowHints: []string{"kubectl get on prod-* is read-only"},
		AskHints:   []string{"never run schema migrations against billing"},
	}
	got := BuildSystemPrompt(cfg, WalkupHints{})
	if !strings.HasPrefix(got, SystemPrompt) {
		t.Errorf("base SystemPrompt is not a prefix of the assembled prompt")
	}
	for _, want := range []string{
		"Project context",
		"trusted: *.example.com",
		"Project allow hints",
		"kubectl get on prod-* is read-only",
		"Project ask hints",
		"never run schema migrations against billing",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("assembled prompt missing %q", want)
		}
	}
}

// TestBuildSystemPromptStripsDefaultsSentinel makes sure the literal
// "$defaults" token never reaches the model — only its expansion does.
func TestBuildSystemPromptStripsDefaultsSentinel(t *testing.T) {
	cfg := ClassifierConfig{
		Context: []string{DefaultsSentinel, "real entry"},
	}
	got := BuildSystemPrompt(cfg, WalkupHints{})
	if strings.Contains(got, DefaultsSentinel) {
		t.Errorf("$defaults sentinel leaked into prompt: %s", got)
	}
	if !strings.Contains(got, "real entry") {
		t.Errorf("user entry alongside sentinel was dropped")
	}
}

// TestBuiltinClassifierDefaultsPopulated locks in that yolonot ships
// non-empty default hints. If a future change accidentally empties one
// of these slices the user-visible behavior of $defaults silently
// degrades.
func TestBuiltinClassifierDefaultsPopulated(t *testing.T) {
	if len(builtinClassifierContext) == 0 {
		t.Error("builtinClassifierContext is empty; default $defaults expansion would be a no-op")
	}
	if len(builtinClassifierAllowHints) == 0 {
		t.Error("builtinClassifierAllowHints is empty")
	}
	if len(builtinClassifierAskHints) == 0 {
		t.Error("builtinClassifierAskHints is empty")
	}
}

// TestBuildSystemPromptDefaultsExpandToRealContent confirms that
// "$defaults" in a user hint list pulls the built-in entries into the
// final system prompt. Catches regressions where the sentinel parser
// works but the built-in slice was wired to the wrong variable.
func TestBuildSystemPromptDefaultsExpandToRealContent(t *testing.T) {
	cfg := ClassifierConfig{Context: []string{DefaultsSentinel}}
	got := BuildSystemPrompt(cfg, WalkupHints{})
	if !strings.Contains(got, builtinClassifierContext[0]) {
		t.Errorf("$defaults did not expand: first builtin entry not in prompt")
	}
}

// TestLabelsForReport locks in the label sets each eval mode uses for
// summary tables and confusion matrices. If risk-mode ever falls back
// to the decision label set, confusion matrices print zero everywhere
// (the bug we just fixed). Cheap regression guard.
func TestLabelsForReport(t *testing.T) {
	cases := []struct {
		suiteType string
		metric    string
		want      []string
	}{
		{"greenfield", "", []string{"allow", "deny", "ask"}},
		{"greenfield", "decision", []string{"allow", "deny", "ask"}},
		{"greenfield", "risk", []string{"safe", "low", "moderate", "high", "critical"}},
		{"brownfield", "", []string{"allow", "ask"}},
		{"brownfield", "risk", []string{"safe", "low", "moderate", "high", "critical"}},
	}
	for _, tc := range cases {
		got := labelsForReport(tc.suiteType, tc.metric)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("labelsForReport(%q,%q): got %v, want %v",
				tc.suiteType, tc.metric, got, tc.want)
		}
	}
}

// TestLoadConfigRoundtripLegacyClassifier is the end-to-end backward-
// compat invariant for the LoadConfig/SaveConfig pair: a config file
// written by a previous yolonot version (classifier as string) must
// load, re-save, and reload byte-equal — no silent migration to the
// object form unless the user adds hints.
func TestLoadConfigRoundtripLegacyClassifier(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".yolonot"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	original := []byte(`{
  "provider": {"name": "openai", "model": "gpt-5.4-mini"},
  "classifier": "llm"
}
`)
	cfgPath := filepath.Join(tmp, ".yolonot", "config.json")
	if err := os.WriteFile(cfgPath, original, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := LoadConfig()
	if c.Classifier.Impl != "llm" {
		t.Errorf("Impl: got %q, want %q", c.Classifier.Impl, "llm")
	}
	if len(c.Classifier.Context)+len(c.Classifier.AllowHints)+len(c.Classifier.AskHints) != 0 {
		t.Errorf("legacy load produced non-empty hints: %+v", c.Classifier)
	}

	SaveConfig(c)
	written, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read after save: %v", err)
	}
	if !strings.Contains(string(written), `"classifier": "llm"`) {
		t.Errorf("legacy round-trip did not preserve string form; got:\n%s", written)
	}
	if strings.Contains(string(written), `"impl"`) {
		t.Errorf("legacy config silently rewrote to object form; got:\n%s", written)
	}
}

// TestLoadConfigSavesObjectFormWithHints confirms the marshaler does
// switch to the object form once any hint is set — otherwise users who
// edit hints in via the CLI/scripts in the future would see their
// changes silently dropped on next SaveConfig.
func TestLoadConfigSavesObjectFormWithHints(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".yolonot"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	c := Config{
		Provider: ProviderConfig{Name: "openai", Model: "gpt-5.4-mini"},
		Classifier: ClassifierConfig{
			Impl:    "llm",
			Context: []string{"trusted: example.com"},
		},
	}
	SaveConfig(c)
	written, err := os.ReadFile(filepath.Join(tmp, ".yolonot", "config.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(written), `"context"`) {
		t.Errorf("object form missing context field; got:\n%s", written)
	}
	if !strings.Contains(string(written), `"impl"`) {
		t.Errorf("object form missing impl field; got:\n%s", written)
	}
}

// TestBuildSystemPromptMergesWalkupAfterConfig locks in the documented
// precedence: config entries appear before walk-up entries within each
// section, so per-user globals are listed before per-project additions.
func TestBuildSystemPromptMergesWalkupAfterConfig(t *testing.T) {
	cfg := ClassifierConfig{Context: []string{"FROM-CONFIG"}}
	walk := WalkupHints{Context: []string{"FROM-WALKUP"}}
	got := BuildSystemPrompt(cfg, walk)
	configIdx := strings.Index(got, "FROM-CONFIG")
	walkIdx := strings.Index(got, "FROM-WALKUP")
	if configIdx < 0 || walkIdx < 0 {
		t.Fatalf("missing entries in prompt: %q", got)
	}
	if configIdx > walkIdx {
		t.Errorf("config entry appeared after walkup entry; want config first")
	}
}
