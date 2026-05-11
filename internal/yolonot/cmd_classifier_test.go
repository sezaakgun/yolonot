package yolonot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPrintClassifierDefaultsJSONShape locks the public schema printed by
// `yolonot classifier defaults`. Users pipe this through jq; changing the
// keys silently would break their scripts.
func TestPrintClassifierDefaultsJSONShape(t *testing.T) {
	out := captureStdout(func() { printClassifierDefaults(os.Stdout) })
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	for _, key := range []string{"system_prompt", "context", "allow_hints", "ask_hints"} {
		if _, ok := payload[key]; !ok {
			t.Errorf("missing key %q in defaults output", key)
		}
	}
	// system_prompt must be the verbatim const so that documentation and
	// `jq -r .system_prompt` both stay reliable.
	if payload["system_prompt"] != SystemPrompt {
		t.Errorf("system_prompt key did not match SystemPrompt const")
	}
}

// TestBuildClassifierReviewUserPromptEmpty confirms the review subcommand
// short-circuits when there's nothing to audit — we don't want to burn an
// LLM call for an empty hint set.
func TestBuildClassifierReviewUserPromptEmpty(t *testing.T) {
	got := buildClassifierReviewUserPrompt(ClassifierConfig{}, WalkupHints{})
	if got != "" {
		t.Errorf("expected empty prompt for empty hints; got %q", got)
	}
}

// TestBuildClassifierReviewUserPromptStructure checks the sectioning of
// the review prompt: each non-empty bucket gets its own labeled section.
func TestBuildClassifierReviewUserPromptStructure(t *testing.T) {
	got := buildClassifierReviewUserPrompt(ClassifierConfig{
		Context:    []string{"trusted: x"},
		AllowHints: []string{"a"},
		AskHints:   []string{"b"},
	}, WalkupHints{})
	for _, want := range []string{"context:", "allow_hints:", "ask_hints:", "trusted: x", "- a", "- b"} {
		if !strings.Contains(got, want) {
			t.Errorf("review prompt missing %q\nfull prompt:\n%s", want, got)
		}
	}
}

// TestTryPrettyJSONStripsCodeFence covers the markdown-fence fallback —
// some models wrap their JSON in ```json blocks. We strip the fence so
// the user sees clean output.
func TestTryPrettyJSONStripsCodeFence(t *testing.T) {
	in := "```json\n{\"findings\":[]}\n```"
	out, ok := tryPrettyJSON(in)
	if !ok {
		t.Fatal("expected fenced JSON to parse")
	}
	if !strings.Contains(out, `"findings"`) || strings.Contains(out, "```") {
		t.Errorf("fence was not stripped or JSON not pretty: %q", out)
	}
}

// TestTryPrettyJSONRejectsNonJSON ensures the helper does not try to
// pretty-print a free-text response — that would trigger a panic in the
// caller's logic.
func TestTryPrettyJSONRejectsNonJSON(t *testing.T) {
	if _, ok := tryPrettyJSON("looks good to me"); ok {
		t.Error("expected non-JSON input to be rejected")
	}
}

// TestPrintClassifierEffectiveEndToEnd integrates the full surface a
// user would exercise via `yolonot classifier config`:
//
//	~/.yolonot/config.json (object form with hints + $defaults sentinel)
//	  + .yolonot walk-up file in cwd
//	  -> printClassifierEffective JSON
//	  -> walkup entries present + config entries present + sentinel
//	     expanded + system_prompt contains them in stable section order.
//
// Locks in: schema keys stable, $defaults expansion reaches output,
// walk-up appends after config, system_prompt contains base prompt.
func TestPrintClassifierEffectiveEndToEnd(t *testing.T) {
	// Two separate dirs so `.yolonot` as a file (walk-up at repo root)
	// and `.yolonot` as a dir (config home under $HOME) don't collide.
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	t.Setenv("HOME", home)

	// Walk-up .yolonot file at repo root
	if err := os.WriteFile(filepath.Join(repo, ".yolonot"),
		[]byte(`context "walkup: from .yolonot file"`+"\n"), 0o644); err != nil {
		t.Fatalf("write .yolonot: %v", err)
	}
	// Personal config dir under $HOME
	if err := os.MkdirAll(filepath.Join(home, ".yolonot"), 0o755); err != nil {
		t.Fatalf("mkdir home/.yolonot: %v", err)
	}
	cfgJSON := `{
  "provider": {"name": "openai", "model": "gpt-5.4-mini"},
  "classifier": {
    "impl": "llm",
    "context": ["$defaults", "config: trusted github.com/yourorg/*"],
    "allow_hints": ["config: ./build/ writes are routine"],
    "ask_hints": ["config: never modify billing schema"]
  }
}
`
	if err := os.WriteFile(filepath.Join(home, ".yolonot", "config.json"),
		[]byte(cfgJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Chdir(repo)

	out := captureStdout(func() { printClassifierEffective(os.Stdout) })
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}

	// Backend field
	if payload["backend"] != "llm" {
		t.Errorf("backend: got %v, want %q", payload["backend"], "llm")
	}

	// $defaults sentinel must have expanded (no raw "$defaults" leaks)
	ctxArr, _ := payload["context"].([]any)
	for _, v := range ctxArr {
		if v == DefaultsSentinel {
			t.Errorf("$defaults sentinel leaked into output context")
		}
	}
	// First builtin entry should be present (proves $defaults expanded)
	firstBuiltin := builtinClassifierContext[0]
	foundBuiltin := false
	for _, v := range ctxArr {
		if v == firstBuiltin {
			foundBuiltin = true
			break
		}
	}
	if !foundBuiltin {
		t.Errorf("$defaults did not expand built-in context into output")
	}

	// Both config and walkup entries should be present
	if !containsString(ctxArr, "config: trusted github.com/yourorg/*") {
		t.Errorf("config context entry missing from output: %v", ctxArr)
	}
	if !containsString(ctxArr, "walkup: from .yolonot file") {
		t.Errorf("walkup context entry missing from output: %v", ctxArr)
	}

	// system_prompt should contain base prompt as prefix + sections + entries
	sp, ok := payload["system_prompt"].(string)
	if !ok || !strings.HasPrefix(sp, SystemPrompt) {
		t.Errorf("system_prompt missing base SystemPrompt prefix")
	}
	for _, expect := range []string{
		"Project context",
		"config: trusted github.com/yourorg/*",
		"walkup: from .yolonot file",
		"Project allow hints",
		"config: ./build/ writes are routine",
		"Project ask hints",
		"config: never modify billing schema",
	} {
		if !strings.Contains(sp, expect) {
			t.Errorf("system_prompt missing %q", expect)
		}
	}
}

func containsString(arr []any, want string) bool {
	for _, v := range arr {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}

// withMockReviewLLM is the cmd_classifier sibling of withMockLLM in
// eval_helpers_test.go. Same pattern, different package-level var.
func withMockReviewLLM(t *testing.T, response string, err error) {
	t.Helper()
	orig := reviewCallLLM
	reviewCallLLM = func(cfg LLMConfig, system, user string, maxTokens int) (string, error) {
		return response, err
	}
	t.Cleanup(func() { reviewCallLLM = orig })
}

// withIsolatedHome sets up a tmp $HOME with optional config.json + a
// repo root in a sibling dir, then Chdir's into the repo. Keeps tests
// isolated from the developer's real ~/.yolonot.
func withIsolatedHome(t *testing.T, configJSON string) (home, repo string) {
	t.Helper()
	tmp := t.TempDir()
	home = filepath.Join(tmp, "home")
	repo = filepath.Join(tmp, "repo")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir repo/.git: %v", err)
	}
	t.Setenv("HOME", home)
	if configJSON != "" {
		if err := os.MkdirAll(filepath.Join(home, ".yolonot"), 0o755); err != nil {
			t.Fatalf("mkdir home/.yolonot: %v", err)
		}
		if err := os.WriteFile(filepath.Join(home, ".yolonot", "config.json"),
			[]byte(configJSON), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}
	t.Chdir(repo)
	return home, repo
}

// TestExecuteClassifierReviewNoProvider covers the early-exit path
// when LLM provider isn't configured. Should write to stderr and
// return exit code 1, NOT call the LLM.
func TestExecuteClassifierReviewNoProvider(t *testing.T) {
	withIsolatedHome(t, "") // empty config → no provider

	called := false
	orig := reviewCallLLM
	reviewCallLLM = func(cfg LLMConfig, system, user string, maxTokens int) (string, error) {
		called = true
		return "", nil
	}
	t.Cleanup(func() { reviewCallLLM = orig })

	var stdout, stderr bytes.Buffer
	code := executeClassifierReview(&stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if called {
		t.Errorf("reviewCallLLM should not be invoked without provider config")
	}
	if !strings.Contains(stderr.String(), "LLM provider not configured") {
		t.Errorf("stderr missing provider error: %s", stderr.String())
	}
}

// TestExecuteClassifierReviewNoHints covers the short-circuit when
// the user has no custom hints to review. Should print a friendly
// note to stdout, NOT call the LLM, return 0.
func TestExecuteClassifierReviewNoHints(t *testing.T) {
	cfgJSON := `{"provider":{"url":"http://localhost","model":"x"},"classifier":"llm"}` + "\n"
	withIsolatedHome(t, cfgJSON)

	called := false
	orig := reviewCallLLM
	reviewCallLLM = func(cfg LLMConfig, system, user string, maxTokens int) (string, error) {
		called = true
		return "", nil
	}
	t.Cleanup(func() { reviewCallLLM = orig })

	var stdout, stderr bytes.Buffer
	code := executeClassifierReview(&stdout, &stderr)
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if called {
		t.Errorf("reviewCallLLM should not be invoked with empty hints")
	}
	if !strings.Contains(stdout.String(), "no custom hints to review") {
		t.Errorf("stdout missing short-circuit message: %s", stdout.String())
	}
}

// TestExecuteClassifierReviewPrettyPrintsJSON covers the happy path:
// hints present, model returns valid JSON findings, output is pretty-
// printed JSON on stdout.
func TestExecuteClassifierReviewPrettyPrintsJSON(t *testing.T) {
	cfgJSON := `{
  "provider": {"url": "http://localhost", "model": "x"},
  "classifier": {"impl": "llm", "allow_hints": ["test hint"]}
}` + "\n"
	withIsolatedHome(t, cfgJSON)

	withMockReviewLLM(t, `{"findings":[{"hint":"test hint","kind":"allow_hint","severity":"warn","note":"too vague"}]}`, nil)

	var stdout, stderr bytes.Buffer
	code := executeClassifierReview(&stdout, &stderr)
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	out := stdout.String()
	if !strings.Contains(out, `"findings"`) {
		t.Errorf("stdout missing findings: %s", out)
	}
	if !strings.Contains(out, "too vague") {
		t.Errorf("stdout missing note text: %s", out)
	}
	// Pretty-printed JSON has indentation
	if !strings.Contains(out, "\n  ") {
		t.Errorf("stdout not pretty-printed: %s", out)
	}
}

// TestExecuteClassifierReviewFallsBackToRawOnNonJSON covers the
// resilience path: model returned prose instead of JSON. We still
// print it (clipped) rather than discarding, so the user sees what
// came back.
func TestExecuteClassifierReviewFallsBackToRawOnNonJSON(t *testing.T) {
	cfgJSON := `{
  "provider": {"url": "http://localhost", "model": "x"},
  "classifier": {"impl": "llm", "ask_hints": ["x"]}
}` + "\n"
	withIsolatedHome(t, cfgJSON)

	withMockReviewLLM(t, "All hints look reasonable to me.", nil)

	var stdout, stderr bytes.Buffer
	code := executeClassifierReview(&stdout, &stderr)
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "All hints look reasonable") {
		t.Errorf("stdout did not preserve raw response: %s", stdout.String())
	}
}

// TestCmdClassifierDispatch covers the switch in cmdClassifier. Each
// subcommand should route to its handler and produce identifiable
// output. We assert on output substrings rather than exact JSON so
// the schema-shape tests (TestPrintClassifierDefaultsJSONShape etc)
// remain the source of truth for format.
func TestCmdClassifierDispatch(t *testing.T) {
	withIsolatedHome(t, "") // no provider needed for these subcommands

	cases := []struct {
		name        string
		args        []string
		wantStdout  string  // substring expected in captured stdout
		wantStderr  string  // substring expected in captured stderr (or "")
	}{
		{"no args defaults to config",
			[]string{},
			`"system_prompt"`, ""},
		{"explicit config",
			[]string{"config"},
			`"system_prompt"`, ""},
		{"defaults",
			[]string{"defaults"},
			`"system_prompt"`, ""},
		{"help",
			[]string{"help"},
			`Usage: yolonot classifier`, ""},
		{"-h flag",
			[]string{"-h"},
			`Usage: yolonot classifier`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(func() { cmdClassifier(tc.args) })
			if !strings.Contains(out, tc.wantStdout) {
				t.Errorf("stdout for args %v missing %q\ngot: %s",
					tc.args, tc.wantStdout, out)
			}
		})
	}
}

// TestExecuteClassifierReviewLLMErrorReturnsNonZero covers the
// transport-failure path. Stderr must explain the failure; exit 1.
func TestExecuteClassifierReviewLLMErrorReturnsNonZero(t *testing.T) {
	cfgJSON := `{
  "provider": {"url": "http://localhost", "model": "x"},
  "classifier": {"impl": "llm", "context": ["something"]}
}` + "\n"
	withIsolatedHome(t, cfgJSON)

	withMockReviewLLM(t, "", fmt.Errorf("simulated upstream 503"))

	var stdout, stderr bytes.Buffer
	code := executeClassifierReview(&stdout, &stderr)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "503") {
		t.Errorf("stderr missing underlying error: %s", stderr.String())
	}
}
