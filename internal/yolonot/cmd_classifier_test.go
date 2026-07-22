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

// withMockVerifyLLM mocks the probe calls of `yolonot classifier verify`.
// Sibling of withMockReviewLLM.
func withMockVerifyLLM(t *testing.T, response string, err error) *int {
	t.Helper()
	calls := 0
	orig := verifyCallLLM
	verifyCallLLM = func(cfg LLMConfig, system, user string, maxTokens int) (string, error) {
		calls++
		return response, err
	}
	t.Cleanup(func() { verifyCallLLM = orig })
	return &calls
}

// contractPrompt is a minimal custom base prompt that keeps the JSON verdict
// contract, so it passes the static gate.
const contractPrompt = `Custom base. Output ONLY JSON: {"decision":"allow|ask","risk":"safe|low|moderate|high|critical"}`

// TestExecuteClassifierVerifyNoOverride: with no override set the built-in
// base is used — verify says so, exits 0, never calls the LLM.
func TestExecuteClassifierVerifyNoOverride(t *testing.T) {
	withIsolatedHome(t, `{"provider":{"url":"http://localhost","model":"x"},"classifier":"llm"}`+"\n")
	calls := withMockVerifyLLM(t, `{"decision":"allow","risk":"safe"}`, nil)

	var stdout, stderr bytes.Buffer
	if code := executeClassifierVerify(&stdout, &stderr); code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if *calls != 0 {
		t.Errorf("LLM called %d times, want 0", *calls)
	}
	if !strings.Contains(stdout.String(), "nothing to verify") {
		t.Errorf("stdout missing no-override message: %s", stdout.String())
	}
}

// TestExecuteClassifierVerifyStaticFail: an override missing the JSON
// contract fails the static gate — exit 1, no LLM call.
func TestExecuteClassifierVerifyStaticFail(t *testing.T) {
	cfg := `{"provider":{"url":"http://localhost","model":"x"},"classifier":{"impl":"llm","system_prompt":"just vibe check it, no schema"}}` + "\n"
	withIsolatedHome(t, cfg)
	calls := withMockVerifyLLM(t, `{"decision":"allow","risk":"safe"}`, nil)

	var stdout, stderr bytes.Buffer
	if code := executeClassifierVerify(&stdout, &stderr); code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if *calls != 0 {
		t.Errorf("LLM called %d times on static failure, want 0", *calls)
	}
	out := stdout.String()
	if !strings.Contains(out, "STATIC") || !strings.Contains(out, "missing the JSON verdict contract") {
		t.Errorf("stdout missing static-fail explanation: %s", out)
	}
}

// TestExecuteClassifierVerifyNoProviderStaticOnly: a contract-valid override
// with no provider passes the static gate and skips the live gate — exit 0.
func TestExecuteClassifierVerifyNoProviderStaticOnly(t *testing.T) {
	// No provider block; clear env so GetLLMConfig resolves to unconfigured.
	t.Setenv("LLM_URL", "")
	t.Setenv("LLM_MODEL", "")
	cfg, _ := json.Marshal(map[string]any{"classifier": map[string]any{"impl": "llm", "system_prompt": contractPrompt}})
	withIsolatedHome(t, string(cfg))
	calls := withMockVerifyLLM(t, `{"decision":"ask","risk":"high"}`, nil)

	var stdout, stderr bytes.Buffer
	if code := executeClassifierVerify(&stdout, &stderr); code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if *calls != 0 {
		t.Errorf("LLM called %d times without provider, want 0", *calls)
	}
	out := stdout.String()
	if !strings.Contains(out, "✓ STATIC") || !strings.Contains(out, "LIVE: skipped") {
		t.Errorf("stdout missing static-pass / live-skipped: %s", out)
	}
}

// TestExecuteClassifierVerifyLivePass: contract-valid override + provider +
// every probe returns a valid verdict → PASS, exit 0, one call per probe.
func TestExecuteClassifierVerifyLivePass(t *testing.T) {
	cfg, _ := json.Marshal(map[string]any{
		"provider":   map[string]any{"url": "http://localhost", "model": "x"},
		"classifier": map[string]any{"impl": "llm", "system_prompt": contractPrompt},
	})
	withIsolatedHome(t, string(cfg))
	calls := withMockVerifyLLM(t, `{"decision":"ask","risk":"high","short":"s","reasoning":"r"}`, nil)

	var stdout, stderr bytes.Buffer
	if code := executeClassifierVerify(&stdout, &stderr); code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if *calls != len(classifierVerifyProbes) {
		t.Errorf("LLM called %d times, want %d (one per probe)", *calls, len(classifierVerifyProbes))
	}
	if !strings.Contains(stdout.String(), "PASS") {
		t.Errorf("stdout missing PASS: %s", stdout.String())
	}
}

// TestExecuteClassifierVerifyLiveFailUnparseable: provider returns non-JSON
// → every probe fails to parse → FAIL, exit 1.
func TestExecuteClassifierVerifyLiveFailUnparseable(t *testing.T) {
	cfg, _ := json.Marshal(map[string]any{
		"provider":   map[string]any{"url": "http://localhost", "model": "x"},
		"classifier": map[string]any{"impl": "llm", "system_prompt": contractPrompt},
	})
	withIsolatedHome(t, string(cfg))
	withMockVerifyLLM(t, "I think that command looks fine to me!", nil)

	var stdout, stderr bytes.Buffer
	if code := executeClassifierVerify(&stdout, &stderr); code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "unparseable") {
		t.Errorf("stdout missing live-fail report: %s", out)
	}
}

// TestExecuteClassifierVerifyDangerAllowNote: probes parse fine but a
// dangerous command comes back allow → still PASS (override works), with a
// safety NOTE surfaced. Verify checks the prompt WORKS, not that it's strict.
func TestExecuteClassifierVerifyDangerAllowNote(t *testing.T) {
	cfg, _ := json.Marshal(map[string]any{
		"provider":   map[string]any{"url": "http://localhost", "model": "x"},
		"classifier": map[string]any{"impl": "llm", "system_prompt": contractPrompt},
	})
	withIsolatedHome(t, string(cfg))
	withMockVerifyLLM(t, `{"decision":"allow","risk":"safe"}`, nil)

	var stdout, stderr bytes.Buffer
	if code := executeClassifierVerify(&stdout, &stderr); code != 0 {
		t.Errorf("exit code: got %d, want 0 (permissive override still works)", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "PASS") {
		t.Errorf("stdout missing PASS: %s", out)
	}
	if !strings.Contains(out, "NOTE") || !strings.Contains(out, "weakened safety") {
		t.Errorf("stdout missing danger-allow safety note: %s", out)
	}
}

// TestExecuteClassifierVerifyTransportErrorNotPromptFail: a provider error on
// one probe (empty response / 5xx) must NOT be reported as a broken prompt —
// the other probes prove the prompt works. Regression for the mercury-2
// "no content in response" flakiness that first surfaced this.
func TestExecuteClassifierVerifyTransportErrorNotPromptFail(t *testing.T) {
	cfg, _ := json.Marshal(map[string]any{
		"provider":   map[string]any{"url": "http://localhost", "model": "x"},
		"classifier": map[string]any{"impl": "llm", "system_prompt": contractPrompt},
	})
	withIsolatedHome(t, string(cfg))

	orig := verifyCallLLM
	verifyCallLLM = func(c LLMConfig, system, user string, maxTokens int) (string, error) {
		if strings.Contains(user, "git push --force") {
			return "", fmt.Errorf("no content in response")
		}
		return `{"decision":"ask","risk":"high"}`, nil
	}
	t.Cleanup(func() { verifyCallLLM = orig })

	var stdout, stderr bytes.Buffer
	if code := executeClassifierVerify(&stdout, &stderr); code != 0 {
		t.Errorf("exit code: got %d, want 0 (transport error is not a prompt failure)", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "PASS") {
		t.Errorf("stdout missing PASS: %s", out)
	}
	if strings.Contains(out, "will NOT work") {
		t.Errorf("transport error wrongly reported as broken prompt: %s", out)
	}
	if !strings.Contains(out, "transient provider error") {
		t.Errorf("stdout missing provider-error note: %s", out)
	}
}

// TestExecuteClassifierVerifyAllTransportError: if EVERY probe hits a provider
// error, verify can't conclude anything — exit 2 (could-not-verify), distinct
// from the exit-1 broken-prompt signal.
func TestExecuteClassifierVerifyAllTransportError(t *testing.T) {
	cfg, _ := json.Marshal(map[string]any{
		"provider":   map[string]any{"url": "http://localhost", "model": "x"},
		"classifier": map[string]any{"impl": "llm", "system_prompt": contractPrompt},
	})
	withIsolatedHome(t, string(cfg))
	withMockVerifyLLM(t, "", fmt.Errorf("upstream 503"))

	var stdout, stderr bytes.Buffer
	if code := executeClassifierVerify(&stdout, &stderr); code != 2 {
		t.Errorf("exit code: got %d, want 2 (could not verify)", code)
	}
	if !strings.Contains(stdout.String(), "COULD NOT VERIFY") {
		t.Errorf("stdout missing could-not-verify message: %s", stdout.String())
	}
}

// TestExecuteClassifierVerifyRetriesTransient: a transport error that clears on
// retry must not fail the run. First call errs, the rest succeed → the retry
// recovers it, every probe passes, and the extra attempt is observable in the
// call count.
func TestExecuteClassifierVerifyRetriesTransient(t *testing.T) {
	cfg, _ := json.Marshal(map[string]any{
		"provider":   map[string]any{"url": "http://localhost", "model": "x"},
		"classifier": map[string]any{"impl": "llm", "system_prompt": contractPrompt},
	})
	withIsolatedHome(t, string(cfg))

	calls := 0
	orig := verifyCallLLM
	verifyCallLLM = func(c LLMConfig, system, user string, maxTokens int) (string, error) {
		calls++
		if calls == 1 {
			return "", fmt.Errorf("transient empty response")
		}
		return `{"decision":"ask","risk":"high"}`, nil
	}
	t.Cleanup(func() { verifyCallLLM = orig })

	var stdout, stderr bytes.Buffer
	if code := executeClassifierVerify(&stdout, &stderr); code != 0 {
		t.Errorf("exit code: got %d, want 0 (retry should recover)", code)
	}
	if calls != len(classifierVerifyProbes)+1 {
		t.Errorf("call count: got %d, want %d (one retry)", calls, len(classifierVerifyProbes)+1)
	}
	if !strings.Contains(stdout.String(), "PASS") {
		t.Errorf("stdout missing PASS after retry: %s", stdout.String())
	}
}

// withVerifyProbes swaps the canned probe set for the duration of a test and
// restores it via t.Cleanup. Sibling of withMockVerifyLLM — the probe list is
// a package var so a test can point a probe at a script it controls.
func withVerifyProbes(t *testing.T, probes []classifierVerifyProbe) {
	t.Helper()
	orig := classifierVerifyProbes
	classifierVerifyProbes = probes
	t.Cleanup(func() { classifierVerifyProbes = orig })
}

// captureVerifyProbePrompts swaps verifyCallLLM for a mock that records every
// user prompt it is handed (the assembled BuildAnalyzePrompt output) and
// returns a canned allow verdict. Restores the real function via t.Cleanup.
func captureVerifyProbePrompts(t *testing.T) *[]string {
	t.Helper()
	var prompts []string
	orig := verifyCallLLM
	verifyCallLLM = func(_ LLMConfig, _, user string, _ int) (string, error) {
		prompts = append(prompts, user)
		return `{"decision":"allow","risk":"safe"}`, nil
	}
	t.Cleanup(func() { verifyCallLLM = orig })
	return &prompts
}

// TestExecuteClassifierVerifyAttachesOutsideProbeWhenFlagOn asserts the
// attach-boundary line executeClassifierVerify runs (attachOutsideRoot =
// userCfg.AttachOutsideRoot) actually reaches the probe prompt: with
// attach_outside_root=true a probe command that runs a script OUTSIDE the
// project root has that script's contents attached to the prompt the
// classifier is shown. The 10 existing TestExecuteClassifierVerify* tests
// execute this wiring but none observe its effect. Verify-path sibling of
// check_test.go's TestCheckHonorsAttachOutsideRoot.
func TestExecuteClassifierVerifyAttachesOutsideProbeWhenFlagOn(t *testing.T) {
	outside := t.TempDir()
	scriptPath := filepath.Join(outside, "probe_tool.py")
	if err := os.WriteFile(scriptPath, []byte("print('VERIFY-OUTSIDE-MARKER')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// One probe that runs the outside script; danger=false so an allow verdict
	// is a clean PASS.
	withVerifyProbes(t, []classifierVerifyProbe{{"python3 " + scriptPath, false}})

	// contractPrompt passes the static gate; attach_outside_root opens the
	// boundary. withIsolatedHome chdirs into a git-root repo (the attach root),
	// so the sibling temp dir holding the script is genuinely outside it.
	cfg, _ := json.Marshal(map[string]any{
		"provider":            map[string]any{"url": "http://localhost", "model": "x"},
		"attach_outside_root": true,
		"classifier":          map[string]any{"impl": "llm", "system_prompt": contractPrompt},
	})
	withIsolatedHome(t, string(cfg))
	prompts := captureVerifyProbePrompts(t)

	attachOutsideRoot = false // fresh-process simulation; only the config load may reopen it
	t.Cleanup(func() { attachOutsideRoot = false })

	var stdout, stderr bytes.Buffer
	if code := executeClassifierVerify(&stdout, &stderr); code != 0 {
		t.Fatalf("exit code: got %d, want 0\nstdout: %s", code, stdout.String())
	}
	if len(*prompts) == 0 {
		t.Fatal("expected at least one probe call")
	}
	if !strings.Contains((*prompts)[0], "VERIFY-OUTSIDE-MARKER") {
		t.Errorf("attach_outside_root=true should attach the outside probe script to the prompt; got:\n%s", (*prompts)[0])
	}
}

// TestExecuteClassifierVerifyWithholdsOutsideProbeWhenFlagOff is the closed-
// boundary half: with no attach_outside_root the same outside probe script is
// withheld from the prompt (contents never leave the box) and a withheld note
// stands in for it. Pre-setting attachOutsideRoot=true proves the config load
// resets it back for this run, exactly as a fresh process would.
func TestExecuteClassifierVerifyWithholdsOutsideProbeWhenFlagOff(t *testing.T) {
	outside := t.TempDir()
	scriptPath := filepath.Join(outside, "probe_tool.py")
	if err := os.WriteFile(scriptPath, []byte("print('VERIFY-OUTSIDE-MARKER')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withVerifyProbes(t, []classifierVerifyProbe{{"python3 " + scriptPath, false}})

	// No attach_outside_root key → boundary stays closed.
	cfg, _ := json.Marshal(map[string]any{
		"provider":   map[string]any{"url": "http://localhost", "model": "x"},
		"classifier": map[string]any{"impl": "llm", "system_prompt": contractPrompt},
	})
	withIsolatedHome(t, string(cfg))
	prompts := captureVerifyProbePrompts(t)

	attachOutsideRoot = true // must be closed back by the config load
	t.Cleanup(func() { attachOutsideRoot = false })

	var stdout, stderr bytes.Buffer
	if code := executeClassifierVerify(&stdout, &stderr); code != 0 {
		t.Fatalf("exit code: got %d, want 0\nstdout: %s", code, stdout.String())
	}
	if len(*prompts) == 0 {
		t.Fatal("expected at least one probe call")
	}
	if strings.Contains((*prompts)[0], "VERIFY-OUTSIDE-MARKER") {
		t.Errorf("closed boundary must withhold the outside probe script; got:\n%s", (*prompts)[0])
	}
	if !strings.Contains((*prompts)[0], "not attached") {
		t.Errorf("closed boundary should carry a withheld note for the outside script; got:\n%s", (*prompts)[0])
	}
}
