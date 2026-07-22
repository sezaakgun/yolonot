package yolonot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEvalSuite writes a one-off JSONL suite file and returns its absolute
// path. Each argument is one JSON case line.
func writeEvalSuite(t *testing.T, cases ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "suite.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(cases, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write suite: %v", err)
	}
	return path
}

// captureEvalPrompts swaps evalCallLLM for a mock that records every user
// prompt (the assembled BuildAnalyzePrompt output) and returns a canned allow
// verdict. Restores the real function via t.Cleanup.
func captureEvalPrompts(t *testing.T) *[]string {
	t.Helper()
	var prompts []string
	orig := evalCallLLM
	evalCallLLM = func(_ LLMConfig, _, user string, _ int) (string, error) {
		prompts = append(prompts, user)
		return `{"decision":"allow","risk":"safe"}`, nil
	}
	t.Cleanup(func() { evalCallLLM = orig })
	return &prompts
}

// TestCmdEvalWithHintsAttachesOutsideScript asserts the attach-boundary line
// cmdEval runs only under --with-hints (attachOutsideRoot =
// evalCfg.AttachOutsideRoot): with the flag AND config attach_outside_root=true,
// a greenfield case whose command runs an outside-root script gets that
// script's contents attached to the graded prompt. No cmdEval test existed, so
// this propagation was unverified.
func TestCmdEvalWithHintsAttachesOutsideScript(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	outside := t.TempDir()
	scriptPath := filepath.Join(outside, "tool.py")
	if err := os.WriteFile(scriptPath, []byte("print('EVAL-OUTSIDE-MARKER')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	SaveConfig(Config{Provider: ProviderConfig{URL: "http://localhost", Model: "x"}, AttachOutsideRoot: true})

	suite := writeEvalSuite(t, `{"id":"c1","command":"python3 `+scriptPath+`","expected":"allow"}`)

	// A greenfield case with empty cwd resolves scripts against the eval
	// process cwd; chdir somewhere that does NOT contain the outside script.
	projectDir := t.TempDir()
	origCwd, _ := os.Getwd()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origCwd)

	prompts := captureEvalPrompts(t)
	attachOutsideRoot = false // fresh-process simulation; only --with-hints config load may open it
	t.Cleanup(func() { attachOutsideRoot = false })

	opts := EvalOptions{
		Suites:    []string{suite},
		Models:    []string{"ollama/test"}, // resolves to localhost → no rate-limit sleep
		Runs:      1,
		MaxTokens: 300,
		WithHints: true,
	}
	captureStdout(func() { cmdEval(opts) })

	if len(*prompts) == 0 {
		t.Fatal("expected at least one eval LLM call")
	}
	if !strings.Contains((*prompts)[0], "EVAL-OUTSIDE-MARKER") {
		t.Errorf("--with-hints + attach_outside_root=true should attach the outside script; got:\n%s", (*prompts)[0])
	}
}

// TestCmdEvalDefaultKeepsAttachBoundaryClosed is the reproducibility half: a
// default run (no --with-hints) must NOT open the attach boundary even when
// config sets attach_outside_root=true — otherwise machine-specific config
// would leak into suite scores. Same config as the ON test, flag off → the
// outside script is withheld.
func TestCmdEvalDefaultKeepsAttachBoundaryClosed(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	outside := t.TempDir()
	scriptPath := filepath.Join(outside, "tool.py")
	if err := os.WriteFile(scriptPath, []byte("print('EVAL-OUTSIDE-MARKER')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	SaveConfig(Config{Provider: ProviderConfig{URL: "http://localhost", Model: "x"}, AttachOutsideRoot: true})

	suite := writeEvalSuite(t, `{"id":"c1","command":"python3 `+scriptPath+`","expected":"allow"}`)

	projectDir := t.TempDir()
	origCwd, _ := os.Getwd()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origCwd)

	prompts := captureEvalPrompts(t)
	attachOutsideRoot = false // fresh-process default; a run without --with-hints never touches it
	t.Cleanup(func() { attachOutsideRoot = false })

	opts := EvalOptions{
		Suites:    []string{suite},
		Models:    []string{"ollama/test"},
		Runs:      1,
		MaxTokens: 300,
		WithHints: false,
	}
	captureStdout(func() { cmdEval(opts) })

	if len(*prompts) == 0 {
		t.Fatal("expected at least one eval LLM call")
	}
	if strings.Contains((*prompts)[0], "EVAL-OUTSIDE-MARKER") {
		t.Errorf("default eval (no --with-hints) must not attach outside scripts even with the config flag set; got:\n%s", (*prompts)[0])
	}
	if !strings.Contains((*prompts)[0], "not attached") {
		t.Errorf("closed boundary should carry a withheld note for the outside script; got:\n%s", (*prompts)[0])
	}
}
