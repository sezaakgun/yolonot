package yolonot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The redaction marker rendered in place of a credential-looking line.
const secretRedactionMarker = "<redacted line — looks like a secret>"

// renderAttachedScript must replace a credential-looking line with the
// redaction marker while leaving surrounding benign lines intact — the LLM
// sees the script's structure without ever receiving the secret bytes.
func TestRenderAttachedScriptRedactsSecretLine(t *testing.T) {
	content := "#!/bin/bash\n" +
		"echo starting\n" +
		"export ANTHROPIC_API_KEY=sk-ant-api03-0123456789abcdefghij\n" +
		"echo done\n"

	rendered := renderAttachedScript([]byte(content))

	if !strings.Contains(rendered, secretRedactionMarker) {
		t.Errorf("secret line should be replaced with the redaction marker, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "sk-ant-api03-0123456789abcdefghij") {
		t.Errorf("raw secret must never appear in the rendered script, got:\n%s", rendered)
	}
}

// Redaction is line-scoped: benign lines around the secret must survive so
// the classifier still sees what the script does.
func TestRenderAttachedScriptKeepsBenignLines(t *testing.T) {
	content := "echo starting\n" +
		"password: hunter2hunter2\n" +
		"echo done\n"

	rendered := renderAttachedScript([]byte(content))

	if !strings.Contains(rendered, "echo starting") || !strings.Contains(rendered, "echo done") {
		t.Errorf("only the secret line should be redacted; benign lines must remain, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "hunter2hunter2") {
		t.Errorf("secret value must be redacted, got:\n%s", rendered)
	}
}

// looksLikeSecret recognizes a credential assignment.
func TestLooksLikeSecretMatchesCredentialAssignment(t *testing.T) {
	if !looksLikeSecret(`api_key = "sk-live-abcdef0123456789"`) {
		t.Error("an api_key assignment with a long value should be flagged as a secret")
	}
}

// looksLikeSecret must not flag an ordinary command line — over-redaction
// would blind the classifier to real behavior.
func TestLooksLikeSecretIgnoresBenignLine(t *testing.T) {
	if looksLikeSecret("kubectl get pods --namespace default") {
		t.Error("an ordinary read-only command must not be flagged as a secret")
	}
}

// End-to-end through the attach path: an in-root script the command provably
// executes has its secret line redacted in the assembled classifier prompt,
// and its benign lines preserved.
func TestBuildAnalyzePromptRedactsInRootScriptSecret(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\n" +
		"echo deploying\n" +
		"AWS_SECRET=AKIA0123456789ABCDEF\n" +
		"echo finished\n"
	if err := os.WriteFile(filepath.Join(dir, "deploy.sh"), []byte(script), 0644); err != nil {
		t.Fatal(err)
	}

	// `bash deploy.sh` with cwd=dir makes deploy.sh the proven executed file,
	// so it attaches as an in-root script.
	prompt := BuildAnalyzePrompt("bash deploy.sh", dir)

	if !strings.Contains(prompt, secretRedactionMarker) {
		t.Errorf("in-root attached script's secret line should be redacted in the prompt, got:\n%s", prompt)
	}
	if strings.Contains(prompt, "AKIA0123456789ABCDEF") {
		t.Errorf("the AWS key must not reach the classifier prompt, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "echo deploying") || !strings.Contains(prompt, "echo finished") {
		t.Errorf("benign lines of the attached script should remain, got:\n%s", prompt)
	}
}

// resolveTimeoutSeconds resolution order: cfg.Timeout > default, then the
// env var named by TimeoutEnvKey overrides — and a custom key (escalation)
// must be isolated from LLM_TIMEOUT (primary knob).
func TestResolveTimeoutSeconds(t *testing.T) {
	os.Unsetenv("LLM_TIMEOUT")
	if got := resolveTimeoutSeconds(LLMConfig{}, 10); got != 10 {
		t.Errorf("default: got %d, want 10", got)
	}
	if got := resolveTimeoutSeconds(LLMConfig{Timeout: 25}, 10); got != 25 {
		t.Errorf("cfg.Timeout: got %d, want 25", got)
	}

	t.Setenv("LLM_TIMEOUT", "7")
	if got := resolveTimeoutSeconds(LLMConfig{Timeout: 25}, 10); got != 7 {
		t.Errorf("LLM_TIMEOUT override: got %d, want 7", got)
	}

	t.Setenv("LLM_ESCALATION_TIMEOUT", "42")
	esc := LLMConfig{Timeout: 25, TimeoutEnvKey: "LLM_ESCALATION_TIMEOUT"}
	if got := resolveTimeoutSeconds(esc, 10); got != 42 {
		t.Errorf("custom TimeoutEnvKey: got %d, want 42", got)
	}
	// And the custom key must NOT read LLM_TIMEOUT.
	t.Setenv("LLM_ESCALATION_TIMEOUT", "")
	if got := resolveTimeoutSeconds(esc, 10); got != 25 {
		t.Errorf("custom key isolation: got %d, want 25 (cfg), not 7 (LLM_TIMEOUT)", got)
	}
}

// callClaudeCLI must kill a hung `claude` process at the resolved timeout
// instead of blocking the hook until the harness's own kill.
func TestCallClaudeCLITimeout(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "claude")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n/bin/sleep 30\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	start := time.Now()
	_, err := callClaudeCLI(LLMConfig{URL: "claude-cli", Model: "m", Timeout: 1}, "sys", "user")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("error should mention timeout, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("call should return ~1s after timeout, took %v", elapsed)
	}
}
