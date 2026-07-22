package yolonot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newClassifyProbeServer stands up a fake OpenAI-compatible endpoint that
// records every request body and always returns a valid allow verdict. The
// recorded bodies let a test see exactly what BuildAnalyzePrompt shipped —
// including any attached script contents — through the real CallLLM path
// (Classify uses CallLLM directly, with no mockable indirection).
func newClassifyProbeServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": `{"decision":"allow","risk":"safe","short":"probe","reasoning":"probe"}`}},
			},
		})
	}))
	t.Cleanup(server.Close)
	return server, &bodies
}

// TestLLMClassifyAttachesOutsideScriptWhenFlagOn asserts the attach-boundary
// line LLMClassifier.Classify runs (attachOutsideRoot =
// userCfg.AttachOutsideRoot) reaches the assembled prompt: with
// attach_outside_root=true, classifying a command that runs a script OUTSIDE
// the project root sends that script's contents to the provider. Classify was
// a thin wrapper over BuildAnalyzePrompt with no dedicated attach assertion.
func TestLLMClassifyAttachesOutsideScriptWhenFlagOn(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	// Force config-resolved provider (env must not override the test server).
	t.Setenv("LLM_URL", "")
	t.Setenv("LLM_MODEL", "")

	server, bodies := newClassifyProbeServer(t)

	outside := t.TempDir()
	scriptPath := filepath.Join(outside, "tool.py")
	if err := os.WriteFile(scriptPath, []byte("print('CLASSIFY-OUTSIDE-MARKER')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	projectDir := t.TempDir() // the attach root; the script lives in a sibling temp dir

	SaveConfig(Config{Provider: ProviderConfig{URL: server.URL, Model: "test"}, AttachOutsideRoot: true})
	attachOutsideRoot = false // fresh-process simulation; only Classify's config load may open it
	t.Cleanup(func() { attachOutsideRoot = false })

	res, err := (&LLMClassifier{}).Classify(context.Background(), "python3 "+scriptPath, ClassifyMeta{Cwd: projectDir})
	if err != nil {
		t.Fatalf("Classify returned error: %v", err)
	}
	if res.Decision != "allow" {
		t.Errorf("RiskResult.Decision: got %q, want allow", res.Decision)
	}
	if res.Backend != "llm" {
		t.Errorf("RiskResult.Backend: got %q, want llm", res.Backend)
	}
	if len(*bodies) != 1 {
		t.Fatalf("expected one provider call, got %d", len(*bodies))
	}
	if !strings.Contains((*bodies)[0], "CLASSIFY-OUTSIDE-MARKER") {
		t.Errorf("attach_outside_root=true should attach the outside script through Classify; body:\n%s", (*bodies)[0])
	}
}

// TestLLMClassifyWithholdsOutsideScriptWhenFlagOff is the closed-boundary half:
// with no attach_outside_root the outside script is withheld from the provider
// request and a withheld note stands in for it. Pre-setting
// attachOutsideRoot=true proves Classify's config load closes it back.
func TestLLMClassifyWithholdsOutsideScriptWhenFlagOff(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("LLM_URL", "")
	t.Setenv("LLM_MODEL", "")

	server, bodies := newClassifyProbeServer(t)

	outside := t.TempDir()
	scriptPath := filepath.Join(outside, "tool.py")
	if err := os.WriteFile(scriptPath, []byte("print('CLASSIFY-OUTSIDE-MARKER')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	projectDir := t.TempDir()

	// No AttachOutsideRoot → boundary stays closed.
	SaveConfig(Config{Provider: ProviderConfig{URL: server.URL, Model: "test"}})
	attachOutsideRoot = true // must be closed back by the config load
	t.Cleanup(func() { attachOutsideRoot = false })

	if _, err := (&LLMClassifier{}).Classify(context.Background(), "python3 "+scriptPath, ClassifyMeta{Cwd: projectDir}); err != nil {
		t.Fatalf("Classify returned error: %v", err)
	}
	if len(*bodies) != 1 {
		t.Fatalf("expected one provider call, got %d", len(*bodies))
	}
	if strings.Contains((*bodies)[0], "CLASSIFY-OUTSIDE-MARKER") {
		t.Errorf("closed boundary must withhold the outside script; body:\n%s", (*bodies)[0])
	}
	if !strings.Contains((*bodies)[0], "not attached") {
		t.Errorf("closed boundary should carry a withheld note for the outside script; body:\n%s", (*bodies)[0])
	}
}
