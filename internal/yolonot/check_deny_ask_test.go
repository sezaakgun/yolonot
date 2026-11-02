package yolonot

import (
	"strings"
	"testing"
)

func TestCheckAndHookAgreeOnDenyOutsideMay(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	isolateEscalationEnv(t)
	t.Setenv("YOLONOT_HARNESS", "claude")
	t.Chdir(t.TempDir())
	llm := mockLLMRisk("deny", "critical", "custom prompt said deny", nil)
	defer llm.Close()
	SaveConfig(Config{Provider: ProviderConfig{URL: llm.URL, Model: "chat", Timeout: 5}, Judges: []JudgeSpec{{Use: "llm", May: []string{"allow", "ask"}}}})

	const command = "some-novel-tool --flag"
	out := runHookWithStruct(t, makePrePayload("check-deny-ask", command, t.TempDir()))
	if got := parseResponse(t, out).HookSpecificOutput.PermissionDecision; got != "ask" {
		t.Fatalf("hook: want ask, got %q (%s)", got, out)
	}
	checkOut := captureStdout(func() { cmdCheck(command) })
	if !strings.Contains(checkOut, "→ Result: ASK") {
		t.Fatalf("check must agree with the hook (ASK), got:\n%s", checkOut)
	}
}
