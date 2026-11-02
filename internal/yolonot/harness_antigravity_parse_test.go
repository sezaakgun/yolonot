package yolonot

import (
	"os"
	"strings"
	"testing"
)

func TestAntigravityUnreadableRunCommandIsDenied(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "antigravity")
	multiRoot := `{"conversationId":"c1","workspacePaths":["/a","/b"],"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf build"}}}`
	if out := runHookWithPayload(t, multiRoot); !strings.Contains(out, `"decision":"deny"`) {
		t.Fatalf("ambiguous cwd was not denied: %q", out)
	}
	post := `{"conversationId":"c1","workspacePaths":["/a","/b"],"hookEventName":"PostToolUse","toolCall":{"name":"run_command","args":{"CommandLine":"ls"}}}`
	if out := runHookWithPayload(t, post); strings.TrimSpace(out) != "" {
		t.Fatalf("PostToolUse parse failure must stay silent: %q", out)
	}
}

func TestAntigravityParseFailureEdges(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "antigravity")
	args := os.Args
	t.Cleanup(func() { os.Args = args })
	broken := `{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"`

	os.Args = []string{"yolonot", "hook", "--harness", "antigravity"}
	if out := runHookWithPayload(t, broken); !strings.Contains(out, `"decision":"deny"`) {
		t.Fatalf("broken PreToolUse input was not denied: %q", out)
	}
	os.Args = []string{"yolonot", "hook", "--harness", "antigravity", "--hook-event", "PostToolUse"}
	if out := runHookWithPayload(t, broken); strings.TrimSpace(out) != "" {
		t.Fatalf("broken PostToolUse input must stay silent: %q", out)
	}
	os.Args = []string{"yolonot", "hook", "--harness", "antigravity"}
	t.Setenv("YOLONOT_DISABLED", "1")
	if out := runHookWithPayload(t, broken); strings.TrimSpace(out) != "" {
		t.Fatalf("disabled yolonot still answered: %q", out)
	}
}
