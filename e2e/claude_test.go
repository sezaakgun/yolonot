//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Claude Code in print mode with prompts disabled: an ask can't reach a
// human, so it must not run the command.
func TestClaudeCLI(t *testing.T) {
	claude := hostBinary(t, "claude")
	hostVersion(t, claude, "--version")
	for _, c := range []struct {
		name, policy, decision string
		marker                 bool
	}{
		{"allow", "allow", "allow", true},
		{"deny", "deny", "deny", false},
		{"ask", "ask", "ask", false},
		// A missing hook binary must block (onFailure: block), not fail open.
		{"broken-hook", "allow", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSandbox(t, c.policy)
			model := newModelServer(t, s.Command())
			s.Env = append(s.Env, "ANTHROPIC_BASE_URL="+model.URL)
			s.write(".claude/settings.json", `{"permissions":{"allow":["Bash(*)"]}}`)
			s.Install("claude")
			if c.name == "broken-hook" {
				b, _ := os.ReadFile(s.path(".claude/settings.json"))
				q, _ := json.Marshal(yolonotBin)
				if !strings.Contains(string(b), string(q)) {
					t.Fatalf("hook command not found:\n%s", b)
				}
				s.write(".claude/settings.json", strings.ReplaceAll(string(b), string(q), `"`+s.path("missing-hook")+`"`))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, claude, "-p", "Run exactly this Bash command once, then reply done: "+s.Command(),
				"--no-session-persistence", "--setting-sources", "user", "--strict-mcp-config", "--mcp-config", `{"mcpServers":{}}`,
				"--model", "claude-sonnet-4-5", "--permission-mode", "manual", "--permission-prompts", "none",
				"--tools", "Bash", "--output-format", "stream-json", "--verbose", "--include-hook-events")
			cmd.Dir, cmd.Env = s.Work, s.Env
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("claude timed out\n%s", tail(string(out)))
			}
			if err != nil {
				t.Logf("claude exit: %v", err)
			}
			if model.Generations.Load() == 0 {
				t.Fatalf("claude never called the fixture model\n%s", tail(string(out)))
			}
			if c.name == "broken-hook" && !strings.Contains(string(out), "PreToolUse:Bash hook error") {
				t.Errorf("tool call was not blocked by the failed hook\n%s", tail(string(out)))
			}
			s.expect(c.marker, c.decision, string(out))
		})
	}
}

// The skill installed by `--skill-only` reaches the model's skill listing.
func TestClaudeSkillDiscovery(t *testing.T) {
	claude := hostBinary(t, "claude")
	s := newSandbox(t, "")
	model := newModelServer(t, "true")
	s.Env = append(s.Env, "ANTHROPIC_BASE_URL="+model.URL)
	if out, err := s.run(s.Work, yolonotBin, "install", "--skill-only", "--harness", "claude"); err != nil {
		t.Fatalf("install --skill-only: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, claude, "-p", "Reply done.", "--no-session-persistence", "--setting-sources", "user",
		"--strict-mcp-config", "--mcp-config", `{"mcpServers":{}}`, "--model", "claude-sonnet-4-5", "--permission-prompts", "none")
	cmd.Dir, cmd.Env = s.Work, s.Env
	out, _ := cmd.CombinedOutput()
	if !model.Saw("Manage yolonot command safety policy") {
		t.Fatalf("yolonot skill not offered to the model\n%s", tail(string(out)))
	}
}
