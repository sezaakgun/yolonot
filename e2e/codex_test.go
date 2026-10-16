//go:build e2e

package e2e

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func codexConfig(s *sandbox, model *modelServer) {
	s.write(".codex/config.toml", `model="fixture-model"
model_provider="fixture"
approval_policy="on-request"
sandbox_mode="workspace-write"
[features]
hooks=true
shell_snapshot=false
[model_providers.fixture]
name="Local fixture"
base_url="`+model.URL+`/v1"
wire_api="responses"
requires_openai_auth=false
`)
}

// codex exec has no approver: an ask falls back to the sandbox (the marker
// is inside the writable workspace), an escalation request is refused, and
// untrusted hooks never run.
func TestCodexExec(t *testing.T) {
	codex := hostBinary(t, "codex")
	hostVersion(t, codex, "--version")
	for _, c := range []struct {
		name, policy, decision string
		escalated, untrusted   bool
		marker                 bool
	}{
		{"allow", "allow", "allow", false, false, true},
		{"deny", "deny", "deny", false, false, false},
		{"ask", "ask", "ask", false, false, true},
		{"escalated-allow", "allow", "allow", true, false, false},
		{"escalated-ask", "ask", "ask", true, false, false},
		{"untrusted-deny", "deny", "", false, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSandbox(t, c.policy)
			model := newModelServer(t, s.Command())
			model.Escalated = c.escalated
			codexConfig(s, model)
			s.Install("codex")
			args := []string{"--no-daemon", "exec", "--skip-git-repo-check", "--ephemeral", "-C", s.Work, "--json"}
			if !c.untrusted {
				args = append(args, "--dangerously-bypass-hook-trust")
			}
			args = append(args, "Run exactly this command once, then reply done: "+s.Command())
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, codex, args...)
			cmd.Dir, cmd.Env = s.Work, s.Env
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("codex timed out\n%s", tail(string(out)))
			}
			if err != nil {
				t.Logf("codex exit: %v", err)
			}
			if model.Generations.Load() == 0 {
				t.Fatalf("codex never called the fixture model\n%s", tail(string(out)))
			}
			s.expect(c.marker, c.decision, string(out))
		})
	}
}
