//go:build e2e

package e2e

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// agySandbox runs Antigravity against the scripted model through its
// direct Gemini API route: no sign-in, isolated HOME, installer-written hooks.
func agySandbox(t *testing.T, policy string) (string, *sandbox, *modelServer) {
	t.Helper()
	bin := hostBinary(t, "agy")
	s := newSandbox(t, policy)
	model := newModelServer(t, s.Command())
	model.Cwd = s.Work
	// Skip first-run screens (including the data-collection consent, left
	// unanswered) and trust the workspace.
	s.write(".gemini/antigravity-cli/settings.json", `{"modelProvider":"gemini","trustedWorkspaces":["`+s.Work+`"]}`)
	s.write(".gemini/antigravity-cli/cache/onboarding.json", `{"consumerOnboardingComplete":true,"onboardingComplete":true}`)
	s.Env = append(s.Env, "GEMINI_API_KEY=fixture-local-only", "GOOGLE_GEMINI_BASE_URL="+model.URL, "TERM=xterm-256color")
	s.Install("antigravity")
	return bin, s, model
}

// Headless: allow runs, deny blocks, an ask can't prompt and blocks.
func TestAntigravityCLI(t *testing.T) {
	hostVersion(t, hostBinary(t, "agy"), "--version")
	for _, c := range []struct {
		policy string
		marker bool
	}{{"allow", true}, {"deny", false}, {"ask", false}} {
		t.Run(c.policy, func(t *testing.T) {
			bin, s, model := agySandbox(t, c.policy)
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "-p", "Run the fixture command.", "--output-format", "json", "--print-timeout", "60s")
			cmd.Dir, cmd.Env = s.Work, s.Env
			out, _ := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("agy timed out\n%s", tail(string(out)))
			}
			if model.Generations.Load() == 0 {
				t.Fatalf("agy never called the fixture model\n%s", tail(string(out)))
			}
			s.expect(c.marker, c.policy, string(out))
		})
	}
}

func TestAntigravityInteractiveAsk(t *testing.T) {
	for _, approve := range []bool{true, false} {
		t.Run(map[bool]string{true: "approved", false: "rejected"}[approve], func(t *testing.T) {
			bin, s, _ := agySandbox(t, "ask")
			x := startTmux(t, s, bin, "-i", "Run the fixture command.")
			var yes []string
			if approve {
				yes = []string{"Enter"}
			}
			interactiveAsk(t, s, s.Marker, x, "Run this command?", yes, []string{"Down", "Down", "Down", "Enter"}, func(string) {})
		})
	}
}
