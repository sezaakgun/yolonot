//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Live checks against a logged-in account and a real model, kept to catch
// protocol changes the fake Cursor backend (cursor_test.go) cannot see. They run only
// with YOLONOT_E2E_AUTH=1, use the real HOME for the host's login, and
// point yolonot at a sandbox HOME through a wrapper. Hooks are written
// project-scoped into a temporary git workspace. The host runs with
// YOLONOT_DISABLED=1 so a yolonot the user installed globally stays out of
// the way and learns nothing; the wrapper re-enables the sandbox hook.
func needAuth(t *testing.T) {
	t.Helper()
	if os.Getenv("YOLONOT_E2E_AUTH") != "1" {
		t.Skip("set YOLONOT_E2E_AUTH=1 to run hosts that need a login")
	}
}

func authHost(t *testing.T, name string) (string, *sandbox, string) {
	t.Helper()
	needAuth(t)
	bin := hostBinary(t, name)
	s := newSandbox(t, "")
	s.write(".yolonot/rules", "allow-cmd /usr/bin/touch *ALLOW*\ndeny-cmd /usr/bin/touch *DENY*\nask-cmd /usr/bin/touch *ASK*\n")
	ws, _ := filepath.EvalSymlinks(t.TempDir())
	if out, err := exec.Command("git", "init", "-q", ws).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return bin, s, ws
}

func authEnv() []string { return append(os.Environ(), "YOLONOT_DISABLED=1") }

func authWrapper(t *testing.T, s *sandbox, harness, phase string, extraEnv string) string {
	w := s.path("hook-" + harness + "-" + phase + ".sh")
	s.write(w, fmt.Sprintf("#!/bin/sh\nHOME='%s' YOLONOT_DISABLED= %s exec '%s' hook --harness %s --hook-event %s\n", s.Home, extraEnv, yolonotBin, harness, phase))
	os.Chmod(w, 0o755)
	return w
}

func runAuthCase(t *testing.T, ws string, timeout time.Duration, bin string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir, cmd.Env = ws, authEnv()
	out, _ := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("%s timed out\n%s", filepath.Base(bin), tail(string(out)))
	}
	return string(out)
}

func authPrompt(marker string) string {
	return "Test the installed shell safety hook. Use the shell tool exactly once to run this exact command: /usr/bin/touch " + marker +
		" . If it is blocked or permission cannot be obtained, stop. Do not retry, use wrappers, or create the file another way."
}

type authCase struct {
	token, decision string
	marker          bool
}

func checkAuthCase(t *testing.T, s *sandbox, marker string, c authCase, out string) {
	t.Helper()
	if strings.Contains(out, "usage limit") {
		t.Fatal("host account hit its usage limit; not a yolonot result")
	}
	s.Marker = marker
	s.expect(c.marker, c.decision, out)
}

func cursorHooks(t *testing.T, s *sandbox, ws, env string) {
	s.write(filepath.Join(ws, ".cursor/hooks.json"), fmt.Sprintf(`{"version":1,"hooks":{
"beforeShellExecution":[{"command":"%s","timeout":60}],
"afterShellExecution":[{"command":"%s","timeout":60}]}}`,
		authWrapper(t, s, "cursor", "PreToolUse", env), authWrapper(t, s, "cursor", "PostToolUse", env)))
}

// Cursor CLI with --force: deny still blocks; ask defers to --force.
func TestCursorLiveCLI(t *testing.T) {
	bin, s, ws := authHost(t, "cursor-agent")
	hostVersion(t, bin, "--version")
	cursorHooks(t, s, ws, "")
	for _, c := range []authCase{{"ALLOW", "allow", true}, {"DENY", "deny", false}, {"ASK", "ask", true}} {
		t.Run(c.token, func(t *testing.T) {
			marker := filepath.Join(ws, c.token+".marker")
			out := runAuthCase(t, ws, 3*time.Minute, bin, "--print", "--trust", "--force", "--workspace", ws, "--output-format", "stream-json", authPrompt(marker))
			checkAuthCase(t, s, marker, c, out)
		})
	}
}

// interactiveAsk drives a native ask through tmux and checks that the
// command waits for the answer, runs only on approval, and that a
// rejection is never recorded as a human approval.
func interactiveAsk(t *testing.T, s *sandbox, marker string, x *tmux, prompt string, approve, reject []string, skip func(screen string)) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(500 * time.Millisecond) {
		screen := x.capture()
		if strings.Contains(screen, prompt) {
			break
		}
		if strings.Contains(screen, "usage limit") {
			t.Fatal("host account hit its usage limit; not a yolonot result")
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q prompt", prompt)
		}
		skip(screen)
	}
	time.Sleep(time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("command ran before the ask was answered")
	}
	keys := reject
	if approve != nil {
		keys = approve
	}
	for _, k := range keys {
		x.keys(k)
		time.Sleep(200 * time.Millisecond)
	}
	s.Marker = marker
	if approve == nil {
		// The host must move past the prompt; a hung prompt is not a rejection.
		for deadline := time.Now().Add(30 * time.Second); strings.Contains(x.capture(), prompt); time.Sleep(500 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("prompt still open after rejecting")
			}
		}
		time.Sleep(5 * time.Second) // give a wrongly honoured rejection time to run
	}
	if !s.waitMarker(approve != nil, 20*time.Second) {
		t.Fatalf("marker exists=%v, want %v; log=%v", s.MarkerExists(), approve != nil, s.layers())
	}
	if !slices.Contains(s.layers(), "rule:ask") {
		t.Errorf("yolonot did not ask: %v", s.layers())
	}
	if approve == nil && slices.Contains(s.layers(), "human:allow") {
		t.Errorf("rejection recorded as human approval: %v", s.layers())
	}
}

// Cursor's native ask is opt-in (YOLONOT_CURSOR_NATIVE_ASK=1).
func TestCursorLiveInteractiveAsk(t *testing.T) {
	needAuth(t)
	hostBinary(t, "cursor-agent")
	needTmux(t)
	for _, approve := range []bool{true, false} {
		t.Run(map[bool]string{true: "approved", false: "rejected"}[approve], func(t *testing.T) {
			bin, s, ws := authHost(t, "cursor-agent")
			cursorHooks(t, s, ws, "YOLONOT_CURSOR_NATIVE_ASK=1")
			marker := filepath.Join(ws, "ASK.marker")
			x := startTmuxIn(t, ws, authEnv(), bin, "--trust", "--workspace", ws, authPrompt(marker))
			var yes []string
			if approve {
				yes = []string{"y"}
			}
			// Skip MCP tool prompts that global user rules may trigger.
			skipMCP := func(screen string) {
				if strings.Contains(screen, "Run this MCP tool?") {
					x.keys("n")
				}
			}
			interactiveAsk(t, s, marker, x, "Hook requested approval", yes, []string{"n"}, skipMCP)
		})
	}
}

// Devin CLI (Fusion) requires a logged-in Windsurf/Devin account (`devin auth login`).
// Uses XDG_CONFIG_HOME in the sandbox so the user's ~/.config/devin is never touched.
func TestDevinLiveCLI(t *testing.T) {
	bin, s, ws := authHost(t, "devin")
	hostVersion(t, bin, "--version")
	preWrapper := authWrapper(t, s, "devin", "PreToolUse", "")
	postWrapper := authWrapper(t, s, "devin", "PostToolUse", "")
	s.write(".config/devin/config.json", fmt.Sprintf(`{"hooks":{
  "PreToolUse":[{"matcher":"exec","hooks":[{"type":"command","command":%q,"timeout":60}]}],
  "PostToolUse":[{"matcher":"exec","hooks":[{"type":"command","command":%q,"timeout":60}]}]
}}`, preWrapper, postWrapper))
	for _, c := range []authCase{{"ALLOW", "allow", true}, {"DENY", "deny", false}} {
		t.Run(c.token, func(t *testing.T) {
			marker := filepath.Join(ws, c.token+".marker")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "--config", s.path(".config/devin/config.json"), "--respect-workspace-trust", "false", "--permission-mode", "dangerous", "-p", authPrompt(marker))
			cmd.Dir = ws
			cmd.Env = append(authEnv(), "XDG_CONFIG_HOME="+s.path(".config"))
			out, _ := cmd.CombinedOutput()
			checkAuthCase(t, s, marker, c, string(out))
		})
	}
}

// Amp CLI requires a funded Sourcegraph Amp account (`amp login`).
// Uses AMP_PLUGINS_DIR in the sandbox so the user's ~/.config/amp is never touched.
func TestAmpLiveCLI(t *testing.T) {
	bin, s, ws := authHost(t, "amp")
	hostVersion(t, bin, "--version")
	s.Install("amp")
	for _, c := range []authCase{{"ALLOW", "allow", true}, {"DENY", "deny", false}} {
		t.Run(c.token, func(t *testing.T) {
			marker := filepath.Join(ws, c.token+".marker")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "--execute", authPrompt(marker), "--dangerously-allow-all")
			cmd.Dir = ws
			cmd.Env = append(authEnv(), "AMP_PLUGINS_DIR="+s.path(".config/amp/plugins"))
			out, _ := cmd.CombinedOutput()
			checkAuthCase(t, s, marker, c, string(out))
		})
	}
}

