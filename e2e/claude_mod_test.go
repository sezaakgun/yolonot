//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

type tmux struct {
	t       *testing.T
	socket  string
	session string
}

func startTmux(t *testing.T, s *sandbox, argv ...string) *tmux {
	t.Helper()
	return startTmuxIn(t, s.Work, s.Env, argv...)
}

func needTmux(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not installed")
	}
}

func startTmuxIn(t *testing.T, dir string, env []string, argv ...string) *tmux {
	t.Helper()
	needTmux(t)
	x := &tmux{t: t, socket: fmt.Sprintf("yolonot-e2e-%d", time.Now().UnixNano()), session: "e2e"}
	args := []string{"-L", x.socket, "-f", "/dev/null", "new-session", "-d", "-s", x.session, "-x", "200", "-y", "50", "-c", dir, "env", "-i"}
	args = append(args, env...)
	args = append(args, argv...)
	if out, err := exec.Command("tmux", args...).CombinedOutput(); err != nil {
		t.Fatalf("tmux: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("screen:\n%s", x.capture())
		}
		exec.Command("tmux", "-L", x.socket, "kill-server").Run()
		time.Sleep(time.Second) // let the killed host stop writing before TempDir cleanup
	})
	return x
}

func (x *tmux) keys(keys ...string) {
	exec.Command("tmux", append([]string{"-L", x.socket, "send-keys", "-t", x.session}, keys...)...).Run()
}

func (x *tmux) typeLine(text string) {
	x.keys("-l", text)
	time.Sleep(300 * time.Millisecond)
	x.keys("Enter")
}

func (x *tmux) capture() string {
	out, _ := exec.Command("tmux", "-L", x.socket, "capture-pane", "-p", "-t", x.session, "-S", "-200").Output()
	return string(out)
}

func (x *tmux) waitFor(text string, timeout time.Duration) {
	x.t.Helper()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if strings.Contains(x.capture(), text) {
			return
		}
	}
	x.t.Fatalf("screen never showed %q", text)
}

// claudeState skips first-run screens: onboarding, API key approval and
// folder trust.
func claudeState(s *sandbox) {
	key := "fixture-local-only"
	s.write(".claude/.claude.json", fmt.Sprintf(`{"hasCompletedOnboarding":true,"theme":"dark","customApiKeyResponses":{"approved":[%q],"rejected":[]},"projects":{%q:{"hasTrustDialogAccepted":true,"hasCompletedProjectOnboarding":true}}}`, key[len(key)-min(20, len(key)):], s.Work))
}

func (s *sandbox) waitMarker(want bool, timeout time.Duration) bool {
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if s.MarkerExists() == want {
			return true
		}
	}
	return false
}

func (s *sandbox) layers() []string {
	var out []string
	for _, d := range s.Decisions() {
		out = append(out, fmt.Sprint(d["layer"], ":", d["decision"]))
	}
	return out
}

// startMod opens interactive Claude with the yolonot mod in tmux.
func startMod(t *testing.T, s *sandbox, model *modelServer, extra ...string) *tmux {
	t.Helper()
	claude := hostBinary(t, "claude")
	s.Env = append(s.Env, "ANTHROPIC_BASE_URL="+model.URL, "TERM=xterm-256color")
	s.Install("claude")
	if out, err := s.run(s.Work, yolonotBin, "install", "--harness", "claude", "--mod"); err != nil {
		t.Fatalf("install --mod: %v\n%s", err, out)
	}
	claudeState(s)
	args := append([]string{claude, "--setting-sources", "user", "--strict-mcp-config", "--mcp-config", `{"mcpServers":{}}`}, extra...)
	x := startTmux(t, s, args...)
	x.waitFor("❯", 30*time.Second)
	return x
}

// dialog waits until the mod dialog accepts keys.
func (x *tmux) dialog() {
	x.t.Helper()
	x.waitFor("Enter to select", 30*time.Second)
	time.Sleep(time.Second) // keys sent before the dialog mounts go to the prompt
}

// The mod dialog, driven through tmux. Each case asks twice for the same
// command: Allow once must prompt again, Allow this session must replay
// silently, Deny must block the repeat without a new dialog, and Explain
// must show the chat model's answer and return to the choices.
func TestClaudeModDialog(t *testing.T) {
	hostBinary(t, "claude")
	needTmux(t)
	for _, c := range []struct {
		name, choice, repeat string
		abs                  bool
		marker               bool
	}{
		{"allow-once", "1", "dialog", false, true},
		{"allow-session", "2", "session:allow", false, true},
		{"deny", "4", "session_deny:deny", false, false},
		{"explain-then-deny", "3", "session_deny:deny", false, false},
		// An absolute native executable is snapshotted, so its session
		// grant replays while the binary is unchanged.
		{"absolute-native-session", "2", "session:allow", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSandbox(t, "ask")
			command := s.Command()
			if c.abs {
				s.write(".yolonot/rules", "ask-cmd /usr/bin/touch *\n")
				command = "/usr/bin/touch " + s.Marker
			}
			model := newModelServer(t, command)
			s.chatModelConfig(model)
			x := startMod(t, s, model, "--model", "claude-sonnet-4-5", "--permission-mode", "default")
			x.typeLine("Run the fixture command.")
			x.dialog()
			if s.MarkerExists() {
				t.Fatal("command ran before the dialog was answered")
			}
			x.keys(c.choice)
			if c.choice == "3" {
				x.waitFor("EXPLAIN-FIXTURE", 20*time.Second)
				if model.ChatCalls.Load() == 0 {
					t.Fatal("Explain did not call the chat model")
				}
				x.dialog()
				x.keys("3") // Explain drops out of the menu; Deny is now 3
			}
			if !s.waitMarker(c.marker, 15*time.Second) {
				t.Fatalf("marker exists=%v, want %v; log=%v", s.MarkerExists(), c.marker, s.layers())
			}
			x.waitFor("done", 15*time.Second)
			os.Remove(s.Marker)
			before := len(s.layers())
			x.typeLine("Run the fixture command again.")
			if c.repeat == "dialog" {
				x.dialog()
				x.keys("4")
			}
			x.waitFor("again.", 5*time.Second)
			for deadline := time.Now().Add(20 * time.Second); len(s.layers()) == before && time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
			}
			time.Sleep(time.Second)
			repeat := s.layers()[before:]
			t.Logf("repeat decisions: %v", repeat)
			want := c.repeat
			if want == "dialog" {
				want = "rule:ask" // a fresh dialog, answered Deny above
			}
			if len(repeat) == 0 || repeat[0] != want {
				t.Errorf("repeat decided %v, want %s first", repeat, want)
			}
			if got, want := s.MarkerExists(), c.repeat == "session:allow"; got != want {
				t.Errorf("repeat marker exists=%v, want %v", got, want)
			}
		})
	}
}

// Claude's auto mode must not swallow yolonot: an ask still opens the mod
// dialog, and allow/deny rules still decide.
func TestClaudeModAutoMode(t *testing.T) {
	hostBinary(t, "claude")
	needTmux(t)
	for _, c := range []struct {
		policy, decision string
		marker           bool
	}{
		{"ask", "human:deny", false},
		{"allow", "rule:allow", true},
		{"deny", "rule:deny", false},
	} {
		t.Run(c.policy, func(t *testing.T) {
			s := newSandbox(t, c.policy)
			model := newModelServer(t, s.Command())
			x := startMod(t, s, model, "--model", "claude-opus-5-5", "--permission-mode", "auto")
			if strings.Contains(x.capture(), "auto mode unavailable") {
				t.Fatalf("auto mode unavailable:\n%s", x.capture())
			}
			x.typeLine("Run the fixture command.")
			if c.policy == "ask" {
				x.dialog()
				x.keys("4")
			}
			x.waitFor("done", 30*time.Second)
			if s.MarkerExists() != c.marker {
				t.Errorf("marker exists=%v, want %v", s.MarkerExists(), c.marker)
			}
			if !slices.Contains(s.layers(), c.decision) {
				t.Errorf("decisions %v lack %s", s.layers(), c.decision)
			}
		})
	}
}
