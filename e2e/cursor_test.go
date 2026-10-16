//go:build e2e

package e2e

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// cursorBackend fakes the slice of Cursor's backend a CLI run needs. The
// CLI talks Connect/protobuf: unary calls over HTTP/1.1, and the agent loop
// (agent.v1.AgentService/Run) as a bidi stream over cleartext HTTP/2.
// Messages are hand-encoded; field numbers come from the schema strings
// embedded in the CLI bundle (e.g. "ShellArgs|1 command 9|2 working_directory 9|…")
// and must be re-checked when a new CLI version breaks this.
type cursorBackend struct {
	*httptest.Server
	command, cwd string
	runs         atomic.Int32
}

func pbVarint(n int) []byte {
	var out []byte
	for ; n >= 0x80; n >>= 7 {
		out = append(out, byte(n)|0x80)
	}
	return append(out, byte(n))
}

// pbBytes encodes a length-delimited field.
func pbBytes(field int, b []byte) []byte {
	return append(append([]byte{byte(field<<3 | 2)}, pbVarint(len(b))...), b...)
}

func pbStr(field int, s string) []byte { return pbBytes(field, []byte(s)) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func newCursorBackend(t *testing.T, command, cwd string) *cursorBackend {
	b := &cursorBackend{command: command, cwd: cwd}
	model := cat(pbStr(1, "fake-model"), pbStr(3, "fake-model"), pbStr(4, "Fake Model"), pbStr(5, "Fake"))
	unary := map[string][]byte{
		"/aiserver.v1.AiService/GetUsableModels":       pbBytes(1, model),
		"/aiserver.v1.AiService/GetDefaultModelForCli": pbBytes(1, model),
		"/agent.v1.AgentService/GetUsableModels":       pbBytes(1, model),
		"/agent.v1.AgentService/GetDefaultModelForCli": pbBytes(1, model),
	}
	b.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "application/connect+") {
			b.run(w, r, ct)
			return
		}
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/proto")
		w.Write(unary[r.URL.Path]) // every other call accepts an empty message
	}))
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	b.Config.Protocols = p
	b.Start()
	t.Cleanup(b.Close)
	return b
}

// run answers one agent turn: a shell exec of the marker command, then a
// text delta, a turn-ended update and the end of the stream.
func (b *cursorBackend) run(w http.ResponseWriter, r *http.Request, ct string) {
	b.runs.Add(1)
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	flush := w.(http.Flusher).Flush
	flush()
	read := func() []byte { // one Connect frame from the client, nil at EOF
		head := make([]byte, 5)
		if _, err := io.ReadFull(r.Body, head); err != nil {
			return nil
		}
		msg := make([]byte, int(head[1])<<24|int(head[2])<<16|int(head[3])<<8|int(head[4]))
		io.ReadFull(r.Body, msg)
		return msg
	}
	send := func(m []byte) {
		w.Write(append([]byte{0, byte(len(m) >> 24), byte(len(m) >> 16), byte(len(m) >> 8), byte(len(m))}, m...))
		flush()
	}
	read() // the run request
	// Only the first run executes; the interactive CLI starts further runs
	// of its own that must not add approvals.
	if b.runs.Load() == 1 {
		// ShellCommandParsingResult: without the parsed command the CLI
		// raises its own "possible bypass" prompt instead of the hook's.
		name, arg, _ := strings.Cut(b.command, " ")
		parsed := pbBytes(2, cat(pbStr(1, name), pbBytes(2, cat(pbStr(1, "word"), pbStr(2, arg))), pbStr(3, b.command)))
		shell := cat(pbStr(1, b.command), pbStr(2, b.cwd), []byte{0x18}, pbVarint(30000), pbStr(4, "call_1"), pbStr(5, name), pbBytes(8, parsed))
		exec := cat([]byte{0x08, 0x01}, pbStr(15, "exec_1"), pbBytes(2, shell))
		send(pbBytes(2, exec))
		// Wait for the shell result; 2-byte frames are heartbeats.
		for m := read(); m != nil && len(m) <= 2; m = read() {
		}
	}
	send(pbBytes(1, pbBytes(1, pbStr(1, "Fixture finished."))))
	send(pbBytes(1, pbBytes(14, nil)))
	time.Sleep(200 * time.Millisecond)
	w.Write([]byte{2, 0, 0, 0, 2, '{', '}'})
}

func cursorSandbox(t *testing.T, policy string, nativeAsk bool) (string, *sandbox, *cursorBackend) {
	t.Helper()
	bin := hostBinary(t, "cursor-agent")
	s := newSandbox(t, policy)
	backend := newCursorBackend(t, s.Command(), s.Work)
	s.Env = append(s.Env, "CURSOR_API_ENDPOINT="+backend.URL, "AGENT_CLI_E2E=true", "TERM=xterm-256color")
	if nativeAsk {
		s.Env = append(s.Env, "YOLONOT_CURSOR_NATIVE_ASK=1")
	}
	s.Install("cursor")
	return bin, s, backend
}

func cursorArgs(s *sandbox, backend *cursorBackend, extra ...string) []string {
	return append([]string{"--endpoint", backend.URL, "--repo-endpoint", backend.URL, "--trust", "--workspace", s.Work}, extra...)
}

// Cursor CLI headless with --force (without it the CLI's own permission
// layer refuses every command it cannot prompt for): deny still blocks, an
// ask defers to --force.
func TestCursorCLI(t *testing.T) {
	hostVersion(t, hostBinary(t, "cursor-agent"), "--version")
	for _, c := range []struct {
		policy string
		marker bool
	}{{"allow", true}, {"deny", false}, {"ask", true}} {
		t.Run(c.policy, func(t *testing.T) {
			bin, s, backend := cursorSandbox(t, c.policy, false)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, cursorArgs(s, backend, "--print", "--force", "--output-format", "stream-json", "Run the fixture command.")...)
			cmd.Dir, cmd.Env = s.Work, s.Env
			out, _ := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("cursor-agent timed out\n%s", tail(string(out)))
			}
			if backend.runs.Load() == 0 {
				t.Fatalf("cursor-agent never reached the fake backend\n%s", tail(string(out)))
			}
			s.expect(c.marker, c.policy, string(out))
		})
	}
}

// Native ask (opt-in) in the interactive CLI: Run once / Skip.
func TestCursorInteractiveAsk(t *testing.T) {
	for _, approve := range []bool{true, false} {
		t.Run(map[bool]string{true: "approved", false: "rejected"}[approve], func(t *testing.T) {
			bin, s, backend := cursorSandbox(t, "ask", true)
			x := startTmux(t, s, append([]string{bin}, cursorArgs(s, backend, "Run the fixture command.")...)...)
			var yes []string
			if approve {
				yes = []string{"y"}
			}
			interactiveAsk(t, s, s.Marker, x, "Hook requested approval", yes, []string{"n"}, func(string) {})
		})
	}
}
