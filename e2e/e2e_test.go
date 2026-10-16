//go:build e2e

// Package e2e drives real agent hosts (Claude Code, Codex, OpenCode, …)
// against a freshly built yolonot binary. Each case runs in an isolated
// HOME with a scripted local model, so no account or network is needed
// unless a test says otherwise. Run: go test -tags e2e ./e2e/... -v
package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

var yolonotBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "yolonot-e2e-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	yolonotBin = filepath.Join(dir, "yolonot")
	build := exec.Command("go", "build", "-o", yolonotBin, "..")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build yolonot:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// hostBinary finds a host CLI: $YOLONOT_E2E_<NAME> first, then PATH.
// Missing hosts skip the test.
func hostBinary(t *testing.T, name string) string {
	t.Helper()
	if p := os.Getenv("YOLONOT_E2E_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); p != "" {
		return p
	}
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not installed", name)
	}
	return p
}

func hostVersion(t *testing.T, bin string, args ...string) {
	t.Helper()
	out, _ := exec.Command(bin, args...).CombinedOutput()
	t.Logf("%s %s", filepath.Base(bin), strings.TrimSpace(string(out)))
}

// sandbox is one isolated case: HOME, a work dir, a marker the command
// touches, and yolonot rules that decide the marker command.
type sandbox struct {
	t      *testing.T
	Home   string
	Work   string
	Marker string
	Env    []string
}

func newSandbox(t *testing.T, policy string) *sandbox {
	t.Helper()
	home := t.TempDir()
	// Resolve /var → /private/var on macOS so hosts and yolonot agree on cwd.
	home, _ = filepath.EvalSymlinks(home)
	s := &sandbox{t: t, Home: home, Work: filepath.Join(home, "work")}
	s.Marker = filepath.Join(s.Work, "marker.txt")
	for _, d := range []string{s.Work, ".yolonot", ".claude", ".codex"} {
		s.mkdir(d)
	}
	s.write(".yolonot/config.json", `{"config_version":1,"judges":[]}`)
	if policy != "" {
		s.Rules(policy)
	}
	for _, k := range []string{"PATH", "TMPDIR", "LANG", "TERM"} {
		if v, ok := os.LookupEnv(k); ok {
			s.Env = append(s.Env, k+"="+v)
		}
	}
	s.Env = append(s.Env,
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"XDG_DATA_HOME="+filepath.Join(home, ".local/share"),
		"XDG_STATE_HOME="+filepath.Join(home, ".local/state"),
		"CODEX_HOME="+filepath.Join(home, ".codex"),
		"CLAUDE_CONFIG_DIR="+filepath.Join(home, ".claude"),
		"OPENAI_API_KEY=fixture-local-only",
		"ANTHROPIC_API_KEY=fixture-local-only",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"DISABLE_AUTOUPDATER=1",
	)
	return s
}

func (s *sandbox) path(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(s.Home, rel)
}

func (s *sandbox) mkdir(rel string) {
	if err := os.MkdirAll(s.path(rel), 0o755); err != nil {
		s.t.Fatal(err)
	}
}

func (s *sandbox) write(rel, content string) {
	s.t.Helper()
	p := s.path(rel)
	s.mkdir(filepath.Dir(p))
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

// Rules sets the global yolonot verdict for the marker command.
func (s *sandbox) Rules(policy string) { s.write(".yolonot/rules", policy+"-cmd touch *\n") }

func (s *sandbox) Command() string { return "touch '" + s.Marker + "'" }

func (s *sandbox) run(dir string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Env = dir, s.Env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (s *sandbox) Install(harness string) {
	s.t.Helper()
	if out, err := s.run(s.Work, yolonotBin, "install", "--harness", harness); err != nil {
		s.t.Fatalf("yolonot install --harness %s: %v\n%s", harness, err, out)
	}
}

func (s *sandbox) MarkerExists() bool {
	_, err := os.Stat(s.Marker)
	return err == nil
}

// Decisions returns yolonot's decision log entries for the marker command.
func (s *sandbox) Decisions() []map[string]any {
	f, err := os.Open(s.path(".yolonot/decisions.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 8<<20)
	for sc.Scan() {
		var e map[string]any
		if json.Unmarshal(sc.Bytes(), &e) == nil && strings.Contains(fmt.Sprint(e["command"]), s.Marker) {
			out = append(out, e)
		}
	}
	return out
}

// expect checks the marker and that yolonot logged the wanted decision.
func (s *sandbox) expect(wantMarker bool, wantDecision string, log string) {
	s.t.Helper()
	if got := s.MarkerExists(); got != wantMarker {
		s.t.Errorf("marker exists=%v, want %v\n%s", got, wantMarker, tail(log))
	}
	if wantDecision == "" {
		if d := s.Decisions(); len(d) != 0 {
			s.t.Errorf("hook ran, want none: %v", d)
		}
		return
	}
	for _, d := range s.Decisions() {
		if d["decision"] == wantDecision {
			return
		}
	}
	s.t.Errorf("no %q decision for marker command; log=%v\n%s", wantDecision, s.Decisions(), tail(log))
}

func tail(s string) string {
	if len(s) > 2000 {
		return "…" + s[len(s)-2000:]
	}
	return s
}

// modelServer scripts one tool call (the marker command) on the first
// generation and a plain text reply afterwards. It speaks the Anthropic
// Messages and OpenAI Responses streaming formats.
type modelServer struct {
	*httptest.Server
	Command     string
	Escalated   bool
	Cwd         string // working directory for tool calls that carry one
	Generations atomic.Int32
	ChatCalls   atomic.Int32
	mu          sync.Mutex
	bodies      []string
}

// Saw reports whether any request the host sent contained text.
func (m *modelServer) Saw(text string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.bodies {
		if strings.Contains(b, text) {
			return true
		}
	}
	return false
}

// ChatReply is what yolonot's own chat model (judge or Explain) receives.
const ChatReply = "EXPLAIN-FIXTURE touch creates an empty marker file."

// chatModelConfig makes the fixture server yolonot's chat model.
func (s *sandbox) chatModelConfig(m *modelServer) {
	s.write(".yolonot/config.json", `{"config_version":1,"models":{"fixture":{"url":"`+m.URL+`/v1/chat/completions","model":"fixture-chat","protocol":"chat","env_key":"OPENAI_API_KEY"}},"judges":["fixture"]}`)
}

func newModelServer(t *testing.T, command string) *modelServer {
	m := &modelServer{Command: command}
	m.Server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.Close)
	return m
}

func (m *modelServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[{"id":"fixture-model","object":"model"}]}`))
		return
	}
	raw, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	m.bodies = append(m.bodies, string(raw))
	m.mu.Unlock()
	var body map[string]any
	json.Unmarshal(raw, &body)
	switch {
	case strings.HasSuffix(r.URL.Path, "/count_tokens"):
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"input_tokens":50}`))
	case strings.HasSuffix(r.URL.Path, "/chat/completions"):
		m.ChatCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"chat_fixture","object":"chat.completion","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"` + ChatReply + `"}}]}`))
	case strings.HasSuffix(r.URL.Path, ":streamGenerateContent"):
		m.gemini(w, body)
	case strings.Contains(r.URL.Path, "/messages"):
		m.anthropic(w, body)
	default:
		m.responses(w)
	}
}

func sse(w http.ResponseWriter, events []map[string]any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	for _, e := range events {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e["type"], b)
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

type obj = map[string]any

// wantsTool reports whether an Anthropic request should get the scripted
// tool call: Bash is offered and there are more user prompts than tool
// calls so far (one call per prompt). Claude merges and reorders blocks
// across turns, so counting is the only stable signal. Side requests
// (titles, summaries) offer no tools and get plain text.
func wantsTool(body obj) bool {
	offered := false
	tools, _ := body["tools"].([]any)
	for _, t := range tools {
		if tm, _ := t.(obj); tm["name"] == "Bash" {
			offered = true
		}
	}
	prompts, calls := 0, 0
	msgs, _ := body["messages"].([]any)
	for _, m := range msgs {
		mm, _ := m.(obj)
		blocks, _ := mm["content"].([]any)
		if text, ok := mm["content"].(string); ok {
			blocks = []any{obj{"type": "text", "text": text}}
		}
		for _, b := range blocks {
			bm, _ := b.(obj)
			text, _ := bm["text"].(string)
			switch {
			case mm["role"] == "assistant" && bm["type"] == "tool_use":
				calls++
			case mm["role"] == "user" && bm["type"] == "text" && !strings.HasPrefix(text, "<system-reminder>"):
				prompts++
			}
		}
	}
	return offered && prompts > calls
}

func (m *modelServer) anthropic(w http.ResponseWriter, body obj) {
	n := m.Generations.Add(1)
	tool := wantsTool(body)
	if os.Getenv("YOLONOT_E2E_DEBUG") != "" {
		msgs, _ := body["messages"].([]any)
		var shape []string
		for _, mm := range msgs {
			mm := mm.(obj)
			var types []string
			if bl, ok := mm["content"].([]any); ok {
				for _, b := range bl {
					bm := b.(obj)
					t := fmt.Sprint(bm["type"])
					if t == "text" {
						t += fmt.Sprintf("(%.30q)", bm["text"])
					}
					types = append(types, t)
				}
			} else {
				types = append(types, "str")
			}
			shape = append(shape, fmt.Sprint(mm["role"], types))
		}
		tools, _ := body["tools"].([]any)
		fmt.Fprintf(os.Stderr, "model req %d tool=%v ntools=%d %v\n", n, tool, len(tools), shape)
	}
	block := obj{"type": "text", "text": ""}
	delta := obj{"type": "text_delta", "text": "Fixture finished."}
	stop := "end_turn"
	if tool {
		input, _ := json.Marshal(obj{"command": m.Command, "description": "Write an isolated test marker"})
		block = obj{"type": "tool_use", "id": fmt.Sprintf("toolu_fixture_%d", n), "name": "Bash", "input": obj{}}
		delta = obj{"type": "input_json_delta", "partial_json": string(input)}
		stop = "tool_use"
	}
	model, _ := body["model"].(string)
	sse(w, []obj{
		{"type": "message_start", "message": obj{"id": "msg_fixture", "type": "message", "role": "assistant", "content": []any{}, "model": model, "stop_reason": nil, "stop_sequence": nil, "usage": obj{"input_tokens": 50, "output_tokens": 1}}},
		{"type": "content_block_start", "index": 0, "content_block": block},
		{"type": "content_block_delta", "index": 0, "delta": delta},
		{"type": "content_block_stop", "index": 0},
		{"type": "message_delta", "delta": obj{"stop_reason": stop, "stop_sequence": nil}, "usage": obj{"output_tokens": 10}},
		{"type": "message_stop"},
	})
}

func (m *modelServer) responses(w http.ResponseWriter) {
	n := m.Generations.Add(1)
	resp := obj{"id": fmt.Sprintf("resp_fixture_%d", n), "object": "response", "created_at": 0, "status": "in_progress", "output": []any{}, "usage": obj{"input_tokens": 50, "output_tokens": 10, "total_tokens": 60}}
	created := obj{"type": "response.created", "response": resp}
	var item obj
	if n == 1 {
		args := obj{"cmd": m.Command, "yield_time_ms": 1000}
		if m.Escalated {
			args["sandbox_permissions"] = "require_escalated"
			args["justification"] = "Allow isolated temporary marker test"
		}
		b, _ := json.Marshal(args)
		item = obj{"id": "fc_fixture", "type": "function_call", "call_id": "call_fixture", "name": "exec_command", "arguments": string(b)}
	} else {
		item = obj{"id": "msg_fixture", "type": "message", "role": "assistant", "content": []any{obj{"type": "output_text", "text": "Fixture finished.", "annotations": []any{}}}}
	}
	done := obj{}
	for k, v := range resp {
		done[k] = v
	}
	done["status"], done["output"] = "completed", []any{item}
	sse(w, []obj{
		created,
		{"type": "response.output_item.added", "output_index": 0, "item": item},
		{"type": "response.output_item.done", "output_index": 0, "item": item},
		{"type": "response.completed", "response": done},
	})
}

// gemini answers the Gemini API stream (Antigravity with GEMINI_API_KEY):
// one run_command call per user prompt, then text.
func (m *modelServer) gemini(w http.ResponseWriter, body obj) {
	m.Generations.Add(1)
	offered := false
	tools, _ := body["tools"].([]any)
	for _, t := range tools {
		decls, _ := t.(obj)["functionDeclarations"].([]any)
		for _, d := range decls {
			if d.(obj)["name"] == "run_command" {
				offered = true
			}
		}
	}
	prompts, calls := 0, 0
	contents, _ := body["contents"].([]any)
	for _, c := range contents {
		cm, _ := c.(obj)
		parts, _ := cm["parts"].([]any)
		text, response := false, false
		for _, p := range parts {
			pm, _ := p.(obj)
			if pm["functionCall"] != nil {
				calls++
			}
			if pm["functionResponse"] != nil {
				response = true
			}
			if pm["text"] != nil {
				text = true
			}
		}
		if cm["role"] == "user" && text && !response {
			prompts++
		}
	}
	part := obj{"text": "Fixture finished."}
	if offered && prompts > calls {
		cwd, _ := os.Getwd()
		if wd := m.Cwd; wd != "" {
			cwd = wd
		}
		part = obj{"functionCall": obj{"name": "run_command", "args": obj{
			"CommandLine": m.Command, "Cwd": cwd, "WaitMsBeforeAsync": 5000,
			"toolSummary": "Create marker", "toolAction": "Running touch command",
		}}}
	}
	b, _ := json.Marshal(obj{
		"candidates":    []any{obj{"content": obj{"role": "model", "parts": []any{part}}, "finishReason": "STOP", "index": 0}},
		"usageMetadata": obj{"promptTokenCount": 50, "candidatesTokenCount": 10, "totalTokenCount": 60},
	})
	w.Header().Set("Content-Type", "text/event-stream")
	fmt.Fprintf(w, "data: %s\n\n", b)
}
