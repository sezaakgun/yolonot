//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// extendedHostBinary finds a host CLI via $YOLONOT_E2E_<NAME>, PATH, ~/.local/bin, or optional fallback paths.
func extendedHostBinary(t *testing.T, name string, fallbacks ...string) string {
	t.Helper()
	if p := os.Getenv("YOLONOT_E2E_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); p != "" {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	realHome, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(realHome, ".local", "bin", name),
	}
	candidates = append(candidates, fallbacks...)
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	t.Skipf("%s not installed", name)
	return ""
}

// newMockToolServer creates a multi-protocol mock LLM server (OpenAI Chat Completions JSON+SSE,
// OpenAI Responses JSON+SSE, Anthropic Messages SSE, and Muse models list) that calls toolName
// on the first turn with toolArgs and returns "done" on subsequent turns.
func newMockToolServer(t *testing.T, toolName string, toolArgs map[string]any) *httptest.Server {
	t.Helper()
	var turn atomic.Int32
	argsBytes, _ := json.Marshal(toolArgs)
	argsStr := string(argsBytes)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)

		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "muse-code/models") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(obj{
				"object": "list",
				"data": []any{obj{
					"id":       "muse-spark-1.3",
					"object":   "model",
					"created":  1700000000,
					"owned_by": "meta",
					"metadata": obj{
						"name":                  "muse-spark-1.3",
						"family":                "muse-spark",
						"release_date":          "2026-09-02",
						"is_hidden":             false,
						"attachment":            false,
						"reasoning":             true,
						"tool_call":             true,
						"modalities":            obj{"input": []string{"text"}, "output": []string{"text"}},
						"limit":                 obj{"context": 1007997, "output": 128000},
						"options":               obj{},
						"roles":                 []any{},
						"cost":                  obj{"input": 1.25, "output": 4.25, "cached": 0.15},
						"variants":              []any{obj{"tier": "minimal", "selector": obj{"reasoningEffort": "minimal"}, "description": nil}},
						"background_agent_model": nil,
					},
				}},
			})
			return
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/models") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"gpt-4o-mini","object":"model"},{"id":"mock-model","object":"model"}]}`)
			return
		}

		var req map[string]any
		_ = json.Unmarshal(raw, &req)
		stream, _ := req["stream"].(bool)
		hasTools := strings.Contains(body, `"tools"`) && strings.Contains(body, `"`+toolName+`"`)

		// OpenAI /v1/responses
		if strings.HasSuffix(r.URL.Path, "/responses") {
			if !hasTools || turn.Add(1) > 1 {
				if stream {
					w.Header().Set("Content-Type", "text/event-stream")
					item := obj{"id": "msg_2", "type": "message", "status": "completed", "role": "assistant", "content": []any{obj{"type": "output_text", "text": "done", "annotations": []any{}}}}
					respObj := obj{"id": "resp_2", "object": "response", "created_at": 1700000000, "model": "muse-spark-1.3", "status": "completed", "output": []any{item}, "usage": obj{"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}}
					b1, _ := json.Marshal(obj{"type": "response.created", "sequence_number": 0, "response": obj{"id": "resp_2", "object": "response", "status": "in_progress", "output": []any{}}})
					b2, _ := json.Marshal(obj{"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": item})
					b3, _ := json.Marshal(obj{"type": "response.output_item.done", "sequence_number": 2, "output_index": 0, "item": item})
					b4, _ := json.Marshal(obj{"type": "response.completed", "sequence_number": 3, "response": respObj})
					fmt.Fprintf(w, "event: response.created\ndata: %s\n\nevent: response.output_item.added\ndata: %s\n\nevent: response.output_item.done\ndata: %s\n\nevent: response.completed\ndata: %s\n\ndata: [DONE]\n\n", b1, b2, b3, b4)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(obj{"id": "resp_2", "object": "response", "status": "completed", "output": []any{obj{"type": "message", "id": "msg_2", "status": "completed", "role": "assistant", "content": []any{obj{"type": "output_text", "text": "done"}}}}})
				return
			}
			itemAdded := obj{"id": "fc_1", "type": "function_call", "status": "in_progress", "call_id": "call_1", "name": toolName, "arguments": ""}
			itemDone := obj{"id": "fc_1", "type": "function_call", "status": "completed", "call_id": "call_1", "name": toolName, "arguments": argsStr}
			respObj := obj{"id": "resp_1", "object": "response", "created_at": 1700000000, "model": "muse-spark-1.3", "status": "completed", "output": []any{itemDone}, "usage": obj{"input_tokens": 10, "output_tokens": 10, "total_tokens": 20}}
			if stream {
				w.Header().Set("Content-Type", "text/event-stream")
				b1, _ := json.Marshal(obj{"type": "response.created", "sequence_number": 0, "response": obj{"id": "resp_1", "object": "response", "status": "in_progress", "output": []any{}}})
				b2, _ := json.Marshal(obj{"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": itemAdded})
				b3, _ := json.Marshal(obj{"type": "response.function_call_arguments.delta", "sequence_number": 2, "item_id": "fc_1", "output_index": 0, "delta": argsStr})
				b4, _ := json.Marshal(obj{"type": "response.function_call_arguments.done", "sequence_number": 3, "item_id": "fc_1", "output_index": 0, "arguments": argsStr})
				b5, _ := json.Marshal(obj{"type": "response.output_item.done", "sequence_number": 4, "output_index": 0, "item": itemDone})
				b6, _ := json.Marshal(obj{"type": "response.completed", "sequence_number": 5, "response": respObj})
				fmt.Fprintf(w, "event: response.created\ndata: %s\n\nevent: response.output_item.added\ndata: %s\n\nevent: response.function_call_arguments.delta\ndata: %s\n\nevent: response.function_call_arguments.done\ndata: %s\n\nevent: response.output_item.done\ndata: %s\n\nevent: response.completed\ndata: %s\n\ndata: [DONE]\n\n", b1, b2, b3, b4, b5, b6)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(respObj)
			return
		}

		// OpenAI /v1/chat/completions
		if !hasTools || turn.Add(1) > 1 {
			if stream {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprintf(w, "data: {\"id\":\"c2\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"done\"},\"finish_reason\":null}]}\n\n")
				fmt.Fprintf(w, "data: {\"id\":\"c2\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\ndata: [DONE]\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(obj{
				"id": "c2", "object": "chat.completion", "created": 1700000000, "model": "gpt-4o-mini",
				"choices": []any{obj{"index": 0, "message": obj{"role": "assistant", "content": "done"}, "finish_reason": "stop"}},
				"usage":   obj{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
			})
			return
		}

		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
			chunk1, _ := json.Marshal(obj{
				"id": "c1", "object": "chat.completion.chunk", "created": 1700000000, "model": "gpt-4o-mini",
				"choices": []any{obj{
					"index": 0,
					"delta": obj{
						"role": "assistant",
						"tool_calls": []any{obj{
							"index": 0, "id": "call_1", "type": "function",
							"function": obj{"name": toolName, "arguments": argsStr},
						}},
					},
					"finish_reason": nil,
				}},
			})
			fmt.Fprintf(w, "data: %s\n\ndata: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":10,\"total_tokens\":20}}\n\ndata: [DONE]\n\n", chunk1)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(obj{
			"id": "c1", "object": "chat.completion", "created": 1700000000, "model": "gpt-4o-mini",
			"choices": []any{obj{
				"index": 0,
				"message": obj{
					"role":    "assistant",
					"content": nil,
					"tool_calls": []any{obj{
						"id": "call_1", "type": "function",
						"function": obj{"name": toolName, "arguments": argsStr},
					}},
				},
				"finish_reason": "tool_calls",
			}},
			"usage": obj{"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
		})
	}))
}

type extCLICase struct {
	name      string
	policy    string
	sessionOp string // "", "approve", "deny"
	decision  string
	layer     string
	marker    bool
	escalated bool
}

func extCLICases(askMarker bool) []extCLICase {
	return []extCLICase{
		{name: "allow", policy: "allow", decision: "allow", layer: "rule", marker: true},
		{name: "deny", policy: "deny", decision: "deny", layer: "rule", marker: false},
		{name: "ask", policy: "ask", decision: "ask", layer: "rule", marker: askMarker},
		{name: "session-allow", policy: "ask", sessionOp: "approve", decision: "allow", layer: "session", marker: true},
		{name: "session-deny", policy: "ask", sessionOp: "deny", decision: "deny", layer: "session_deny", marker: false},
	}
}

const extTestSessionUUID = "00000000-0000-4000-8000-000000000001"

func prepareExtSandbox(t *testing.T, harness string, c extCLICase) *sandbox {
	t.Helper()
	s := newSandbox(t, c.policy)
	sid := extTestSessionUUID
	envKey := "YOLONOT_" + strings.ToUpper(harness) + "_SESSION_ID"
	s.Env = append(s.Env, envKey+"="+sid, "YOLONOT_FORCE_SESSION_ID="+sid)
	if c.sessionOp != "" {
		out, err := s.run(s.Work, yolonotBin, c.sessionOp, "--harness", harness, "--session-id", sid, "--cwd", s.Work, s.Command())
		if err != nil {
			t.Fatalf("yolonot %s failed: %v\n%s", c.sessionOp, err, out)
		}
	}
	return s
}

func (s *sandbox) expectExt(c extCLICase, log string) {
	s.t.Helper()
	if got := s.MarkerExists(); got != c.marker {
		s.t.Errorf("marker exists=%v, want %v\n%s", got, c.marker, tail(log))
	}
	decisions := s.Decisions()
	matched := false
	for _, d := range decisions {
		if c.decision == "ask" && d["layer"] == "human" && d["source"] == "allow_once" {
			s.t.Errorf("headless/auto-approve ask must not fabricate human allow_once: %v", d)
		}
		if d["decision"] == c.decision && (c.layer == "" || d["layer"] == c.layer) {
			if c.escalated && d["bypass_sandbox"] != true {
				continue
			}
			matched = true
		}
	}
	if !matched {
		s.t.Errorf("no decision=%q layer=%q (escalated=%v) for marker command; log=%v\n%s", c.decision, c.layer, c.escalated, decisions, tail(log))
	}
}

func runWithTimeout(t *testing.T, dir string, env []string, timeout time.Duration, bin string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir, cmd.Env = dir, env
	cmd.WaitDelay = 2 * time.Second
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func TestCrushCLI(t *testing.T) {
	crush := extendedHostBinary(t, "crush")
	hostVersion(t, crush, "--version")
	for _, c := range extCLICases(true) {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "crush", c)
			s.Install("crush")
			cmdStr := s.Command()
			srv := newMockToolServer(t, "bash", obj{"command": cmdStr, "description": "marker"})
			defer srv.Close()

			cfgPath := s.path(".config/crush/crush.json")
			rawCfg, _ := os.ReadFile(cfgPath)
			var cfg map[string]any
			_ = json.Unmarshal(rawCfg, &cfg)
			cfg["providers"] = obj{
				"mock": obj{
					"type":     "openai-compat",
					"base_url": srv.URL + "/v1",
					"api_key":  "mock-key",
					"models":   []any{obj{"id": "gpt-4o-mini", "name": "gpt-4o-mini", "context_window": 128000, "default_max_tokens": 4096}},
				},
			}
			cfg["models"] = obj{
				"large": obj{"model": "gpt-4o-mini", "provider": "mock"},
				"small": obj{"model": "gpt-4o-mini", "provider": "mock"},
			}
			newCfg, _ := json.MarshalIndent(cfg, "", "  ")
			s.write(".config/crush/crush.json", string(newCfg))

			out := runWithTimeout(t, s.Work, s.Env, 30*time.Second, crush, "run", "Run "+cmdStr)
			s.expectExt(c, out)
		})
	}
}

func TestGooseCLI(t *testing.T) {
	goose := extendedHostBinary(t, "goose")
	hostVersion(t, goose, "--version")
	for _, c := range extCLICases(true) {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "goose", c)
			s.Install("goose")
			cmdStr := s.Command()
			srv := newMockToolServer(t, "shell", obj{"command": cmdStr})
			defer srv.Close()

			env := append(append([]string{}, s.Env...),
				"GOOSE_PROVIDER=openai",
				"GOOSE_MODEL=gpt-4o-mini",
				"OPENAI_HOST="+srv.URL,
				"OPENAI_API_KEY=mock",
				"GOOSE_MODE=auto",
			)
			out := runWithTimeout(t, s.Work, env, 30*time.Second, goose, "run", "--no-session", "-t", "Run "+cmdStr)
			s.expectExt(c, out)
		})
	}
}

func TestQwenCLI(t *testing.T) {
	qwen := extendedHostBinary(t, "qwen")
	hostVersion(t, qwen, "--version")
	cases := append(extCLICases(false),
		// Unsandboxed request (dangerouslyDisableSandbox: true) must not reuse a prior sandboxed session approval.
		extCLICase{name: "escalated-isolated-session", policy: "ask", sessionOp: "approve", decision: "ask", layer: "rule", marker: false, escalated: true},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "qwen", c)
			s.Install("qwen")
			cmdStr := s.Command()
			toolArgs := obj{"command": cmdStr}
			if c.escalated {
				toolArgs["dangerouslyDisableSandbox"] = true
			}
			srv := newMockToolServer(t, "run_shell_command", toolArgs)
			defer srv.Close()

			env := append(append([]string{}, s.Env...),
				"OPENAI_BASE_URL="+srv.URL+"/v1",
				"OPENAI_API_KEY=mock",
				"OPENAI_MODEL=gpt-4o-mini",
			)
			out := runWithTimeout(t, s.Work, env, 30*time.Second, qwen, "-p", "Run "+cmdStr, "--yolo")
			s.expectExt(c, out)
		})
	}
}

func TestKiloCLI(t *testing.T) {
	kilo := extendedHostBinary(t, "kilo")
	hostVersion(t, kilo, "--version")
	for _, c := range extCLICases(true) {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "kilo", c)
			s.Install("kilo")
			cmdStr := s.Command()
			srv := newMockToolServer(t, "bash", obj{"command": cmdStr, "description": "marker"})
			defer srv.Close()

			s.write(".config/kilo/kilo.json", fmt.Sprintf(`{
  "model": "mock/gpt-4o-mini",
  "provider": {
    "mock": {
      "npm": "@ai-sdk/openai-compatible",
      "options": {"baseURL": %q, "apiKey": "mock"},
      "models": {"gpt-4o-mini": {"name": "gpt-4o-mini"}}
    }
  }
}`, srv.URL+"/v1"))
			out := runWithTimeout(t, s.Work, s.Env, 30*time.Second, kilo, "run", "--auto", "Run "+cmdStr)
			s.expectExt(c, out)
		})
	}
}

func TestPiCLI(t *testing.T) {
	pi := extendedHostBinary(t, "pi")
	hostVersion(t, pi, "--version")
	for _, c := range extCLICases(false) {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "pi", c)
			s.Install("pi")
			cmdStr := s.Command()
			srv := newMockToolServer(t, "bash", obj{"command": cmdStr})
			defer srv.Close()

			s.write(".pi/agent/models.json", fmt.Sprintf(`{
  "providers": {
    "mock": {
      "baseUrl": %q,
      "apiKey": "test-key",
      "api": "openai-completions",
      "models": [{"id": "mock-model", "name": "Mock Model"}]
    }
  }
}`, srv.URL+"/v1"))
			out := runWithTimeout(t, s.Work, s.Env, 30*time.Second, pi, "--offline", "--no-session", "--provider", "mock", "--model", "mock-model", "-p", "Run "+cmdStr)
			s.expectExt(c, out)
		})
	}
}

func TestOpenHandsCLI(t *testing.T) {
	oh := extendedHostBinary(t, "openhands")
	hostVersion(t, oh, "--version")
	for _, c := range extCLICases(true) {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "openhands", c)
			s.Install("openhands")
			hooksData, err := os.ReadFile(s.path(".openhands/hooks.json"))
			if err != nil {
				t.Fatalf("read .openhands/hooks.json: %v", err)
			}
			s.write(filepath.Join(s.Work, ".openhands/hooks.json"), string(hooksData))

			cmdStr := s.Command()
			srv := newMockToolServer(t, "terminal", obj{"command": cmdStr, "security_risk": "LOW"})
			defer srv.Close()

			env := append(append([]string{}, s.Env...),
				"LLM_MODEL=openai/gpt-4o-mini",
				"LLM_BASE_URL="+srv.URL+"/v1",
				"LLM_API_KEY=mock",
			)
			out := runWithTimeout(t, s.Work, env, 45*time.Second, oh, "--headless", "--override-with-envs", "--always-approve", "-t", "Run "+cmdStr)
			s.expectExt(c, out)
		})
	}
}

func TestKimiCLI(t *testing.T) {
	kimi := extendedHostBinary(t, "kimi")
	hostVersion(t, kimi, "--version")
	for _, c := range extCLICases(true) {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "kimi", c)
			s.Install("kimi")
			cmdStr := s.Command()
			srv := newMockToolServer(t, "Bash", obj{"command": cmdStr})
			defer srv.Close()

			env := append(append([]string{}, s.Env...),
				"KIMI_MODEL_NAME=gpt-4o-mini",
				"KIMI_MODEL_API_KEY=test-key",
				"KIMI_MODEL_PROVIDER_TYPE=openai",
				"KIMI_MODEL_BASE_URL="+srv.URL+"/v1",
			)
			out := runWithTimeout(t, s.Work, env, 30*time.Second, kimi, "-p", "Run "+cmdStr)
			s.expectExt(c, out)
		})
	}
}

func TestZCodeCLI(t *testing.T) {
	zcode := extendedHostBinary(t, "zcode")
	hostVersion(t, zcode, "--version")
	for _, c := range extCLICases(false) {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "zcode", c)
			cmdStr := s.Command()
			srv := newMockToolServer(t, "Bash", obj{"command": cmdStr})
			defer srv.Close()

			s.write(".zcode/v2/provider_config.json", fmt.Sprintf(`{
  "schemaVersion": 1,
  "config": {
    "providerConfigRules": {
      "providerRules": [{
        "providerId": "custom",
        "templateId": null,
        "providerName": "Custom provider",
        "enabled": true,
        "config": {
          "group": "standard-personal",
          "logo": null,
          "access": {"type": "api-key", "apiKey": "test-key"},
          "api": {"type": "openai-chat-completions", "baseUrl": %q, "headers": {}},
          "personalModelIds": ["gpt-4o-mini"],
          "modelOrder": ["gpt-4o-mini"],
          "visibility": "visible"
        }
      }]
    },
    "modelConfigRules": {
      "providerModelRules": [{
        "providerId": "custom",
        "modelId": "gpt-4o-mini",
        "config": {
          "enabled": true,
          "properties": {
            "contextWindow": 200000,
            "inputFormat": {"supportsText": true, "supportsImage": false, "supportsVideo": false, "supportsAudio": false, "supportsPdf": false},
            "outputFormat": {"supportsText": true},
            "supportsToolCall": true,
            "supportsJsonSchemaOutput": false,
            "supportsNativeWebSearch": false,
            "supportsMidConversationSystem": false,
            "requiresMfjsToolSchema": false
          }
        }
      }],
      "manualProviderModelRules": []
    },
    "providerOrder": ["custom"],
    "defaultModelSelection": {"providerId": "custom", "modelId": "gpt-4o-mini", "options": {}}
  }
}`, srv.URL+"/v1"))
			s.write(".zcode/cli/setting.json", `{
  "permission": {
    "mode": "auto",
    "allowedTools": [],
    "disallowedTools": [],
    "autoApproveHighRisk": true,
    "allowMediumRiskInAuto": true
  }
}`)
			s.Install("zcode")

			out := runWithTimeout(t, s.Work, s.Env, 30*time.Second, zcode, "-p", "Run "+cmdStr)
			s.expectExt(c, out)
		})
	}
}

func TestClineCLI(t *testing.T) {
	cline := extendedHostBinary(t, "cline")
	hostVersion(t, cline, "--version")
	for _, c := range extCLICases(true) {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "cline", c)
			s.Install("cline")
			cmdStr := s.Command()
			srv := newMockToolServer(t, "run_commands", obj{"commands": []string{cmdStr}})
			defer srv.Close()

			_ = runWithTimeout(t, s.Work, s.Env, 15*time.Second, cline, "auth", "-p", "openai", "-k", "test-key", "-m", "gpt-4o-mini", "-b", srv.URL+"/v1")
			out := runWithTimeout(t, s.Work, s.Env, 30*time.Second, cline, "--json", "--auto-approve", "true", "-c", s.Work, "Run "+cmdStr)
			s.expectExt(c, out)
		})
	}
}

func TestGrokCLI(t *testing.T) {
	grok := extendedHostBinary(t, "grok")
	hostVersion(t, grok, "--version")
	cases := append(extCLICases(true),
		extCLICase{name: "escalated-isolated-session", policy: "ask", sessionOp: "approve", decision: "ask", layer: "rule", marker: true, escalated: true},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "grok", c)
			cmdStr := s.Command()
			toolArgs := obj{"command": cmdStr, "description": "marker"}
			if c.escalated {
				toolArgs["dangerouslyDisableSandbox"] = true
			}
			srv := newMockToolServer(t, "run_terminal_command", toolArgs)
			defer srv.Close()

			s.write(".grok/config.toml", fmt.Sprintf("[model.mock]\nmodel = \"gpt-4o-mini\"\nbase_url = %q\napi_key = \"test-key\"\n", srv.URL+"/v1"))
			s.Install("grok")

			sockPath := filepath.Join("/tmp", fmt.Sprintf("grok-%d-%s.sock", os.Getpid(), c.name))
			t.Cleanup(func() { _ = os.Remove(sockPath) })

			env := append(append([]string{}, s.Env...),
				"GROK_HOME="+s.path(".grok"),
			)
			out := runWithTimeout(t, s.Work, env, 30*time.Second, grok, "--always-approve", "--leader-socket", sockPath, "-m", "mock", "-p", "Run "+cmdStr)
			s.expectExt(c, out)
		})
	}
}

func TestCopilotCLI(t *testing.T) {
	copilot := extendedHostBinary(t, "copilot")
	hostVersion(t, copilot, "--version")
	cases := append(extCLICases(false),
		extCLICase{name: "escalated-isolated-session", policy: "ask", sessionOp: "approve", decision: "ask", layer: "rule", marker: false, escalated: true},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "copilot", c)
			s.Install("copilot")
			cmdStr := s.Command()
			toolArgs := obj{"command": cmdStr, "description": "marker"}
			if c.escalated {
				toolArgs["requestSandboxBypass"] = true
			}
			srv := newMockToolServer(t, "bash", toolArgs)
			defer srv.Close()

			env := append(append([]string{}, s.Env...),
				"COPILOT_PROVIDER_BASE_URL="+srv.URL+"/v1",
				"COPILOT_PROVIDER_API_KEY=test-key",
				"COPILOT_MODEL=gpt-4o-mini",
			)
			out := runWithTimeout(t, s.Work, env, 30*time.Second, copilot, "--yolo", "-p", "Run "+cmdStr)
			s.expectExt(c, out)
		})
	}
}

func TestMuseCLI(t *testing.T) {
	muse := extendedHostBinary(t, "muse")
	for _, c := range extCLICases(true) {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "muse", c)
			s.Install("muse")
			cmdStr := s.Command()
			srv := newMockToolServer(t, "bash", obj{"command": cmdStr, "workdir": s.Work})
			defer srv.Close()

			env := append(append([]string{}, s.Env...),
				"MUSE_NO_AUTO_UPDATE=1",
				"META_API_KEY=test-key",
			)
			out := runWithTimeout(t, s.Work, env, 30*time.Second, muse, "exec",
				"--provider", "meta",
				"--model", "muse-spark-1.3",
				"--base-url", srv.URL+"/v1",
				"--session-id", extTestSessionUUID,
				"--disable-reminders",
				"--disable-web-tools",
				"--yolo",
				"Run "+cmdStr,
			)
			s.expectExt(c, out)
		})
	}
}

func TestKiroCLI(t *testing.T) {
	kiro := extendedHostBinary(t, "kiro-cli-chat", "/Applications/Kiro CLI.app/Contents/MacOS/kiro-cli-chat")
	sqliteBin, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 not installed")
	}
	for _, c := range extCLICases(true) {
		t.Run(c.name, func(t *testing.T) {
			s := prepareExtSandbox(t, "kiro", c)
			s.Install("kiro")
			cmdStr := s.Command()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"models":[{"modelId":"claude-sonnet-4","modelName":"Claude Sonnet 4","tokenLimits":{"maxInputTokens":200000}}],"defaultModel":{"modelId":"claude-sonnet-4","modelName":"Claude Sonnet 4","tokenLimits":{"maxInputTokens":200000}}}`)
			}))
			defer srv.Close()

			cliCfgPath := s.path(".kiro/settings/cli.json")
			rawCLI, _ := os.ReadFile(cliCfgPath)
			var cliCfg map[string]any
			_ = json.Unmarshal(rawCLI, &cliCfg)
			if cliCfg == nil {
				cliCfg = map[string]any{}
			}
			cliCfg["api.codewhisperer.service"] = obj{"endpoint": srv.URL, "region": "us-east-1"}
			cliCfg["api.q.service"] = obj{"endpoint": srv.URL, "region": "us-east-1"}
			cliCfg["api.krs.service"] = obj{"endpoint": srv.URL, "region": "us-east-1"}
			cliCfg["api.cps.service"] = obj{"endpoint": srv.URL, "region": "us-east-1"}
			newCLI, _ := json.MarshalIndent(cliCfg, "", "  ")
			s.write(".kiro/settings/cli.json", string(newCLI))

			// Let Kiro run its built-in SQLite schema migrations first
			_ = runWithTimeout(t, s.Work, s.Env, 10*time.Second, kiro, "whoami")

			dbPath := s.path("Library/Application Support/kiro-cli/data.sqlite3")
			if _, err := os.Stat(dbPath); err != nil {
				dbPath = s.path(".local/share/kiro-cli/data.sqlite3")
			}
			sqlInit := `INSERT OR REPLACE INTO auth_kv VALUES ('kirocli:social:token', '{"access_token":"test-token","accessToken":"test-token","expires_at":"2099-01-01T00:00:00Z","expiresAt":"2099-01-01T00:00:00Z","refresh_token":"test-refresh","refreshToken":"test-refresh","profile_arn":"arn:aws:codewhisperer:us-east-1:123456789012:profile/TESTPROFILE","profileArn":"arn:aws:codewhisperer:us-east-1:123456789012:profile/TESTPROFILE","provider":"github","auth_method":"github","authMethod":"Github"}');`
			sqlCmd := exec.Command(sqliteBin, dbPath, sqlInit)
			if out, err := sqlCmd.CombinedOutput(); err != nil {
				t.Fatalf("sqlite3 init (%s): %v\n%s", dbPath, err, string(out))
			}

			mockEvents := []any{
				[]any{obj{"tool_use_id": "call_1", "name": "execute_bash", "args": obj{"command": cmdStr}}},
				[]any{"Done!"},
			}
			mockBytes, _ := json.Marshal(mockEvents)
			mockPath := s.path("kiro-mock.json")
			s.write("kiro-mock.json", string(mockBytes))

			env := append(append([]string{}, s.Env...),
				"KIRO_TEST_MODE=1",
				"KIRO_MOCK_CHAT_RESPONSE="+mockPath,
			)
			out := runWithTimeout(t, s.Work, env, 30*time.Second, kiro, "chat", "--legacy-ui", "--agent-engine", "v1", "--trust-all-tools", "--no-interactive", "Run "+cmdStr)
			s.expectExt(c, out)
		})
	}
}

func TestMirrorExtensionRuntime(t *testing.T) {
	realHome, _ := os.UserHomeDir()
	mirrorPy := filepath.Join(realHome, ".local", "share", "uv", "tools", "reflection-mirror", "bin", "python")
	if _, err := os.Stat(mirrorPy); err != nil {
		t.Skip("reflection-mirror uv python not installed")
	}
	s := newSandbox(t, "")
	s.write(".yolonot/rules", "allow-cmd touch *\nask-cmd git push *\ndeny-cmd rm -rf /*\n")
	s.Install("mirror")
	s.Env = append(s.Env, "YOLONOT_MIRROR_SESSION_ID=mirror-s1")
	if out, err := s.run(s.Work, yolonotBin, "approve", "--harness", "mirror", "--session-id", "mirror-s1", "--cwd", s.Work, "git push origin approved-branch"); err != nil {
		t.Fatalf("yolonot approve mirror: %v\n%s", err, out)
	}
	if out, err := s.run(s.Work, yolonotBin, "deny", "--harness", "mirror", "--session-id", "mirror-s1", "--cwd", s.Work, "git push origin denied-branch"); err != nil {
		t.Fatalf("yolonot deny mirror: %v\n%s", err, out)
	}

	driver := s.path("run-mirror-ext.py")
	s.write(driver, fmt.Sprintf(`import asyncio, json, pathlib, types
from mirror import config
from mirror.cli import actions, extension, user_extensions

async def main():
    home = pathlib.Path(%q)
    work = pathlib.Path(%q)
    reg = extension.ExtensionRegistry()
    ue = user_extensions.UserExtensions(reg, home / ".mirror" / "extensions", settings=config.Config(home / ".mirror" / "config.json"))
    await ue.start(trust_extensions=False)
    dispatched = []
    ext = reg._extensions["yolonot"].extension
    st = types.SimpleNamespace(extensions=reg.create_view().initial_states)
    class FakeCtx:
        workspace = extension.Workspace(cwd=work, remote=False)
        def dispatch(self, act): dispatched.append((act.call_id, act.approved))
    for cid, cmd in [
        ("c1", %q),
        ("c2", "rm -rf /tmp/x"),
        ("c3", "git push origin main"),
        ("c4", "git push origin approved-branch"),
        ("c5", "git push origin denied-branch"),
    ]:
        _, effs = ext.reduce(st, actions.ApprovalRequested(actions.ApprovalRequest(call_id=cid, name="bash", args=json.dumps({"command": cmd}))))
        await ext.handle_effect(FakeCtx(), effs[0].payload)
    # Simulate human approving c3 ("git push origin main") in Mirror TUI -> PostToolUse allow_once
    _, post_effs = ext.reduce(st, actions.DecideApproval(approved=True, call_id="c3"))
    for eff in post_effs:
        await ext.handle_effect(FakeCtx(), eff.payload)
    print("DISPATCHED:", dispatched)

asyncio.run(main())
`, s.Home, s.Work, s.Command()))

	out := runWithTimeout(t, s.Work, s.Env, 15*time.Second, mirrorPy, driver)
	// c1 (allow) -> True, c2 (deny) -> False, c3 (ask) -> not auto-dispatched (left for TUI), c4 (session-allow) -> True, c5 (session-deny) -> False
	if !strings.Contains(out, "('c1', True)") || !strings.Contains(out, "('c2', False)") || strings.Contains(out, "'c3'") || !strings.Contains(out, "('c4', True)") || !strings.Contains(out, "('c5', False)") {
		t.Fatalf("Mirror extension runtime output unexpected:\n%s", out)
	}
	rawDecisions, _ := os.ReadFile(s.path(".yolonot/decisions.jsonl"))
	if !strings.Contains(string(rawDecisions), `"source":"allow_once"`) || !strings.Contains(string(rawDecisions), `"layer":"session"`) || !strings.Contains(string(rawDecisions), `"layer":"session_deny"`) {
		t.Fatalf("Mirror decisions.jsonl missing allow_once/session/session_deny:\n%s", string(rawDecisions))
	}
}

func TestOpenClawAndAmpPluginShimsRuntime(t *testing.T) {
	nodeBin := extendedHostBinary(t, "node")
	s := newSandbox(t, "")
	s.write(".yolonot/rules", "allow-cmd touch *\nask-cmd git push *\ndeny-cmd rm -rf /*\n")
	s.Install("openclaw")
	s.Install("amp")
	s.Env = append(s.Env, "YOLONOT_OPENCLAW_SESSION_ID=oc-s1", "YOLONOT_AMP_SESSION_ID=amp-s1")
	if out, err := s.run(s.Work, yolonotBin, "approve", "--harness", "openclaw", "--session-id", "oc-s1", "--cwd", s.Work, "git push origin oc-approved"); err != nil {
		t.Fatalf("yolonot approve openclaw: %v\n%s", err, out)
	}
	if out, err := s.run(s.Work, yolonotBin, "deny", "--harness", "openclaw", "--session-id", "oc-s1", "--cwd", s.Work, "git push origin oc-denied"); err != nil {
		t.Fatalf("yolonot deny openclaw: %v\n%s", err, out)
	}
	if out, err := s.run(s.Work, yolonotBin, "approve", "--harness", "amp", "--session-id", "amp-s1", "--cwd", s.Work, "git push origin amp-approved"); err != nil {
		t.Fatalf("yolonot approve amp: %v\n%s", err, out)
	}
	if out, err := s.run(s.Work, yolonotBin, "deny", "--harness", "amp", "--session-id", "amp-s1", "--cwd", s.Work, "git push origin amp-denied"); err != nil {
		t.Fatalf("yolonot deny amp: %v\n%s", err, out)
	}

	// 1. OpenClaw shim runtime in Node.js (allow, deny, ask + after_tool_call allow_once, session-allow, session-deny, and elevated BypassSandbox)
	ocShim := s.path(".openclaw/extensions/yolonot/index.js")
	ocDriver := s.path("run-openclaw-shim.mjs")
	s.write(ocDriver, fmt.Sprintf(`import register from %q;
let beforeFn, afterFn;
register({ on(ev, cb) { if (ev === "before_tool_call") beforeFn = cb; if (ev === "after_tool_call") afterFn = cb; } });
const ctx = { sessionId: "oc-s1", cwd: %q };
const allowRes = await beforeFn({ toolName: "exec", toolCallId: "1", params: { command: %q } }, ctx);
const denyRes = await beforeFn({ toolName: "exec", toolCallId: "2", params: { command: "rm -rf /tmp/x" } }, ctx);
const askRes = await beforeFn({ toolName: "exec", toolCallId: "3", params: { command: "git push origin main", elevated: true } }, ctx);
await afterFn({ toolName: "exec", toolCallId: "3", params: { command: "git push origin main", elevated: true } }, ctx);
const sessAllowRes = await beforeFn({ toolName: "exec", toolCallId: "4", params: { command: "git push origin oc-approved" } }, ctx);
const sessDenyRes = await beforeFn({ toolName: "exec", toolCallId: "5", params: { command: "git push origin oc-denied" } }, ctx);
console.log(JSON.stringify({ allowRes: allowRes || null, denyRes: denyRes || null, askRes: askRes || null, sessAllowRes: sessAllowRes || null, sessDenyRes: sessDenyRes || null }));
`, ocShim, s.Work, s.Command()))

	ocOut := runWithTimeout(t, s.Work, s.Env, 15*time.Second, nodeBin, ocDriver)
	if !strings.Contains(ocOut, `"allowRes":null`) || !strings.Contains(ocOut, `"block":true`) || !strings.Contains(ocOut, `"requireApproval"`) || !strings.Contains(ocOut, `"sessAllowRes":null`) {
		t.Fatalf("OpenClaw shim runtime output unexpected:\n%s", ocOut)
	}

	// 2. Amp shim runtime in Node.js (allow, deny, ask approved -> allow_once, ask rejected, session-allow, session-deny)
	ampShim := s.path(".config/amp/plugins/yolonot.ts")
	ampDriver := s.path("run-amp-shim.mjs")
	s.write(ampDriver, fmt.Sprintf(`import register from %q;
let fn;
register({ on(ev, cb) { if (ev === "tool.call") fn = cb; } });
const allowRes = await fn({ tool: "Bash", input: { cmd: %q, cwd: %q } }, { ui: { async confirm() { return false; } } });
const denyRes = await fn({ tool: "Bash", input: { cmd: "rm -rf /tmp/x", cwd: %q } }, { ui: { async confirm() { return true; } } });
const askApprovedRes = await fn({ tool: "Bash", input: { cmd: "git push origin main", cwd: %q } }, { ui: { async confirm() { return true; } } });
const askRejectedRes = await fn({ tool: "Bash", input: { cmd: "git push origin other", cwd: %q } }, { ui: { async confirm() { return false; } } });
const sessAllowRes = await fn({ tool: "Bash", input: { cmd: "git push origin amp-approved", cwd: %q } }, { ui: { async confirm() { return false; } } });
const sessDenyRes = await fn({ tool: "Bash", input: { cmd: "git push origin amp-denied", cwd: %q } }, { ui: { async confirm() { return true; } } });
console.log(JSON.stringify({ allowRes, denyRes, askApprovedRes, askRejectedRes, sessAllowRes, sessDenyRes }));
`, ampShim, s.Command(), s.Work, s.Work, s.Work, s.Work, s.Work, s.Work))

	ampOut := runWithTimeout(t, s.Work, s.Env, 15*time.Second, nodeBin, ampDriver)
	if !strings.Contains(ampOut, `"allowRes":{"action":"allow"}`) ||
		!strings.Contains(ampOut, `"askApprovedRes":{"action":"allow"}`) ||
		!strings.Contains(ampOut, `"askRejectedRes":{"action":"reject-and-continue","message":"Denied by user"}`) ||
		!strings.Contains(ampOut, `"sessAllowRes":{"action":"allow"}`) ||
		!strings.Contains(ampOut, `"sessDenyRes":{"action":"reject-and-continue"`) {
		t.Fatalf("Amp shim runtime output unexpected:\n%s", ampOut)
	}

	// 3. Pi interactive UI confirmation in Node.js (ask approved -> allow_once, ask rejected -> Denied by user)
	s.Install("pi")
	piShim := s.path(".pi/agent/extensions/yolonot.ts")
	piDriver := s.path("run-pi-shim.mjs")
	s.write(piDriver, fmt.Sprintf(`import register from %q;
let fn;
register({ on(ev, cb) { if (ev === "tool_call") fn = cb; } });
const askApproved = await fn({ toolName: "bash", toolCallId: "p1", input: { command: "git push origin pi-ok" } }, { hasUI: true, cwd: %q, sessionManager: { getSessionId() { return "pi-s1"; } }, ui: { async confirm() { return true; } } });
const askRejected = await fn({ toolName: "bash", toolCallId: "p2", input: { command: "git push origin pi-no" } }, { hasUI: true, cwd: %q, sessionManager: { getSessionId() { return "pi-s1"; } }, ui: { async confirm() { return false; } } });
console.log(JSON.stringify({ askApproved: askApproved || null, askRejected: askRejected || null }));
`, piShim, s.Work, s.Work))

	piOut := runWithTimeout(t, s.Work, s.Env, 15*time.Second, nodeBin, piDriver)
	if !strings.Contains(piOut, `"askApproved":null`) || !strings.Contains(piOut, `"Denied by user"`) {
		t.Fatalf("Pi interactive shim runtime output unexpected:\n%s", piOut)
	}
}

func TestHermesAndDeepSeekHookRuntimes(t *testing.T) {
	s := newSandbox(t, "")
	s.write(".yolonot/rules", "allow-cmd touch *\nask-cmd git push *\ndeny-cmd rm -rf /*\n")
	s.Install("hermes")
	s.Install("deepseek")
	if out, err := s.run(s.Work, yolonotBin, "approve", "--harness", "hermes", "--session-id", "h1", "--cwd", s.Work, "git push origin h-approved"); err != nil {
		t.Fatalf("yolonot approve hermes: %v\n%s", err, out)
	}
	if out, err := s.run(s.Work, yolonotBin, "deny", "--harness", "hermes", "--session-id", "h1", "--cwd", s.Work, "git push origin h-denied"); err != nil {
		t.Fatalf("yolonot deny hermes: %v\n%s", err, out)
	}
	if out, err := s.run(s.Work, yolonotBin, "approve", "--harness", "deepseek", "--session-id", "d1", "--cwd", s.Work, "git push origin d-approved"); err != nil {
		t.Fatalf("yolonot approve deepseek: %v\n%s", err, out)
	}
	if out, err := s.run(s.Work, yolonotBin, "deny", "--harness", "deepseek", "--session-id", "d1", "--cwd", s.Work, "git push origin d-denied"); err != nil {
		t.Fatalf("yolonot deny deepseek: %v\n%s", err, out)
	}
	s.Install("devin")
	if out, err := s.run(s.Work, yolonotBin, "approve", "--harness", "devin", "--session-id", "dev1", "--cwd", s.Work, "git push origin dev-approved"); err != nil {
		t.Fatalf("yolonot approve devin: %v\n%s", err, out)
	}
	if out, err := s.run(s.Work, yolonotBin, "deny", "--harness", "devin", "--session-id", "dev1", "--cwd", s.Work, "git push origin dev-denied"); err != nil {
		t.Fatalf("yolonot deny devin: %v\n%s", err, out)
	}

	// Verify Hermes config.yaml hook command executes for allow, ask, deny, session-allow, and session-deny
	hermesCfg, err := os.ReadFile(s.path(".hermes/config.yaml"))
	if err != nil || !strings.Contains(string(hermesCfg), "--harness hermes") {
		t.Fatalf("hermes config.yaml missing hook command: err=%v, body=%s", err, string(hermesCfg))
	}
	for _, tc := range []struct {
		cmd, want string
	}{
		{s.Command(), ""},
		{"git push origin main", `"action":"approve"`},
		{"rm -rf /tmp/x", `"action":"block"`},
		{"git push origin h-approved", ""},
		{"git push origin h-denied", `"action":"block"`},
	} {
		cmd := exec.Command(yolonotBin, "hook", "--harness", "hermes")
		cmd.Dir, cmd.Env = s.Work, s.Env
		cmd.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"pre_tool_call","session_id":"h1","cwd":%q,"tool_name":"terminal","tool_input":{"command":%q}}`, s.Work, tc.cmd))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("hermes hook (%s) failed: %v\n%s", tc.cmd, err, string(out))
		}
		if tc.want == "" && strings.TrimSpace(string(out)) != "" {
			t.Fatalf("hermes allow expected empty stdout, got %q", string(out))
		}
		if tc.want != "" && !strings.Contains(string(out), tc.want) {
			t.Fatalf("hermes (%s) expected %s, got %q", tc.cmd, tc.want, string(out))
		}
	}

	// Verify DeepSeek yolonot-hooks.json + cordis.patch.yml hook executes for allow, ask, deny, session-allow, and session-deny
	dshHooks, err := os.ReadFile(s.path(".dsh/yolonot-hooks.json"))
	if err != nil || !strings.Contains(string(dshHooks), `"Bash|bash|pwsh"`) {
		t.Fatalf("deepseek yolonot-hooks.json unexpected: err=%v, body=%s", err, string(dshHooks))
	}
	for _, tc := range []struct {
		cmd, want string
	}{
		{s.Command(), ""},
		{"git push origin main", `"permissionDecision":"ask"`},
		{"rm -rf /tmp/x", `"permissionDecision":"deny"`},
		{"git push origin d-approved", ""},
		{"git push origin d-denied", `"permissionDecision":"deny"`},
	} {
		cmd := exec.Command(yolonotBin, "hook", "--harness", "deepseek")
		cmd.Dir, cmd.Env = s.Work, s.Env
		cmd.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":"d1","cwd":%q,"tool_name":"bash","tool_input":{"command":%q}}`, s.Work, tc.cmd))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("deepseek hook (%s) failed: %v\n%s", tc.cmd, err, string(out))
		}
		if tc.want == "" && strings.TrimSpace(string(out)) != "" {
			t.Fatalf("deepseek allow expected empty stdout, got %q", string(out))
		}
		if tc.want != "" && !strings.Contains(string(out), tc.want) {
			t.Fatalf("deepseek (%s) expected %s, got %q", tc.cmd, tc.want, string(out))
		}
	}

	// Verify Devin config.json hook executes for allow, ask, deny, session-allow, and session-deny
	for _, tc := range []struct {
		cmd, want string
	}{
		{s.Command(), `"permissionDecision":"allow"`},
		{"git push origin main", `"permissionDecision":"ask"`},
		{"rm -rf /tmp/x", `"permissionDecision":"deny"`},
		{"git push origin dev-approved", `"permissionDecision":"allow"`},
		{"git push origin dev-denied", `"permissionDecision":"deny"`},
	} {
		cmd := exec.Command(yolonotBin, "hook", "--harness", "devin")
		cmd.Dir, cmd.Env = s.Work, s.Env
		cmd.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":"dev1","cwd":%q,"tool_name":"exec","tool_input":{"command":%q}}`, s.Work, tc.cmd))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("devin hook (%s) failed: %v\n%s", tc.cmd, err, string(out))
		}
		if !strings.Contains(string(out), tc.want) {
			t.Fatalf("devin (%s) expected %s, got %q", tc.cmd, tc.want, string(out))
		}
	}
}


