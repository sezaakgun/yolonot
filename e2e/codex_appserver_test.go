//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type rpcClient struct {
	t    *testing.T
	cmd  *exec.Cmd
	in   io.WriteCloser
	msgs chan obj
	id   int
}

func startAppServer(t *testing.T, codex string, s *sandbox) *rpcClient {
	t.Helper()
	cmd := exec.Command(codex, "app-server", "--stdio")
	cmd.Dir, cmd.Env = s.Work, s.Env
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &rpcClient{t: t, cmd: cmd, in: in, msgs: make(chan obj, 256)}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(nil, 8<<20)
		for sc.Scan() {
			var m obj
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				c.msgs <- m
			}
		}
		close(c.msgs)
	}()
	c.call("initialize", obj{"clientInfo": obj{"name": "yolonot_e2e", "version": "1"}, "capabilities": obj{"experimentalApi": true}})
	c.send(obj{"method": "initialized"})
	return c
}

func (c *rpcClient) send(m obj) {
	b, _ := json.Marshal(m)
	c.in.Write(append(b, '\n'))
}

func (c *rpcClient) next(timeout time.Duration) obj {
	select {
	case m, ok := <-c.msgs:
		if !ok {
			c.t.Fatal("app-server exited")
		}
		return m
	case <-time.After(timeout):
		c.t.Fatal("app-server: no message before timeout")
		return nil
	}
}

func (c *rpcClient) call(method string, params obj) obj {
	c.t.Helper()
	c.id++
	id := c.id
	c.send(obj{"id": id, "method": method, "params": params})
	for {
		m := c.next(20 * time.Second)
		if n, ok := m["id"].(float64); ok && int(n) == id && m["method"] == nil {
			if m["error"] != nil {
				c.t.Fatalf("%s: %v", method, m["error"])
			}
			r, _ := m["result"].(obj)
			return r
		}
	}
}

func (c *rpcClient) stop() {
	c.in.Close()
	c.cmd.Process.Kill()
	c.cmd.Wait()
}

// trustHooks records the current hook hashes as trusted in config.toml,
// the same state the /hooks screen writes.
func trustHooks(t *testing.T, codex string, s *sandbox) {
	c := startAppServer(t, codex, s)
	list := c.call("hooks/list", obj{"cwds": []string{s.Work}})
	c.stop()
	data, _ := list["data"].([]any)
	if len(data) == 0 {
		t.Fatalf("hooks/list returned nothing: %v", list)
	}
	hooks, _ := data[0].(obj)["hooks"].([]any)
	if len(hooks) == 0 {
		t.Fatal("codex sees no yolonot hooks")
	}
	f, err := os.OpenFile(s.path(".codex/config.toml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, h := range hooks {
		h := h.(obj)
		key, _ := json.Marshal(h["key"])
		hash, _ := json.Marshal(h["currentHash"])
		fmt.Fprintf(f, "\n[hooks.state.%s]\ntrusted_hash=%s\n", key, hash)
	}
}

// The app-server has a frontend: an ask must surface as an approval
// request (declined here), and a PermissionRequest deny must block even
// after PreToolUse allowed.
func TestCodexAppServer(t *testing.T) {
	codex := hostBinary(t, "codex")
	for _, c := range []struct {
		name, policy, decision string
		marker, approval       bool
	}{
		{"allow", "allow", "allow", true, false},
		{"ask-declined", "ask", "ask", false, true},
		{"permission-deny", "allow", "deny", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSandbox(t, c.policy)
			model := newModelServer(t, s.Command())
			model.Escalated = true
			codexConfig(s, model)
			s.Install("codex")
			if c.name == "permission-deny" {
				// PreToolUse sees allow; the wrapper flips the rule to deny
				// before PermissionRequest runs.
				wrapper := s.path("hook.sh")
				s.write(wrapper, fmt.Sprintf("#!/bin/sh\np=$(cat)\nprintf '%%s' \"$p\" | '%s' hook --harness codex\nrc=$?\ncase \"$p\" in *'\"PreToolUse\"'*) echo 'deny-cmd touch *' > '%s';; esac\nexit $rc\n", yolonotBin, s.path(".yolonot/rules")))
				os.Chmod(wrapper, 0o755)
				hooksFile := s.path(".codex/hooks.json")
				b, err := os.ReadFile(hooksFile)
				if err != nil {
					t.Fatal(err)
				}
				orig := "'" + yolonotBin + "' hook --harness codex"
				if !strings.Contains(string(b), orig) {
					t.Fatalf("hook command not found in hooks.json:\n%s", b)
				}
				s.write(hooksFile, strings.ReplaceAll(string(b), orig, "'"+wrapper+"'"))
			}
			trustHooks(t, codex, s)
			rpc := startAppServer(t, codex, s)
			defer rpc.stop()
			th := rpc.call("thread/start", obj{"cwd": s.Work, "model": "fixture-model", "modelProvider": "fixture", "approvalPolicy": "on-request", "sandbox": "workspace-write", "ephemeral": true})
			tid := th["thread"].(obj)["id"]
			rpc.call("turn/start", obj{"threadId": tid, "input": []any{obj{"type": "text", "text": "Run the fixture command once.", "text_elements": []any{}}}})
			var approvals []string
			status := ""
			deadline := time.Now().Add(45 * time.Second)
			for status == "" && time.Now().Before(deadline) {
				m := rpc.next(time.Until(deadline))
				method, _ := m["method"].(string)
				if _, isReq := m["id"]; isReq && method != "" {
					approvals = append(approvals, method)
					rpc.send(obj{"id": m["id"], "result": obj{"decision": "decline"}})
				}
				if method == "turn/completed" {
					status, _ = m["params"].(obj)["turn"].(obj)["status"].(string)
				}
			}
			if status != "completed" {
				t.Fatalf("turn status=%q", status)
			}
			if got := len(approvals) > 0; got != c.approval {
				t.Errorf("frontend approval requests=%v, want any=%v", approvals, c.approval)
			}
			s.expect(c.marker, c.decision, strings.Join(approvals, "\n"))
		})
	}
}

func TestCodexSkillDiscovery(t *testing.T) {
	codex := hostBinary(t, "codex")
	s := newSandbox(t, "")
	if out, err := s.run(s.Work, yolonotBin, "install", "--skill-only", "--harness", "codex"); err != nil {
		t.Fatalf("install --skill-only: %v\n%s", err, out)
	}
	rpc := startAppServer(t, codex, s)
	defer rpc.stop()
	list := rpc.call("skills/list", obj{"cwds": []string{s.Work}, "forceReload": true})
	data, _ := list["data"].([]any)
	for _, item := range data {
		skills, _ := item.(obj)["skills"].([]any)
		for _, sk := range skills {
			if sk.(obj)["name"] == "yolonot" {
				return
			}
		}
	}
	t.Fatalf("codex did not discover the yolonot skill: %v", list)
}
