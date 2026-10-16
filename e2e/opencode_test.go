//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// smokePlugin adds a /yolonot-smoke command that calls the shell tool
// directly, so the gate is exercised without a model.
const smokePlugin = `import {writeFile} from "node:fs/promises";
export default {
  id: "yolonot-e2e-driver",
  setup: async ctx => {
    await ctx.command.transform(editor => editor.add({
      name: "yolonot-smoke",
      execute: async invocation => {
        const spec = JSON.parse(invocation.prompt.text ?? "{}");
        const tool = (await ctx.tool.list()).find(x => x.name === "shell");
        let result, error;
        try {
          result = await tool.execute({command: spec.command, workdir: ctx.location.directory}, {
            sessionID: invocation.sessionID, agent: undefined, messageID: "msg_smoke", id: spec.id,
            progress: async () => {}, signal: new AbortController().signal,
          });
        } catch (e) { error = String(e); }
        await writeFile(spec.file, JSON.stringify({result, error}));
      }
    }));
  }
};
`

type opencodeServer struct {
	url, auth string
}

func (o *opencodeServer) call(t *testing.T, method, path string, body any) obj {
	t.Helper()
	out, err := o.raw(method, path, body)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (o *opencodeServer) raw(method, path string, body any) (obj, error) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, o.url+path, r)
	req.Header.Set("Authorization", o.auth)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out obj
	json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 300 {
		return out, fmt.Errorf("%s %s: HTTP %d %v", method, path, resp.StatusCode, out)
	}
	return out, nil
}

func startOpencode(t *testing.T, bin string, s *sandbox) *opencodeServer {
	t.Helper()
	cmd := exec.Command(bin, "serve", "--hostname", "127.0.0.1")
	cmd.Dir, cmd.Env = s.Work, s.Env
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); pw.Close() })
	listen := regexp.MustCompile(`server listening on (\S+)`)
	pass := regexp.MustCompile(`server password (\S+)`)
	o := &opencodeServer{}
	found := make(chan struct{})
	go func() {
		var url, auth string
		reported := false
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			if reported {
				continue
			}
			if m := listen.FindStringSubmatch(sc.Text()); m != nil {
				url = m[1]
			}
			if m := pass.FindStringSubmatch(sc.Text()); m != nil {
				auth = "Basic " + base64.StdEncoding.EncodeToString([]byte("opencode:"+m[1]))
			}
			if url != "" && auth != "" {
				o.url, o.auth = url, auth
				close(found)
				reported = true
			}
		}
		// Keep draining after a scan error so the writer never blocks Wait.
		io.Copy(io.Discard, pr)
	}()
	select {
	case <-found:
	case <-time.After(30 * time.Second):
		t.Fatal("opencode serve did not report its address")
	}
	return o
}

// OpenCode V2: the yolonot plugin gates the shell tool, a native ask is
// answered through the permission API, and a host deny still wins over a
// yolonot allow.
func TestOpencodeV2(t *testing.T) {
	bin := hostBinary(t, "opencode")
	hostVersion(t, bin, "--version")
	s := newSandbox(t, "")
	s.write(".yolonot/rules", "allow-cmd touch *ALLOWED*\nask-cmd touch *ASKED*\ndeny-cmd touch *DENIED*\n")
	s.Install("opencode")
	s.write(".config/opencode/plugins/zz-e2e.ts", smokePlugin)
	srv := startOpencode(t, bin, s)
	for _, c := range []struct {
		name, token, host, reply string
		marker                   bool
	}{
		{"allow", "ALLOWED", "ask", "", true},
		{"deny", "DENIED", "allow", "", false},
		{"ask-approved", "ASKED", "allow", "once", true},
		{"ask-rejected", "ASKED", "allow", "reject", false},
		{"host-deny", "ALLOWED", "deny", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sess := srv.call(t, "POST", "/api/session", obj{"location": obj{"directory": s.Work}, "permissions": []any{obj{"action": "shell", "resource": "*", "effect": c.host}}})
			sid := sess["data"].(obj)["id"].(string)
			marker := filepath.Join(s.Work, c.token+"-"+c.name+".marker")
			result := filepath.Join(s.Home, c.name+"-result.json")
			spec, _ := json.Marshal(obj{"command": "touch " + marker, "id": "call_" + strings.ReplaceAll(c.name, "-", "_"), "file": result})
			done := make(chan struct{})
			go func() {
				defer close(done)
				srv.raw("POST", "/api/session/"+sid+"/command", obj{"name": "yolonot-smoke", "text": string(spec)})
			}()
			if c.reply != "" {
				var pending obj
				for deadline := time.Now().Add(10 * time.Second); pending == nil && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
					if ps, _ := srv.call(t, "GET", "/api/session/"+sid+"/permission", nil)["data"].([]any); len(ps) > 0 {
						pending = ps[0].(obj)
					}
				}
				if pending == nil {
					t.Fatal("yolonot ask did not reach OpenCode's permission queue")
				}
				if _, err := os.Stat(marker); err == nil {
					t.Fatal("command ran before the ask was answered")
				}
				srv.call(t, "POST", "/api/session/"+sid+"/permission/"+pending["id"].(string)+"/reply", obj{"decision": c.reply})
			}
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("smoke command did not finish")
			}
			out, _ := os.ReadFile(result)
			if _, err := os.Stat(marker); (err == nil) != c.marker {
				t.Errorf("marker exists=%v, want %v; result=%s", err == nil, c.marker, out)
			}
		})
	}
}

func TestOpencodeSkillDiscovery(t *testing.T) {
	bin := hostBinary(t, "opencode")
	s := newSandbox(t, "")
	if out, err := s.run(s.Work, yolonotBin, "install", "--skill-only", "--harness", "opencode"); err != nil {
		t.Fatalf("install --skill-only: %v\n%s", err, out)
	}
	srv := startOpencode(t, bin, s)
	sid := srv.call(t, "POST", "/api/session", obj{"location": obj{"directory": s.Work}})["data"].(obj)["id"].(string)
	if _, err := srv.raw("POST", "/api/experimental/session/"+sid+"/skill", obj{"id": "no-such-skill-e2e"}); err == nil {
		t.Fatal("control: unknown skill was accepted, so this check proves nothing")
	}
	if _, err := srv.raw("POST", "/api/experimental/session/"+sid+"/skill", obj{"id": "yolonot"}); err != nil {
		t.Fatalf("opencode did not find the yolonot skill: %v", err)
	}
}
