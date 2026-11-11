package yolonot

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func repoRootForTest(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// minimalRFC6455Server upgrades HTTP to a raw RFC 6455 text WebSocket so we can
// test scripts/desktop-signoff.mjs's CDP client with zero external Go packages.
func serveMockCDPWebSocket(t *testing.T, onMsg func(id int, method string, params map[string]interface{}) interface{}) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/json/list" {
			wsURL := "ws://" + r.Host + "/devtools/page/1"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]string{
				{
					"id":                   "1",
					"type":                 "page",
					"title":                "cursor-test",
					"url":                  "vscode-file://vscode-app/workbench.html",
					"webSocketDebuggerUrl": wsURL,
				},
			})
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		hj, ok := w.(http.Hijacker)
		if !ok || key == "" {
			http.Error(w, "bad ws upgrade", http.StatusBadRequest)
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		accept := base64.StdEncoding.EncodeToString(sum[:])
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n")
		_ = rw.Flush()

		var writeMu sync.Mutex
		writeFrame := func(payload []byte) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			var hdr []byte
			hdr = append(hdr, 0x81) // FIN + text frame
			n := len(payload)
			switch {
			case n < 126:
				hdr = append(hdr, byte(n))
			case n <= 65535:
				hdr = append(hdr, 126, byte(n>>8), byte(n))
			default:
				hdr = append(hdr, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
			}
			if _, err := conn.Write(hdr); err != nil {
				return err
			}
			_, err := conn.Write(payload)
			return err
		}

		for {
			b2 := make([]byte, 2)
			if _, err := io.ReadFull(rw, b2); err != nil {
				return
			}
			opcode := b2[0] & 0x0f
			if opcode == 0x8 { // close
				return
			}
			masked := (b2[1] & 0x80) != 0
			length := uint64(b2[1] & 0x7f)
			switch length {
			case 126:
				ext := make([]byte, 2)
				if _, err := io.ReadFull(rw, ext); err != nil {
					return
				}
				length = uint64(binary.BigEndian.Uint16(ext))
			case 127:
				ext := make([]byte, 8)
				if _, err := io.ReadFull(rw, ext); err != nil {
					return
				}
				length = binary.BigEndian.Uint64(ext)
			}
			var maskKey [4]byte
			if masked {
				if _, err := io.ReadFull(rw, maskKey[:]); err != nil {
					return
				}
			}
			data := make([]byte, length)
			if _, err := io.ReadFull(rw, data); err != nil {
				return
			}
			if masked {
				for i := range data {
					data[i] ^= maskKey[i%4]
				}
			}
			var req struct {
				ID     int                    `json:"id"`
				Method string                 `json:"method"`
				Params map[string]interface{} `json:"params"`
			}
			if json.Unmarshal(data, &req) != nil {
				continue
			}
			res := onMsg(req.ID, req.Method, req.Params)
			reply, _ := json.Marshal(map[string]interface{}{"id": req.ID, "result": res})
			if writeFrame(reply) != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDesktopSignoffCursorCDPDryFlow(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	root := repoRootForTest(t)
	ws := t.TempDir()
	tmp := t.TempDir()
	decisionsLog := filepath.Join(tmp, "decisions.jsonl")

	var mu sync.Mutex
	var draftedText string
	var pendingAskMarker string
	appendLog := func(file, layer, decision string) {
		rec, _ := json.Marshal(map[string]string{
			"command":  "touch " + file,
			"cwd":      ws,
			"layer":    layer,
			"decision": decision,
		})
		f, err := os.OpenFile(decisionsLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = f.Write(append(rec, '\n'))
			_ = f.Close()
		}
	}
	markerRe := regexp.MustCompile(`touch ([^\s]+\.marker)`)

	srv := serveMockCDPWebSocket(t, func(_ int, method string, params map[string]interface{}) interface{} {
		mu.Lock()
		defer mu.Unlock()
		switch method {
		case "Runtime.enable":
			return map[string]interface{}{}
		case "Input.insertText":
			if s, ok := params["text"].(string); ok {
				draftedText = s
			}
			return map[string]interface{}{}
		case "Input.dispatchKeyEvent":
			typ, _ := params["type"].(string)
			key, _ := params["key"].(string)
			if typ == "keyDown" && key == "Enter" && draftedText != "" {
				m := markerRe.FindStringSubmatch(draftedText)
				draftedText = ""
				if len(m) == 2 {
					file := m[1]
					switch {
					case strings.Contains(file, "ALLOW"):
						_ = os.WriteFile(file, nil, 0o644)
						appendLog(file, "rule", "allow")
					case strings.Contains(file, "DENY"):
						appendLog(file, "rule", "deny")
					case strings.Contains(file, "ASK"):
						pendingAskMarker = file
						appendLog(file, "rule", "ask")
					}
				}
			}
			return map[string]interface{}{}
		case "Input.dispatchMouseEvent":
			typ, _ := params["type"].(string)
			x, _ := params["x"].(float64)
			if typ == "mousePressed" && pendingAskMarker != "" {
				if x < 150 { // Run button at x=100
					_ = os.WriteFile(pendingAskMarker, nil, 0o644)
				}
				pendingAskMarker = ""
			}
			return map[string]interface{}{}
		case "Runtime.evaluate":
			expr, _ := params["expression"].(string)
			switch {
			case strings.Contains(expr, ".monaco-workbench"):
				return map[string]interface{}{"result": map[string]interface{}{"value": true}}
			case strings.Contains(expr, ".aislash-editor-input"):
				return map[string]interface{}{"result": map[string]interface{}{"value": map[string]float64{"x": 300, "y": 500}}}
			case strings.Contains(expr, "hasPrompt"):
				if pendingAskMarker == "" {
					return map[string]interface{}{"result": map[string]interface{}{"value": nil}}
				}
				return map[string]interface{}{
					"result": map[string]interface{}{
						"value": map[string]interface{}{
							"hasPrompt": true,
							"run":       map[string]float64{"x": 100, "y": 400},
							"skip":      map[string]float64{"x": 200, "y": 400},
						},
					},
				}
			}
		}
		return map[string]interface{}{}
	})

	cmd := exec.Command("node", filepath.Join(root, "scripts", "desktop-signoff.mjs"), "cursor", ws, tmp)
	cmd.Env = append(os.Environ(),
		"HOME="+tmp,
		"YOLONOT_DESKTOP_SETTLE_MS=50",
		"YOLONOT_DESKTOP_TEST_CDP_URL="+srv.URL,
		"YOLONOT_DECISIONS_LOG="+decisionsLog,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("desktop-signoff.mjs cursor failed: %v\n%s", err, out)
	}
	for _, want := range []string{"✓ #1 ALLOW-CI: marker", "✓ #2 DENY-CI: no marker", "✓ #3 ASK-CI-APPROVE: see:", "✓ #4 ASK-CI-REJECT: no log human:allow"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestDesktopSignoffClaudeAXDryFlow(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	root := repoRootForTest(t)
	ws := t.TempDir()
	tmp := t.TempDir()
	decisionsLog := filepath.Join(tmp, "decisions.jsonl")
	statePath := filepath.Join(tmp, "ax-state.json")

	// Fake ax-desktop driver simulating Claude Desktop + yolonot --mod across all 10 rows.
	fakeAx := filepath.Join(tmp, "fake-ax")
	fakeScript := fmt.Sprintf(`#!/usr/bin/env python3
import json, os, re, sys

state_path = %q
log_path = %q
args = sys.argv[1:]
cmd = args[0]

def load_state():
    if os.path.exists(state_path):
        return json.load(open(state_path))
    return {"mode": "default", "pending": "", "explained": False, "session_allow": [], "session_deny": []}

def save_state(st):
    json.dump(st, open(state_path, "w"))

def log_dec(file, layer, decision):
    with open(log_path, "a") as f:
        f.write(json.dumps({"command": "touch " + file, "layer": layer, "decision": decision}) + "\n")

st = load_state()
if cmd == "check":
    print("trusted")
elif cmd == "wait-ready":
    print("ready:AXTextArea:100,500")
elif cmd == "claude-mode":
    st["mode"] = args[1]
    save_state(st)
    print("mode:" + args[1])
elif cmd == "send-prompt":
    m = re.search(r"touch ([^\s]+\.marker)", args[2])
    if m:
        f = m.group(1)
        if "ALLOW" in f:
            open(f, "w").close()
            log_dec(f, "rule", "allow")
        elif "DENY" in f:
            log_dec(f, "rule", "deny")
        elif f in st["session_allow"]:
            open(f, "w").close()
            log_dec(f, "session", "allow")
        elif f in st["session_deny"]:
            log_dec(f, "session_deny", "deny")
        else:
            st["pending"] = f
            st["explained"] = False
            log_dec(f, "rule", "ask")
            save_state(st)
    print("sent")
elif cmd == "click-text":
    choice = args[2]
    f = st.get("pending", "")
    if choice == "Allow once" and f:
        open(f, "w").close()
        log_dec(f, "human", "allow")
        st["pending"] = ""
    elif choice == "Allow this session" and f:
        open(f, "w").close()
        log_dec(f, "human", "allow")
        st["session_allow"].append(f)
        st["pending"] = ""
    elif choice == "Deny" and f:
        log_dec(f, "human", "deny")
        st["session_deny"].append(f)
        st["pending"] = ""
    elif choice == "Explain" and f:
        st["explained"] = True
    save_state(st)
    print("clicked:AXButton:" + choice)
elif cmd == "wait-text":
    f = st.get("pending", "")
    if st.get("explained"):
        print(json.dumps(["yolonot: matched rule\n\n$ touch " + f + "\n\nTouches a test marker file inside the temporary workspace."]))
    else:
        print(json.dumps(["Allow once", "Allow this session", "Explain", "Deny"]))
elif cmd == "key":
    st["pending"] = ""
    save_state(st)
    print("key:" + args[2])
`, statePath, decisionsLog)
	if err := os.WriteFile(fakeAx, []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("node", filepath.Join(root, "scripts", "desktop-signoff.mjs"), "claude", ws, tmp)
	cmd.Env = append(os.Environ(),
		"HOME="+tmp,
		"YOLONOT_DESKTOP_SETTLE_MS=50",
		"YOLONOT_AX_DRIVER="+fakeAx,
		"YOLONOT_SKIP_APP_OPEN=1",
		"YOLONOT_DECISIONS_LOG="+decisionsLog,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("desktop-signoff.mjs claude failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"✓ #1 ALLOW-CD: marker",
		"✓ #4 ASK-CD-SESSION: log session:allow",
		"✓ #6 ASK-CD-EXPLAIN: see: An explanation was shown, not an HTTP or credential error?",
		"✓ #7 ASK-CD-ESC: no log session_deny:deny",
		"✓ #10 ASK-CD-AUTO: log human:deny",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAxDesktopSwiftCompiles(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only Swift Accessibility helper")
	}
	if _, err := exec.LookPath("swiftc"); err != nil {
		t.Skip("swiftc not installed")
	}
	// Ensure network-free local compile check succeeds cleanly.
	_, _ = net.LookupHost("localhost")
	root := repoRootForTest(t)
	outBin := filepath.Join(t.TempDir(), "ax-desktop")
	cmd := exec.Command("swiftc", filepath.Join(root, "scripts", "ax-desktop.swift"), "-o", outBin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("swiftc failed: %v\n%s", err, out)
	}
}
