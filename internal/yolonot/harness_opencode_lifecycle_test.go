package yolonot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func installedOpencodeDriver(t *testing.T, binary string) func(event, cwd string, env ...string) string {
	t.Helper()
	bun, err := exec.LookPath("bun")
	if err != nil {
		t.Skip("Bun is required to execute the OpenCode plugin")
	}
	h := &OpencodeHarness{}
	if err := h.Install(binary); err != nil {
		t.Fatal(err)
	}
	pluginPath, _ := json.Marshal(h.SettingsPath())
	driver := "import { YolonotPlugin } from " + string(pluginPath) + `;
const hooks = await YolonotPlugin({});
const spec = JSON.parse(process.argv[2]);
const args = {command: "my-tool --probe", cwd: spec.cwd};
let error = "";
try {
  await hooks[spec.event](
    {tool: "bash", sessionID: "shim-session", args},
    spec.event === "tool.execute.before"
      ? {args}
      : {title: "probe title", output: "probe output"}
  );
} catch (e) { error = String(e); }
console.log(JSON.stringify({error}));
`
	driverPath := filepath.Join(t.TempDir(), "driver.ts")
	if err := os.WriteFile(driverPath, []byte(driver), 0600); err != nil {
		t.Fatal(err)
	}
	return func(event, cwd string, env ...string) string {
		t.Helper()
		spec, _ := json.Marshal(map[string]string{"event": event, "cwd": cwd})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bun, "run", driverPath, string(spec))
		cmd.Env = append(os.Environ(), env...)
		cmd.Dir = filepath.Dir(driverPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cannot execute installed shim: %v\n%s", err, output)
		}
		var result struct{ Error string }
		if err := json.Unmarshal(output, &result); err != nil {
			t.Fatalf("invalid driver result: %v\n%s", err, output)
		}
		return result.Error
	}
}

// Run the real Go hook beneath the installed TS shim. Only the provider and
// OpenCode host are fixtures; all yolonot decision/format/bridge code runs.
func TestOpencodePluginRealHookFallback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		rules   string
		reason  string
		blocked bool
	}{
		{"unavailable model", http.StatusServiceUnavailable, "", "HTTP 503", false},
		{"parse failed model", http.StatusOK, "", "parse error", false},
		{"deny remains enforced", http.StatusOK, "deny-cmd my-tool*\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, cleanup := withFakeHome(t)
			defer cleanup()
			t.Setenv("YOLONOT_DISABLED", "")
			t.Setenv("YOLONOT_MOD", "")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, `{"choices":[{"message":{"content":"invalid decision"}}]}`)
			}))
			defer server.Close()
			SaveConfig(Config{
				Models:  map[string]ModelConfig{"chat": {URL: server.URL, Model: "test"}},
				Judges:  JudgeList{{Use: "chat"}},
				Failure: FailurePolicy{Unavailable: ActionPassthrough, Parse: ActionPassthrough},
			})
			writeGlobalRules(t, home, tc.rules)
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			wrapperPath := filepath.Join(home, "hook-entrypoint")
			// The helper exits before Go's test runner writes PASS to stdout.
			quotedExecutable := "'" + strings.ReplaceAll(executable, "'", "'\"'\"'") + "'"
			wrapper := "#!/bin/sh\nexec " + quotedExecutable + " -test.run=^TestOpencodeRealHookHelperProcess$\n"
			if err := os.WriteFile(wrapperPath, []byte(wrapper), 0700); err != nil {
				t.Fatal(err)
			}
			runShim := installedOpencodeDriver(t, wrapperPath)
			shimErr := runShim("tool.execute.before", home, "YOLONOT_TEST_OPENCODE_HOOK_HELPER=1")
			if blocked := shimErr != ""; blocked != tc.blocked {
				t.Fatalf("blocked=%v, want %v: %s", blocked, tc.blocked, shimErr)
			}
			entries := ReadRecentDecisions(1)
			if len(entries) != 1 {
				t.Fatalf("real hook did not log its result: %+v", entries)
			}
			wantDecision := "passthrough"
			if tc.blocked {
				wantDecision = ActionDeny
			}
			if entries[0].Decision != wantDecision || !strings.Contains(entries[0].Reasoning, tc.reason) {
				t.Fatalf("unexpected actual hook result: %+v", entries[0])
			}
		})
	}
}

func TestOpencodeRealHookHelperProcess(t *testing.T) {
	if os.Getenv("YOLONOT_TEST_OPENCODE_HOOK_HELPER") != "1" {
		return
	}
	cmdHook()
	os.Exit(0)
}
