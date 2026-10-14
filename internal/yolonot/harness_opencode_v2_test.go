package yolonot

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the real V2 default definition with a domain/editor fixture that
// uses the upstream Promise API shape. Real OpenCode smoke checks are kept
// separate so ordinary tests need only Bun, not a configured model account.
func TestOpencodeV2PluginNativePermissionLifecycle(t *testing.T) {
	bun, err := exec.LookPath("bun")
	if err != nil {
		t.Skip("Bun is required to execute the OpenCode plugin")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	requests := filepath.Join(home, "requests.jsonl")
	fixture := filepath.Join(home, "hook fixture-with-\"quote")
	const fixtureScript = "#!/bin/sh\ncat >> \"$YOLONOT_SHIM_REQUEST\"\nprintf '\\n' >> \"$YOLONOT_SHIM_REQUEST\"\nprintf '%s\\n' \"$YOLONOT_OPENCODE_API\" >> \"$YOLONOT_SHIM_REQUEST.api\"\nif [ \"$YOLONOT_SHIM_STDERR\" = large ]; then head -c 131072 /dev/zero >&2; fi\nprintf '%s' \"$YOLONOT_SHIM_REPLY\"\n"
	if err := os.WriteFile(fixture, []byte(fixtureScript), 0700); err != nil {
		t.Fatal(err)
	}
	h := &OpencodeHarness{}
	if err := h.Install(fixture); err != nil {
		t.Fatal(err)
	}
	pluginPath, _ := json.Marshal(h.SettingsPath())
	driver := "import plugin from " + string(pluginPath) + `;
const spec = JSON.parse(process.argv[2]);
const hooks = [];
let executed = false, effect = "", error = "";
const ctx = {sessionID: "native-session", id: "native-call"};
const tool = {id: "shell", name: "shell", execute: async (input, context) => {
  const event = {action: "shell", sessionID: context.sessionID,
    source: {type: "tool", id: context.id}, effect: spec.hostEffect};
  for (const hook of hooks) await hook(event);
  effect = event.effect;
  if (effect === "deny" || (effect === "ask" && spec.reject)) throw new Error("host rejected");
  executed = true;
  return {output: {output: "ok", exit: 0}};
}};
const dispose = await plugin.setup({
  location: {directory: spec.directory},
  permission: {hook: async (name, callback) => {
    if (name !== "evaluate") throw new Error("unexpected permission hook");
    hooks.push(callback);
  }},
  tool: {transform: async callback => callback({
    list: () => [tool], update: (id, callback) => callback(tool),
  })},
});
const input = {command: "original-command", workdir: "child"};
// All execute.before middleware runs before the transformed executor.
if (spec.rewrite) input.command = spec.rewrite;
try { await tool.execute(input, ctx); } catch (e) { error = String(e); }
const after = {action: "shell", sessionID: ctx.sessionID,
  source: {type: "tool", id: ctx.id}, effect: "allow"};
for (const hook of hooks) await hook(after);
dispose();
console.log(JSON.stringify({error, executed, effect, cleaned: after.effect === "allow"}));
`
	driverPath := filepath.Join(home, "driver.ts")
	if err := os.WriteFile(driverPath, []byte(driver), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, decision, hostEffect, wantEffect, rewrite string
		reject, blocked, executed, stderr               bool
		wantRequests                                    int
	}{
		{"allow removes native ask", ActionAllow, ActionAsk, ActionAllow, "", false, false, true, false, 2},
		{"native ask approved", ActionAsk, ActionAllow, ActionAsk, "", false, false, true, false, 2},
		{"native ask rejected", ActionAsk, ActionAllow, ActionAsk, "", true, true, false, false, 1},
		{"deny before execution", ActionDeny, ActionAllow, "", "", false, true, false, false, 1},
		{"upstream deny is preserved", ActionAllow, ActionDeny, ActionDeny, "", false, true, false, false, 1},
		{"empty passthrough preserves native ask", "", ActionAsk, ActionAsk, "", false, false, true, false, 2},
		{"rewritten final input is judged", ActionDeny, ActionAllow, "", "forbidden-final-command", false, true, false, false, 1},
		{"large stderr does not hang", ActionAllow, ActionAsk, ActionAllow, "", false, false, true, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(requests, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(requests+".api", nil, 0600); err != nil {
				t.Fatal(err)
			}
			reply := ""
			if tc.decision != "" {
				reply = `{"hookSpecificOutput":{"permissionDecision":"` + tc.decision + `","permissionDecisionReason":"native fixture"}}`
			}
			spec, _ := json.Marshal(map[string]interface{}{
				"directory": home, "hostEffect": tc.hostEffect, "reject": tc.reject, "rewrite": tc.rewrite,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bun, "run", driverPath, string(spec))
			cmd.Env = append(os.Environ(), "YOLONOT_SHIM_REQUEST="+requests, "YOLONOT_SHIM_REPLY="+reply)
			if tc.stderr {
				cmd.Env = append(cmd.Env, "YOLONOT_SHIM_STDERR=large")
			}
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("V2 runtime failed: %v\n%s", err, output)
			}
			var result struct {
				Error             string
				Effect            string
				Executed, Cleaned bool
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("invalid V2 result: %v\n%s", err, output)
			}
			if (result.Error != "") != tc.blocked || result.Executed != tc.executed || result.Effect != tc.wantEffect || !result.Cleaned {
				t.Fatalf("unexpected native lifecycle: %+v", result)
			}
			data, err := os.ReadFile(requests)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) != tc.wantRequests {
				t.Fatalf("requests=%d, want %d: %s", len(lines), tc.wantRequests, data)
			}
			var payload HookPayload
			if err := json.Unmarshal([]byte(lines[0]), &payload); err != nil {
				t.Fatal(err)
			}
			wantCommand := "original-command"
			if tc.rewrite != "" {
				wantCommand = tc.rewrite
			}
			if payload.Cwd != filepath.Join(home, "child") || payload.SessionID != "native-session" || payload.ToolInput["command"] != wantCommand {
				t.Fatalf("wrong final shell context: %+v", payload)
			}
			api, err := os.ReadFile(requests + ".api")
			if err != nil || string(api) != strings.Repeat("2\n", tc.wantRequests) {
				t.Fatalf("V2 capability marker lost: %q, %v", api, err)
			}
		})
	}
}
