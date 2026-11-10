package yolonot

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	realProcessEnv  = os.Environ()
	shimTestBinOnce sync.Once
	shimTestBinPath string
	shimTestBinErr  error
)

func shimTestYolonotBinary(t *testing.T) string {
	t.Helper()
	shimTestBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "yolonot-shim-bin-")
		if err != nil {
			shimTestBinErr = err
			return
		}
		bin := filepath.Join(dir, "yolonot")
		cmd := exec.Command("go", "build", "-o", bin, "../..")
		cmd.Env = realProcessEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			os.RemoveAll(dir)
			shimTestBinErr = err
			_ = out
			return
		}
		shimTestBinPath = bin
	})
	if shimTestBinErr != nil {
		t.Fatalf("build yolonot test binary: %v", shimTestBinErr)
	}
	return shimTestBinPath
}

func TestGroupDHarnessesLifecycleAndProtocol(t *testing.T) {
	home, _ := withFakeHome(t)

	for alias, canonical := range map[string]string{
		"kilocode":          "kilo",
		"kilo-code":         "kilo",
		"open-claw":         "openclaw",
		"pi-coding-agent":   "pi",
		"reflection-mirror": "mirror",
		"ampcode":           "amp",
	} {
		h := GetHarness(alias)
		if h == nil || h.Name() != canonical {
			t.Fatalf("GetHarness(%q) = %v, want %q", alias, h, canonical)
		}
	}

	for _, name := range []string{"kilo", "openclaw", "pi", "mirror", "amp"} {
		h := GetHarness(name)
		if h == nil {
			t.Fatalf("missing harness %s", name)
		}
		if h.IsInstalled() {
			t.Fatalf("%s should not be installed initially", name)
		}
		if err := h.Install("/usr/local/bin/yolonot"); err != nil {
			t.Fatalf("%s Install() failed: %v", name, err)
		}
		if !h.IsInstalled() {
			t.Fatalf("%s should be installed after Install()", name)
		}
		if !h.IsDetected() {
			t.Fatalf("%s should be detected in %s after Install()", name, home)
		}
		if _, err := h.InstallSkill(); err != nil {
			t.Fatalf("%s InstallSkill() failed: %v", name, err)
		}
		if err := h.UninstallSkill(); err != nil {
			t.Fatalf("%s UninstallSkill() failed: %v", name, err)
		}
		if err := h.Uninstall(); err != nil {
			t.Fatalf("%s Uninstall() failed: %v", name, err)
		}
		if h.IsInstalled() {
			t.Fatalf("%s should not be installed after Uninstall()", name)
		}
	}

	// OpenClaw elevated / gateway host sandbox bypass detection + ctx sessionId/cwd in shim
	oc := GetHarness("openclaw")
	if err := oc.Install("/usr/local/bin/yolonot"); err != nil {
		t.Fatalf("openclaw Install: %v", err)
	}
	ocShim, err := os.ReadFile(filepath.Join(home, ".openclaw", "extensions", "yolonot", "index.js"))
	if err != nil || !strings.Contains(string(ocShim), "ctx.sessionId") || !strings.Contains(string(ocShim), "ctx.cwd") {
		t.Fatalf("openclaw index.js missing ctx.sessionId / ctx.cwd: err=%v, body=%s", err, string(ocShim))
	}
	_ = oc.Uninstall()
	ocp, err := oc.ParseHookInput([]byte(`{"hook_event_name":"PreToolUse","tool_name":"exec","session_id":"oc1","cwd":"/tmp/ws","tool_input":{"command":"docker ps","elevated":true}}`))
	if err != nil || ocp.ToolInput["command"] != "docker ps" || !ocp.BypassSandbox {
		t.Fatalf("openclaw elevated parse failed: %+v, err=%v", ocp, err)
	}
	ocpHost, err := oc.ParseHookInput([]byte(`{"hook_event_name":"PreToolUse","tool_name":"exec","session_id":"oc1","cwd":"/tmp/ws","tool_input":{"command":"docker ps","host":"gateway"}}`))
	if err != nil || !ocpHost.BypassSandbox {
		t.Fatalf("openclaw gateway host parse failed: %+v, err=%v", ocpHost, err)
	}

	// Amp cmd field normalization
	amp := GetHarness("amp")
	ap, err := amp.ParseHookInput([]byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"amp1","cwd":"/tmp/ws","tool_input":{"cmd":"pnpm test"}}`))
	if err != nil || ap.ToolInput["command"] != "pnpm test" {
		t.Fatalf("amp cmd parse failed: %+v, err=%v", ap, err)
	}
	if got := amp.FormatHookResponse(makeHookResp("PreToolUse", ActionAsk, "confirm")); !strings.Contains(got, `"permissionDecision":"ask"`) {
		t.Fatalf("amp ask = %s", got)
	}
}

func TestGroupDDiscoverHostPermissions(t *testing.T) {
	home, _ := withFakeHome(t)
	ws := filepath.Join(home, "workspace")
	_ = os.MkdirAll(ws, 0o755)

	// Kilo Code
	kiloDir := filepath.Join(home, ".config", "kilo")
	_ = os.MkdirAll(kiloDir, 0o755)
	_ = os.WriteFile(filepath.Join(kiloDir, "kilo.json"), []byte(`{"permission":{"bash":"allow"},"sandbox":{"enabled":false}}`), 0o600)

	// OpenClaw
	ocDir := filepath.Join(home, ".openclaw")
	_ = os.MkdirAll(ocDir, 0o755)
	_ = os.WriteFile(filepath.Join(ocDir, "openclaw.json"), []byte(`{"tools":{"exec":{"mode":"full","safeBins":["git"]}},"agents":{"defaults":{"sandbox":{"mode":"off"}}}}`), 0o600)

	// Pi
	piDir := filepath.Join(home, ".pi", "agent")
	_ = os.MkdirAll(piDir, 0o755)
	_ = os.WriteFile(filepath.Join(piDir, "settings.json"), []byte(`{"defaultProjectTrust":"always"}`), 0o600)

	// Mirror
	mirrorDir := filepath.Join(home, ".mirror")
	_ = os.MkdirAll(mirrorDir, 0o755)
	_ = os.WriteFile(filepath.Join(mirrorDir, "config.json"), []byte(`{"approval_mode":"auto"}`), 0o600)

	// Amp
	ampDir := filepath.Join(home, ".config", "amp")
	_ = os.MkdirAll(ampDir, 0o755)
	_ = os.WriteFile(filepath.Join(ampDir, "settings.json"), []byte(`{"amp.dangerouslyAllowAll":true,"amp.permissions":[{"tool":"Bash","action":"reject","matches":{"cmd":"rm -rf *"}}]}`), 0o600)

	summary := DiscoverHostPermissions(ws)
	found := map[string]bool{}
	for _, hf := range summary.HostFiles {
		found[hf.Harness] = true
	}
	for _, name := range []string{"kilo", "openclaw", "pi", "mirror", "amp"} {
		if !found[name] {
			t.Errorf("DiscoverHostPermissions did not find %s; got %+v", name, summary.HostFiles)
		}
	}
}

func TestPluginShimsHumanResolutionLifecycle(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()
	ws := filepath.Join(home, "workspace")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	writeGlobalRules(t, home, "allow-cmd touch *\nask-cmd git push *\ndeny-cmd rm -rf /*\n")

	wrapperPath := shimTestYolonotBinary(t)

	if nodeBin, err := exec.LookPath("node"); err == nil {
		for _, name := range []string{"openclaw", "pi", "amp"} {
			if err := GetHarness(name).Install(wrapperPath); err != nil {
				t.Fatalf("Install(%s): %v", name, err)
			}
		}

		// 1. OpenClaw: onResolution("allow-always") -> ask_approved + session allow on replay;
		//    onResolution("deny") -> ask_rejected + session_deny on replay.
		ocShim := GetHarness("openclaw").SettingsPath()
		ocDriver := filepath.Join(home, "oc-driver.mjs")
		ocCode := `import register from ` + mustJSONQuote(ocShim) + `;
let beforeFn, afterFn;
register({ on(ev, cb) { if (ev === "before_tool_call") beforeFn = cb; if (ev === "after_tool_call") afterFn = cb; } });
const ctx = { sessionId: "oc-res-1", cwd: ` + mustJSONQuote(ws) + ` };
const askAlways = await beforeFn({ toolName: "exec", toolCallId: "oc-1", params: { command: "git push origin oc-always" } }, ctx);
if (typeof askAlways?.requireApproval?.onResolution === "function") {
  askAlways.requireApproval.onResolution("allow-always");
}
await afterFn({ toolName: "exec", toolCallId: "oc-1", params: { command: "git push origin oc-always" } }, ctx);
const replayAlways = await beforeFn({ toolName: "exec", toolCallId: "oc-2", params: { command: "git push origin oc-always" } }, ctx);

const askOnce = await beforeFn({ toolName: "exec", toolCallId: "oc-once-1", params: { command: "git push origin oc-once" } }, ctx);
if (typeof askOnce?.requireApproval?.onResolution === "function") {
  askOnce.requireApproval.onResolution("allow-once");
}
await afterFn({ toolName: "exec", toolCallId: "oc-once-1", params: { command: "git push origin oc-once" } }, ctx);

const askDeny = await beforeFn({ toolName: "exec", toolCallId: "oc-3", params: { command: "git push origin oc-reject" } }, ctx);
if (typeof askDeny?.requireApproval?.onResolution === "function") {
  askDeny.requireApproval.onResolution("deny");
}
const replayDeny = await beforeFn({ toolName: "exec", toolCallId: "oc-4", params: { command: "git push origin oc-reject" } }, ctx);
console.log(JSON.stringify({ replayAlways: replayAlways || null, replayDeny: replayDeny || null }));
`
		if err := os.WriteFile(ocDriver, []byte(ocCode), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(nodeBin, ocDriver)
		cmd.Env = append(os.Environ(), "HOME="+home, "YOLONOT_TEST_SHIM_CLI_HELPER=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("openclaw node driver failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), `"replayAlways":null`) || !strings.Contains(string(out), `"block":true`) {
			t.Fatalf("openclaw resolution replay unexpected: %s", out)
		}
		ocProj := ProjectSessionID("oc-res-1", ws)
		if ContainsLine(ocProj, "once", "git push origin oc-once") {
			t.Fatalf("openclaw allow-once with completed=true must not leave stranded .once marker")
		}

		// 2. Pi: ctx.ui.select("Allow for session") -> ask_approved + session allow on replay;
		//    unsandboxed Allow for session -> isolated in .approved_unsandboxed (never .approved);
		//    script modified during dialog -> downgraded to allow-once (not persisted to .approved);
		//    ctx.ui.confirm() == false -> ask_rejected + session_deny on replay.
		writeGlobalRules(t, home, "ask-cmd git push *\nask-cmd bash *\n")
		dialogScript := filepath.Join(ws, "deploy.sh")
		if err := os.WriteFile(dialogScript, []byte("echo safe-v1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		piShim := GetHarness("pi").SettingsPath()
		piDriver := filepath.Join(home, "pi-driver.mjs")
		piCode := `import { writeFileSync } from "node:fs";
import register from ` + mustJSONQuote(piShim) + `;
let fn;
register({ on(ev, cb) { if (ev === "tool_call") fn = cb; } });
const sidMgr = { getSessionId() { return "pi-res-1"; } };
const selectSession = await fn({ toolName: "bash", toolCallId: "pi-1", input: { command: "git push origin pi-sess" } }, { hasUI: true, cwd: ` + mustJSONQuote(ws) + `, sessionManager: sidMgr, ui: { async select() { return "Allow for session"; } } });
const replaySession = await fn({ toolName: "bash", toolCallId: "pi-2", input: { command: "git push origin pi-sess" } }, { hasUI: true, cwd: ` + mustJSONQuote(ws) + `, sessionManager: sidMgr, ui: { async confirm() { return false; } } });
const unsandboxedSession = await fn({ toolName: "bash", toolCallId: "pi-u1", input: { command: "git push origin pi-unsb", dangerouslyDisableSandbox: true } }, { hasUI: true, cwd: ` + mustJSONQuote(ws) + `, sessionManager: sidMgr, ui: { async select() { return "Allow for session"; } } });
const toctouSession = await fn({ toolName: "bash", toolCallId: "pi-t1", input: { command: "bash ./deploy.sh" } }, { hasUI: true, cwd: ` + mustJSONQuote(ws) + `, sessionManager: sidMgr, ui: { async select() { writeFileSync(` + mustJSONQuote(dialogScript) + `, "echo swapped-v2\n"); return "Allow for session"; } } });
const rejectOnce = await fn({ toolName: "bash", toolCallId: "pi-3", input: { command: "git push origin pi-deny" } }, { hasUI: true, cwd: ` + mustJSONQuote(ws) + `, sessionManager: sidMgr, ui: { async confirm() { return false; } } });
const replayReject = await fn({ toolName: "bash", toolCallId: "pi-4", input: { command: "git push origin pi-deny" } }, { hasUI: true, cwd: ` + mustJSONQuote(ws) + `, sessionManager: sidMgr, ui: { async confirm() { return true; } } });
console.log(JSON.stringify({ selectSession: selectSession || null, replaySession: replaySession || null, unsandboxedSession: unsandboxedSession || null, toctouSession: toctouSession || null, rejectOnce: rejectOnce || null, replayReject: replayReject || null }));
`
		if err := os.WriteFile(piDriver, []byte(piCode), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd = exec.Command(nodeBin, piDriver)
		cmd.Env = append(os.Environ(), "HOME="+home, "YOLONOT_TEST_SHIM_CLI_HELPER=1")
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("pi node driver failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), `"selectSession":null`) || !strings.Contains(string(out), `"replaySession":null`) || !strings.Contains(string(out), "previously rejected this session") {
			t.Fatalf("pi resolution replay unexpected: %s", out)
		}
		piProj := ProjectSessionID("pi-res-1", ws)
		if !ContainsLine(piProj, "approved_unsandboxed", "git push origin pi-unsb") || ContainsLine(piProj, "approved", "git push origin pi-unsb") {
			t.Fatalf("unsandboxed Pi session approval must write to .approved_unsandboxed only")
		}
		if ContainsLine(piProj, "approved", "bash ./deploy.sh") {
			t.Fatalf("TOCTOU script edit during Pi dialog must downgrade allow-session to allow-once")
		}

		// 3. Amp: ctx.ui.confirm() == false -> ask_rejected + session_deny on replay.
		ampShim := GetHarness("amp").SettingsPath()
		ampDriver := filepath.Join(home, "amp-driver.mjs")
		ampCode := `import register from ` + mustJSONQuote(ampShim) + `;
let fn;
register({ on(ev, cb) { if (ev === "tool.call") fn = cb; } });
const reject1 = await fn({ id: "amp-1", tool: "Bash", input: { cmd: "git push origin amp-reject", cwd: ` + mustJSONQuote(ws) + ` } }, { threadId: "amp-res-1", ui: { async confirm() { return false; } } });
const replay2 = await fn({ id: "amp-2", tool: "Bash", input: { cmd: "git push origin amp-reject", cwd: ` + mustJSONQuote(ws) + ` } }, { threadId: "amp-res-1", ui: { async confirm() { return true; } } });
console.log(JSON.stringify({ reject1, replay2 }));
`
		if err := os.WriteFile(ampDriver, []byte(ampCode), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd = exec.Command(nodeBin, ampDriver)
		cmd.Env = append(os.Environ(), "HOME="+home, "YOLONOT_TEST_SHIM_CLI_HELPER=1")
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("amp node driver failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), `"Denied by user"`) || !strings.Contains(string(out), "previously rejected this session") {
			t.Fatalf("amp resolution replay unexpected: %s", out)
		}
	}

	// 4. Mirror Python extension shim: DecideApproval(approved=False) -> ask_rejected + session_deny;
	//    DecideApproval(approved=True, remember=True) -> ask_approved + session allow.
	pyBin := "/usr/bin/python3"
	if exec.Command(pyBin, "-c", "pass").Run() != nil {
		pyBin, _ = exec.LookPath("python3")
	}
	if pyBin != "" && exec.Command(pyBin, "-c", "pass").Run() == nil {
		if err := GetHarness("mirror").Install(wrapperPath); err != nil {
			t.Fatalf("Install(mirror): %v", err)
		}
		mirrorShim := GetHarness("mirror").SettingsPath()
		pyDriver := filepath.Join(home, "mirror-driver.py")
		pyCode := `import asyncio, importlib.util, json, sys, types
actions_mod = types.ModuleType("mirror.cli.actions")
class ApprovalRequest:
    def __init__(self, call_id, name, args):
        self.call_id, self.name, self.args = call_id, name, args
class ApprovalRequested:
    def __init__(self, request):
        self.request = request
class DecideApproval:
    def __init__(self, approved, call_id, remember=False):
        self.approved, self.call_id, self.remember = approved, call_id, remember
actions_mod.ApprovalRequest = ApprovalRequest
actions_mod.ApprovalRequested = ApprovalRequested
actions_mod.DecideApproval = DecideApproval

ext_mod = types.ModuleType("mirror.cli.extension")
class Extension:
    def effect(self, payload):
        return types.SimpleNamespace(payload=payload)
ext_mod.Extension = Extension

mirror_pkg = types.ModuleType("mirror")
cli_pkg = types.ModuleType("mirror.cli")
cli_pkg.actions = actions_mod
cli_pkg.extension = ext_mod
sys.modules["mirror"] = mirror_pkg
sys.modules["mirror.cli"] = cli_pkg
sys.modules["mirror.cli.actions"] = actions_mod
sys.modules["mirror.cli.extension"] = ext_mod

spec = importlib.util.spec_from_file_location("yolonot_mirror", ` + mustJSONQuote(mirrorShim) + `)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

async def main():
    ext = mod.YolonotExtension()
    st = types.SimpleNamespace(extensions={"yolonot": {}})
    dispatched = []
    class Ctx:
        workspace = types.SimpleNamespace(cwd=` + mustJSONQuote(ws) + `)
        def dispatch(self, act): dispatched.append((act.call_id, act.approved))
    ctx = Ctx()
    # 1) Ask + human reject -> session_deny on replay
    _, effs = ext.reduce(st, ApprovalRequested(ApprovalRequest("m1", "bash", json.dumps({"command": "git push origin m-reject"}))))
    await ext.handle_effect(ctx, effs[0].payload)
    _, post_effs = ext.reduce(st, DecideApproval(approved=False, call_id="m1"))
    for e in post_effs:
        await ext.handle_effect(ctx, e.payload)
    _, effs2 = ext.reduce(st, ApprovalRequested(ApprovalRequest("m2", "bash", json.dumps({"command": "git push origin m-reject"}))))
    await ext.handle_effect(ctx, effs2[0].payload)

    # 2) Ask + human approve with remember=True -> session allow on replay
    _, effs3 = ext.reduce(st, ApprovalRequested(ApprovalRequest("m3", "bash", json.dumps({"command": "git push origin m-session"}))))
    await ext.handle_effect(ctx, effs3[0].payload)
    _, post_effs3 = ext.reduce(st, DecideApproval(approved=True, call_id="m3", remember=True))
    for e in post_effs3:
        await ext.handle_effect(ctx, e.payload)
    _, effs4 = ext.reduce(st, ApprovalRequested(ApprovalRequest("m4", "bash", json.dumps({"command": "git push origin m-session"}))))
    await ext.handle_effect(ctx, effs4[0].payload)
    print(json.dumps(dispatched))

asyncio.run(main())
`
		if err := os.WriteFile(pyDriver, []byte(pyCode), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(pyBin, pyDriver)
		cmd.Env = append(os.Environ(), "HOME="+home, "YOLONOT_MIRROR_SESSION_ID=mirror-res-1", "YOLONOT_TEST_SHIM_CLI_HELPER=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("mirror python driver failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), `["m2", false]`) || !strings.Contains(string(out), `["m4", true]`) {
			t.Fatalf("mirror resolution replay unexpected: %s", out)
		}
	}
}

func mustJSONQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
