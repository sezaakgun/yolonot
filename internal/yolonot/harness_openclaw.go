package yolonot

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

func init() { RegisterHarness(newOpenclawHarness()) }

type OpenclawHarness struct{ baseHarness }

func openclawConfigDir() string {
	return xdgOrHomeConfigDir([]string{"OPENCLAW_STATE_DIR"}, "", ".openclaw")
}

func newOpenclawHarness() *OpenclawHarness {
	h := &OpenclawHarness{
		baseHarness: baseHarness{
			name:           "openclaw",
			supportsAsk:    true,
			sessionEnvKeys: []string{"YOLONOT_OPENCLAW_SESSION_ID", "OPENCLAW_SESSION_ID"},
			configDirFn:    openclawConfigDir,
			settingsPathFn: func() string { return filepath.Join(openclawConfigDir(), "extensions", "yolonot", "index.js") },
			riskMap:        claudeCompatRiskMap(),
			parseFn: func(input []byte) (HookPayload, error) {
				p, err := parseFlexibleHookPayload(input)
				if err != nil {
					return p, err
				}
				if b, ok := p.ToolInput["elevated"].(bool); ok && b {
					p.BypassSandbox = true
				}
				if host, ok := p.ToolInput["host"].(string); ok && (host == "gateway" || host == "node") {
					p.BypassSandbox = true
				}
				return p, nil
			},
			formatFn: formatCanonicalPluginResponse,
			notesFn: func(settingsPath string) []string {
				return []string{
					fmt.Sprintf("OpenClaw extension installed at %s (auto-enabled on startup).", filepath.Dir(settingsPath)),
				}
			},
		},
	}
	h.useShimFileHooks(shimFileHooksSpec{
		marker:               "// yolonot — OpenClaw plugin shim",
		removeDirOnUninstall: true,
		buildShim: func(settingsPath, binaryPath string) ([]byte, error) {
			extDir := filepath.Dir(settingsPath)
			manifest := `{"id":"yolonot","configSchema":{"type":"object","additionalProperties":false},"activation":{"onStartup":true,"onCapabilities":["hook"]}}` + "\n"
			if err := atomicWriteFile(filepath.Join(extDir, "openclaw.plugin.json"), []byte(manifest), 0o644); err != nil {
				return nil, err
			}
			quotedBin, _ := json.Marshal(binaryPath)
			js := fmt.Sprintf(`// yolonot — OpenClaw plugin shim
import { spawnSync } from "node:child_process";
const BIN = %s;
function runHook(payload) {
  const res = spawnSync(BIN, ["hook", "--harness", "openclaw"], { input: JSON.stringify(payload), encoding: "utf8", timeout: 60000 });
  if (res.error || res.status !== 0) return { permissionDecision: "deny", permissionDecisionReason: (res.stderr || "").trim() || (res.error && res.error.message) || "Blocked by yolonot" };
  const raw = (res.stdout || "").trim();
  if (!raw) return {};
  try { return JSON.parse(raw).hookSpecificOutput || {}; } catch { return { permissionDecision: "deny", permissionDecisionReason: "Blocked by yolonot (invalid hook response)" }; }
}
export default function register(api) {
  const pendingAsk = new Set();
  api.on("before_tool_call", async (event, ctx) => {
    if (event.toolName !== "exec" && event.name !== "exec") return;
    const params = event.params || event.input || {};
    const sid = (ctx && (ctx.sessionId || ctx.sessionKey || ctx.runId)) || event.sessionId || "";
    const cwd = (ctx && (ctx.cwd || ctx.workspaceDir)) || process.cwd();
    const callKey = (event.toolCallId || "") + ":" + String(params.command || "");
    const out = runHook({ hook_event_name: "PreToolUse", tool_name: "exec", session_id: sid, tool_use_id: event.toolCallId || "", cwd, tool_input: params });
    if (out.permissionDecision === "deny") return { block: true, blockReason: out.permissionDecisionReason || "Blocked by yolonot" };
    if (out.permissionDecision === "ask") {
      pendingAsk.add(callKey);
      const desc = out.permissionDecisionReason ? String(params.command || "") + "\n" + out.permissionDecisionReason : String(params.command || "");
      return { requireApproval: { title: "Allow command?", description: desc, severity: "warning", allowedDecisions: ["allow-once", "allow-always", "deny"] } };
    }
  }, { priority: 100 });
  api.on("after_tool_call", async (event, ctx) => {
    if (event.toolName !== "exec" && event.name !== "exec") return;
    const params = event.params || event.input || {};
    const callKey = (event.toolCallId || "") + ":" + String(params.command || "");
    if (!pendingAsk.delete(callKey)) return;
    if (event.error || event.blocked || event.cancelled) return;
    const sid = (ctx && (ctx.sessionId || ctx.sessionKey || ctx.runId)) || event.sessionId || "";
    const cwd = (ctx && (ctx.cwd || ctx.workspaceDir)) || process.cwd();
    runHook({ hook_event_name: "PostToolUse", tool_name: "exec", session_id: sid, tool_use_id: event.toolCallId || "", cwd, tool_input: params });
  });
}
`, string(quotedBin))
			return []byte(js), nil
		},
	})
	return h
}
