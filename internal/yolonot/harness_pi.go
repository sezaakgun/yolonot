package yolonot

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

func init() { RegisterHarness(newPiHarness()) }

type PiHarness struct{ baseHarness }

func piConfigDir() string {
	return xdgOrHomeConfigDir([]string{"PI_CODING_AGENT_DIR"}, "", filepath.Join(".pi", "agent"))
}

func newPiHarness() *PiHarness {
	h := &PiHarness{
		baseHarness: baseHarness{
			name:           "pi",
			supportsAsk:    true,
			sessionEnvKeys: []string{"YOLONOT_PI_SESSION_ID", "PI_SESSION_ID"},
			configDirFn:    piConfigDir,
			settingsPathFn: func() string { return filepath.Join(piConfigDir(), "extensions", "yolonot.ts") },
			riskMap:        claudeCompatRiskMap(),
			formatFn:       formatCanonicalPluginResponse,
			notesFn: func(settingsPath string) []string {
				return []string{
					fmt.Sprintf("Pi extension installed at %s.", settingsPath),
					"Note: Pi has no built-in confirmation prompt or OS sandbox without an extension; yolonot provides both ask prompts (via ctx.ui.confirm) and hard blocks.",
				}
			},
		},
	}
	h.useShimFileHooks(shimFileHooksSpec{
		marker: "// yolonot — Pi extension shim",
		buildShim: func(_, binaryPath string) ([]byte, error) {
			quotedBin, _ := json.Marshal(binaryPath)
			ts := fmt.Sprintf(`// yolonot — Pi extension shim
import { spawnSync } from "node:child_process";
const BIN = %s;
export default function (pi: any) {
  pi.on("tool_call", async (event: any, ctx: any) => {
    const tool = event.toolName || event.name || "";
    if (tool !== "bash" && tool !== "powershell") return;
    const input = event.input || {};
    const sid = (ctx && ctx.sessionManager && typeof ctx.sessionManager.getSessionId === "function" && ctx.sessionManager.getSessionId()) || process.env.YOLONOT_PI_SESSION_ID || process.env.PI_SESSION_ID || process.env.YOLONOT_FORCE_SESSION_ID || "";
    const payload = { hook_event_name: "PreToolUse", tool_name: tool, tool_use_id: event.toolCallId || "", session_id: sid, cwd: (ctx && ctx.cwd) || process.cwd(), tool_input: input };
    const res = spawnSync(BIN, ["hook", "--harness", "pi"], { input: JSON.stringify(payload), encoding: "utf8", timeout: 60000 });
    const raw = (res.stdout || "").trim();
    let out: any = {};
    if (raw) {
      try { out = JSON.parse(raw).hookSpecificOutput || {}; } catch { return { block: true, reason: "Blocked by yolonot (invalid hook response)" }; }
    }
    if (res.error || res.status !== 0 || out.permissionDecision === "deny") {
      return { block: true, reason: out.permissionDecisionReason || (res.stderr || "").trim() || (res.error && res.error.message) || "Blocked by yolonot" };
    }
    if (out.permissionDecision === "ask") {
      if (!ctx || !ctx.hasUI || (!ctx.ui?.confirm && !ctx.ui?.select)) return { block: true, reason: out.permissionDecisionReason || "Approval required in non-interactive mode" };
      const cmdStr = String(input.command || "");
      const detail = out.permissionDecisionReason ? cmdStr + "\n" + out.permissionDecisionReason : cmdStr;
      let verdict = "deny";
      if (typeof ctx.ui.select === "function") {
        const choice = await ctx.ui.select("yolonot: " + detail, ["Allow once", "Allow for session", "Deny"]);
        verdict = choice === "Allow for session" ? "allow-session" : choice === "Allow once" ? "allow-once" : "deny";
      } else {
        const ok = await ctx.ui.confirm("yolonot: Allow command?", detail);
        verdict = ok ? "allow-once" : "deny";
      }
      const bypass = Boolean(input.dangerouslyDisableSandbox || input.BypassSandbox || input.sandbox === false || input.with_escalated_permissions === true || input.sandbox_permissions === "require_escalated");
      if (verdict === "deny") {
        if (sid) {
          spawnSync(BIN, ["mod", "resolve"], { input: JSON.stringify({ harness: "pi", session_id: sid, tool_use_id: event.toolCallId || "pi-ask", cwd: payload.cwd, command: cmdStr, verdict: "deny", bypass_sandbox: bypass, completed: true }), encoding: "utf8", timeout: 60000 });
        }
        return { block: true, reason: "Denied by user" };
      }
      if (verdict === "allow-session" && sid) {
        spawnSync(BIN, ["mod", "resolve"], { input: JSON.stringify({ harness: "pi", session_id: sid, tool_use_id: event.toolCallId || "pi-ask", cwd: payload.cwd, command: cmdStr, verdict: "allow-session", bypass_sandbox: bypass, completed: true }), encoding: "utf8", timeout: 60000 });
      } else {
        spawnSync(BIN, ["hook", "--harness", "pi"], { input: JSON.stringify({ ...payload, hook_event_name: "PostToolUse" }), encoding: "utf8", timeout: 60000 });
      }
    }
  });
}
`, string(quotedBin))
			return []byte(ts), nil
		},
	})
	return h
}
