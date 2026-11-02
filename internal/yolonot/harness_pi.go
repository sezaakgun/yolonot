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
    const sid = (ctx && ctx.sessionManager && typeof ctx.sessionManager.getSessionId === "function" && ctx.sessionManager.getSessionId()) || process.env.PI_SESSION_ID || "";
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
      if (!ctx || !ctx.hasUI || !ctx.ui?.confirm) return { block: true, reason: out.permissionDecisionReason || "Approval required in non-interactive mode" };
      const detail = out.permissionDecisionReason ? String(input.command || "") + "\n" + out.permissionDecisionReason : String(input.command || "");
      const ok = await ctx.ui.confirm("yolonot: Allow command?", detail);
      if (!ok) return { block: true, reason: "Denied by user" };
      spawnSync(BIN, ["hook", "--harness", "pi"], { input: JSON.stringify({ ...payload, hook_event_name: "PostToolUse" }), encoding: "utf8", timeout: 60000 });
    }
  });
}
`, string(quotedBin))
			return []byte(ts), nil
		},
	})
	return h
}
