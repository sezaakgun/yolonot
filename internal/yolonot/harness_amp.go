package yolonot

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

func init() { RegisterHarness(newAmpHarness()) }

type AmpHarness struct{ baseHarness }

func ampConfigDir() string {
	return xdgOrHomeConfigDir([]string{"AMP_CONFIG_DIR"}, "amp", filepath.Join(".config", "amp"))
}

func newAmpHarness() *AmpHarness {
	h := &AmpHarness{
		baseHarness: baseHarness{
			name:           "amp",
			supportsAsk:    true,
			sessionEnvKeys: []string{"YOLONOT_AMP_SESSION_ID", "AMP_CURRENT_THREAD_ID", "AMP_THREAD_ID", "AGENT_THREAD_ID"},
			configDirFn:    ampConfigDir,
			settingsPathFn: func() string { return filepath.Join(ampConfigDir(), "plugins", "yolonot.ts") },
			riskMap:        claudeCompatRiskMap(),
			formatFn:       formatCanonicalPluginResponse,
			notesFn: func(settingsPath string) []string {
				return []string{
					fmt.Sprintf("Amp plugin installed at %s.", settingsPath),
				}
			},
		},
	}
	h.useShimFileHooks(shimFileHooksSpec{
		marker: "// yolonot — Amp plugin shim",
		buildShim: func(_, binaryPath string) ([]byte, error) {
			quotedBin, _ := json.Marshal(binaryPath)
			ts := fmt.Sprintf(`// @i-know-the-amp-plugin-api-is-wip-and-very-experimental-right-now
// yolonot — Amp plugin shim
import { spawnSync } from "node:child_process";
const BIN = %s;
export default function (amp: any) {
  amp.on("tool.call", async (event: any, ctx: any) => {
    const tool = event.tool || event.name || "";
    if (tool !== "Bash" && tool !== "shell_command" && tool !== "async_shell_command") return {};
    const inp = event.input || {};
    const cmd = inp.cmd || inp.command || "";
    const cwd = inp.cwd || inp.workdir || process.cwd();
    const payload = { hook_event_name: "PreToolUse", tool_name: tool, session_id: process.env.AMP_CURRENT_THREAD_ID || "", cwd, tool_input: { ...inp, command: cmd } };
    const res = spawnSync(BIN, ["hook", "--harness", "amp"], { input: JSON.stringify(payload), encoding: "utf8", timeout: 60000 });
    const raw = (res.stdout || "").trim();
    let out: any = {};
    if (raw) {
      try { out = JSON.parse(raw).hookSpecificOutput || {}; } catch { return { action: "reject-and-continue", message: "Blocked by yolonot (invalid hook response)" }; }
    }
    if (res.error || res.status !== 0 || out.permissionDecision === "deny") {
      return { action: "reject-and-continue", message: out.permissionDecisionReason || (res.stderr || "").trim() || (res.error && res.error.message) || "Blocked by yolonot" };
    }
    if (out.permissionDecision === "ask") {
      try {
        const msg = out.permissionDecisionReason ? cmd + "\n" + out.permissionDecisionReason : cmd;
        const ok = await ctx.ui.confirm({ title: "Allow command?", message: msg, requireHuman: true });
        if (!ok) return { action: "reject-and-continue", message: "Denied by user" };
        spawnSync(BIN, ["hook", "--harness", "amp"], { input: JSON.stringify({ ...payload, hook_event_name: "PostToolUse" }), encoding: "utf8", timeout: 60000 });
        return { action: "allow" };
      } catch {
        return { action: "reject-and-continue", message: "Approval required in headless mode" };
      }
    }
    if (out.permissionDecision === "allow") return { action: "allow" };
    return {};
  });
}
`, string(quotedBin))
			return []byte(ts), nil
		},
	})
	return h
}
