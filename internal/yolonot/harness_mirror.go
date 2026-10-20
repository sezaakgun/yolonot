package yolonot

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

func init() { RegisterHarness(newMirrorHarness()) }

type MirrorHarness struct{ baseHarness }

func mirrorConfigDir() string {
	return xdgOrHomeConfigDir([]string{"MIRROR_HOME"}, "", ".mirror")
}

func newMirrorHarness() *MirrorHarness {
	h := &MirrorHarness{
		baseHarness: baseHarness{
			name:           "mirror",
			supportsAsk:    true,
			sessionEnvKeys: []string{"YOLONOT_MIRROR_SESSION_ID", "MIRROR_SESSION_ID"},
			configDirFn:    mirrorConfigDir,
			settingsPathFn: func() string { return filepath.Join(mirrorConfigDir(), "extensions", "yolonot", "extension.py") },
			riskMap:        claudeCompatRiskMap(),
			formatFn:       formatCanonicalPluginResponse,
			notesFn: func(settingsPath string) []string {
				return []string{
					fmt.Sprintf("Mirror extension installed at %s.", settingsPath),
				}
			},
		},
	}
	h.useShimFileHooks(shimFileHooksSpec{
		marker:               "# yolonot — Mirror extension shim",
		removeDirOnUninstall: true,
		buildShim: func(_, binaryPath string) ([]byte, error) {
			quotedBin, _ := json.Marshal(binaryPath)
			py := fmt.Sprintf(`# yolonot — Mirror extension shim
"""yolonot command guard extension for Reflection Mirror."""
import json, os, subprocess, uuid
try:
    from mirror.cli import actions, extension
    _Base = extension.Extension
except Exception:
    actions = None
    class _Base:
        pass

BIN = %s
_PROCESS_SESSION_ID = uuid.uuid4().hex[:12]

def evaluate_bash(command, cwd="", session_id="", tool_use_id="", event="PreToolUse", tool_input=None):
    inp = dict(tool_input) if isinstance(tool_input, dict) else {}
    inp["command"] = command
    payload = {"hook_event_name": event, "tool_name": "bash", "tool_use_id": tool_use_id, "session_id": session_id, "cwd": cwd or os.getcwd(), "tool_input": inp}
    try:
        res = subprocess.run([BIN, "hook", "--harness", "mirror"], input=json.dumps(payload), text=True, capture_output=True, timeout=60)
    except Exception as exc:
        return "deny", f"Blocked by yolonot ({exc})"
    if res.returncode != 0:
        return "deny", (res.stderr or "").strip() or "Blocked by yolonot"
    raw = (res.stdout or "").strip()
    if not raw:
        return "", ""
    try:
        out = json.loads(raw).get("hookSpecificOutput", {})
        return out.get("permissionDecision", ""), out.get("permissionDecisionReason", "")
    except Exception:
        return "deny", "Blocked by yolonot (invalid hook response)"

class YolonotExtension(_Base):
    _pending = {}

    @classmethod
    def id(cls) -> str:
        return "yolonot"

    def reduce(self, global_state, action):
        st = global_state.extensions[self.id()]
        if actions is not None and isinstance(action, actions.ApprovalRequested) and action.request.name == "bash":
            return st, (self.effect(action.request),)
        if actions is not None and isinstance(action, actions.DecideApproval) and action.call_id in self._pending:
            info = self._pending.pop(action.call_id, None)
            if action.approved and info:
                return st, (self.effect(("post", action.call_id, info)),)
        return st, ()

    async def handle_effect(self, context, request):
        if isinstance(request, tuple) and len(request) == 3 and request[0] == "post":
            _, call_id, info = request
            evaluate_bash(info["cmd"], cwd=info["cwd"], session_id=info["sid"], tool_use_id=call_id, event="PostToolUse", tool_input=info.get("args"))
            return
        try:
            args = json.loads(request.args or "{}")
        except Exception:
            args = {}
        if not isinstance(args, dict):
            args = {}
        cmd = args.get("command", "")
        if not cmd:
            return
        cwd = str(context.workspace.cwd) if getattr(context, "workspace", None) else os.getcwd()
        sid = os.environ.get("YOLONOT_MIRROR_SESSION_ID") or os.environ.get("MIRROR_SESSION_ID") or _PROCESS_SESSION_ID
        dec, _ = evaluate_bash(cmd, cwd=cwd, session_id=sid, tool_use_id=getattr(request, "call_id", ""), tool_input=args)
        if dec == "allow":
            context.dispatch(actions.DecideApproval(approved=True, call_id=request.call_id))
        elif dec == "deny":
            context.dispatch(actions.DecideApproval(approved=False, call_id=request.call_id))
        elif dec == "ask":
            self._pending[getattr(request, "call_id", "")] = {"cmd": cmd, "cwd": cwd, "sid": sid, "args": args}
`, string(quotedBin))
			return []byte(py), nil
		},
		postInstall: func(settingsPath string) error {
			cfgPath := filepath.Join(mirrorConfigDir(), "config.json")
			cfg, err := readHarnessJSON(cfgPath)
			if err != nil {
				return err
			}
			exts, _ := cfg["extensions"].(map[string]interface{})
			if exts == nil {
				exts = map[string]interface{}{}
				cfg["extensions"] = exts
			}
			exts["yolonot"] = map[string]interface{}{"enabled": true}
			exts[settingsPath] = map[string]interface{}{"enabled": true}
			if resolved, rerr := filepath.EvalSymlinks(settingsPath); rerr == nil && resolved != "" {
				exts[resolved] = map[string]interface{}{"enabled": true}
			}
			return saveHarnessJSON(cfgPath, cfg)
		},
		postUninstall: func(settingsPath string) error {
			cfgPath := filepath.Join(mirrorConfigDir(), "config.json")
			cfg, err := readHarnessJSON(cfgPath)
			if err != nil || len(cfg) == 0 {
				return nil
			}
			if exts, ok := cfg["extensions"].(map[string]interface{}); ok {
				delete(exts, "yolonot")
				delete(exts, settingsPath)
				if resolved, rerr := filepath.EvalSymlinks(settingsPath); rerr == nil && resolved != "" {
					delete(exts, resolved)
				}
				return saveHarnessJSON(cfgPath, cfg)
			}
			return nil
		},
	})
	return h
}
