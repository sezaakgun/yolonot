package yolonot

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sezaakgun/yolonot/internal/fastallow"
)

// The Claude Code mod (function hooks module) runs `yolonot hook` itself from
// its tool.call hook with YOLONOT_MOD=1, resolves asks in its own dialog, and
// lets the call through. The classic settings hook then runs a second time for
// the same tool_use_id and replays the recorded verdict from the session's
// `.mod` file instead of judging again.

type modEntry struct {
	ID             string   `json:"id"`
	Command        string   `json:"command,omitempty"`
	Cwd            string   `json:"cwd,omitempty"`
	Binding        string   `json:"binding,omitempty"`
	ApprovalHashes []string `json:"approval_hashes,omitempty"`
	BypassSandbox  bool     `json:"bypass_sandbox,omitempty"`
	Grant          string   `json:"grant,omitempty"`
	Completed      bool     `json:"completed,omitempty"`
	Decision       string   `json:"decision"`
	Layer          string   `json:"layer"`
	Reason         string   `json:"reason,omitempty"`
	Ms             int64    `json:"ms,omitempty"`
}

var (
	modRun            bool
	modSessionID      string
	modToolUseID      string
	modStart          time.Time
	modCommand        string
	modCwd            string
	modRuleAction     string
	modBinding        string
	modApprovalHashes []string
)

type codexPreEntry struct {
	Command        string   `json:"command"`
	Cwd            string   `json:"cwd"`
	Binding        string   `json:"binding"`
	ApprovalHashes []string `json:"approval_hashes,omitempty"`
	RuleAction     string   `json:"rule_action,omitempty"`
	Decision       string   `json:"decision"`
	Layer          string   `json:"layer"`
	Reason         string   `json:"reason,omitempty"`
	Passthrough    bool     `json:"passthrough,omitempty"`
	Completed      bool     `json:"completed,omitempty"`
}

func codexRecordPre(sessionID, command, cwd, ruleAction, decision, layer, reason string, passthrough bool) {
	if sessionID == "" || command == "" || decision == "deny" {
		return
	}
	if h := ActiveHarness(); h == nil || !harnessUsesPermissionRequest(h) || currentHookEventName != "PreToolUse" {
		return
	}
	binding, hashes := modBinding, modApprovalHashes
	if binding == "" {
		binding, hashes = modCommandSnapshot(command, cwd)
	}
	if binding == "" {
		return
	}
	b, err := json.Marshal(codexPreEntry{
		Command: command, Cwd: cwd, Binding: binding, ApprovalHashes: hashes,
		RuleAction: ruleAction, Decision: decision, Layer: layer, Reason: reason, Passthrough: passthrough,
	})
	if err == nil {
		AppendLine(sessionID, "codexpre", string(b))
	}
}

func codexConsumePre(sessionID, command, cwd, ruleAction string) *codexPreEntry {
	if sessionID == "" || command == "" {
		return nil
	}
	binding := modCommandBinding(command, cwd)
	if binding == "" {
		return nil
	}
	lines := ReadLines(sessionID, "codexpre")
	matchIdx := -1
	var matched codexPreEntry
	for i, l := range lines {
		var e codexPreEntry
		if json.Unmarshal([]byte(l), &e) == nil && !e.Completed &&
			e.Command == command && e.Cwd == cwd && e.Binding == binding && e.RuleAction == ruleAction {
			matchIdx = i
			matched = e
		}
	}
	if matchIdx < 0 {
		return nil
	}
	matched.Completed = true
	if b, err := json.Marshal(matched); err == nil {
		lines[matchIdx] = string(b)
		if path := sessionPath(sessionID, "codexpre"); path != "" {
			atomicWriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600)
		}
	}
	return &matched
}

func modAppend(sessionID string, e modEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	AppendLine(sessionID, "mod", string(b))
}

func modRecord(decision, layer, reason string) {
	if !modRun || modToolUseID == "" {
		return
	}
	modAppend(modSessionID, modEntry{ID: modToolUseID, Command: modCommand, Cwd: modCwd, Binding: modBinding, ApprovalHashes: modApprovalHashes,
		BypassSandbox: currentBypassSandbox, Decision: decision, Layer: layer, Reason: reason, Ms: time.Since(modStart).Milliseconds()})
}

// modCommandBinding pins a replay to the exact command, working directory,
// attached script contents and directly executed native binary identity.
// Withheld scripts cannot be
// checked for changes, so they deliberately disable replay.
func modCommandBinding(command, cwd string) string {
	attached, withheld := collectScripts(command, cwd)
	return modBindingFromCollected(command, cwd, attached, withheld)
}

func modCommandSnapshot(command, cwd string) (string, []string) {
	attached, withheld := collectScripts(command, cwd)
	return replaySnapshotFromCollected(command, cwd, attached, withheld)
}

// Classifier verdicts use their already-collected snapshot here, rather
// than recollecting files before or after a model request.
func modBindingFromCollected(command, cwd string, attached []attachedScript, withheld []withheldScript) string {
	binding, _ := replaySnapshotFromCollected(command, cwd, attached, withheld)
	return binding
}

func replaySnapshotFromCollected(command, cwd string, attached []attachedScript, withheld []withheldScript) (string, []string) {
	hashes := approvalHashesFromCollected(command, attached, withheld)
	identity, token := nativeExecutableIdentity(command, cwd)
	if identity != "" {
		hashes = append(hashes, executableApprovalPrefix(command)+identity)
	} else if inner := UnwrapCommand(command, SessionWrappers()); inner != "" {
		if identity, token = nativeExecutableIdentity(inner, cwd); identity != "" {
			hashes = append(hashes, executableApprovalPrefix(inner)+identity)
		}
	}
	for _, w := range withheld {
		// A native executable's identity is pinned independently from prompt
		// attachment. Other withheld scripts still forbid replay.
		if identity != "" && w.ref.executed && w.ref.raw == token &&
			(w.reason == whReasonOutside || w.reason == whReasonNotText || w.reason == whReasonTooLarge) {
			continue
		}
		return "", hashes
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00", command, cwd)
	if currentBypassSandbox {
		fmt.Fprintf(h, "unsandboxed\x00")
	}
	for _, a := range attached {
		fmt.Fprintf(h, "%s\x00", a.ref.abs)
		h.Write(a.digest[:])
	}
	if identity != "" {
		fmt.Fprintf(h, "native-executable\x00%s\x00", identity)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), hashes
}

func modLookupBound(sessionID, toolUseID, command, cwd string) *modEntry {
	e := modLookup(sessionID, toolUseID)
	if e == nil || e.Completed || e.Binding == "" || e.Command != command || e.Cwd != cwd ||
		e.BypassSandbox != currentBypassSandbox || e.Binding != modCommandBinding(command, cwd) {
		return nil
	}
	return e
}

func modLookup(sessionID, toolUseID string) *modEntry {
	if toolUseID == "" {
		return nil
	}
	var found *modEntry
	for _, l := range ReadLines(sessionID, "mod") {
		var e modEntry
		if json.Unmarshal([]byte(l), &e) == nil && e.ID == toolUseID {
			c := e
			found = &c
		}
	}
	return found
}

// dropLine removes every exact copy of line from a session file; reports
// whether any was there.
func dropLine(sessionID, suffix, line string) bool {
	path := sessionPath(sessionID, suffix)
	if path == "" {
		return false
	}
	lines := ReadLines(sessionID, suffix)
	kept := lines[:0]
	for _, l := range lines {
		if l != line {
			kept = append(kept, l)
		}
	}
	if len(kept) == len(lines) {
		return false
	}
	for i := range kept {
		kept[i] = encodeSessionLine(suffix, kept[i])
	}
	atomicWriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0600)
	return true
}

// dropLineOrVariant is dropLine with the wrapper equivalence of
// MatchesLineOrWrappedVariant: a rewrite hook may turn `ls` into `rtk ls`
// between PreToolUse and PostToolUse, and the once marker must still be found.
func dropLineOrVariant(sessionID, suffix, command string) bool {
	if command == "" {
		return false
	}
	wrappers := SessionWrappers()
	inner := UnwrapCommand(command, wrappers)
	isWrapped := func(line string) bool {
		if !strings.HasSuffix(line, " "+command) {
			return false
		}
		for _, w := range wrappers {
			if strings.HasPrefix(line, w+" ") {
				return true
			}
		}
		return false
	}
	path := sessionPath(sessionID, suffix)
	if path == "" {
		return false
	}
	lines := ReadLines(sessionID, suffix)
	kept := lines[:0]
	for _, l := range lines {
		if l == command || (inner != "" && l == inner) || isWrapped(l) {
			continue
		}
		kept = append(kept, l)
	}
	if len(kept) == len(lines) {
		return false
	}
	for i := range kept {
		kept[i] = encodeSessionLine(suffix, kept[i])
	}
	atomicWriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0600)
	return true
}

type modResolve struct {
	SessionID string `json:"session_id"`
	ToolUseID string `json:"tool_use_id"`
	Cwd       string `json:"cwd"`
	Command   string `json:"command"`
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason"`
}

func cmdMod(args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "resolve":
		var r modResolve
		if err := json.NewDecoder(os.Stdin).Decode(&r); err != nil || r.SessionID == "" || r.ToolUseID == "" || r.Command == "" {
			fmt.Fprintln(os.Stderr, "yolonot mod resolve: expects JSON on stdin: session_id, tool_use_id, cwd, command, verdict")
			os.Exit(2)
		}
		proj := ProjectSessionID(r.SessionID, r.Cwd)
		cfg := LoadConfig()
		attachOutsideRoot = cfg.AttachOutsideRoot
		fastallow.AddWrappers(cfg.Wrappers...)
		previous := modLookup(r.SessionID, r.ToolUseID)
		currentBypassSandbox = previous != nil && previous.BypassSandbox
		binding, hashes := modCommandSnapshot(r.Command, r.Cwd)
		entry := modEntry{ID: r.ToolUseID, Command: r.Command, Cwd: r.Cwd,
			Binding: binding, ApprovalHashes: hashes, BypassSandbox: currentBypassSandbox, Layer: "human", Grant: r.Verdict}
		// A human answer is about the snapshot originally judged. Do not
		// silently bind it to script edits made while the dialog was open.
		snapshotUnchanged := true
		if previous != nil && previous.Command == r.Command && previous.Cwd == r.Cwd {
			snapshotUnchanged = previous.Binding != "" && previous.Binding == binding
			entry.Binding = previous.Binding
			entry.ApprovalHashes = previous.ApprovalHashes
		}
		switch r.Verdict {
		case "allow-once":
			dropLine(proj, "asked", r.Command)
			AppendLine(proj, "once", r.Command)
			LogDecision(DecisionEntry{SessionID: r.SessionID, Command: r.Command, Cwd: r.Cwd, Layer: "human", Decision: "allow", Source: "allow_once", ToolUseID: r.ToolUseID})
			entry.Decision, entry.Reason = "allow", "allowed once"
		case "allow-session":
			if snapshotUnchanged {
				dropLine(proj, "asked", r.Command)
				if selfPolicyVerb(r.Command) == "" {
					saveApprovedSnapshot(proj, r.Command, entry.ApprovalHashes)
				}
				LogDecision(DecisionEntry{SessionID: r.SessionID, Command: r.Command, Cwd: r.Cwd, Layer: "human", Decision: "allow", Source: "ask_approved", ToolUseID: r.ToolUseID})
				entry.Decision, entry.Reason = "allow", "allowed for this session"
			} else {
				entry.Grant = "allow-once"
				dropLine(proj, "asked", r.Command)
				AppendLine(proj, "once", r.Command)
				LogDecision(DecisionEntry{SessionID: r.SessionID, Command: r.Command, Cwd: r.Cwd, Layer: "human", Decision: "allow", Source: "allow_once", ToolUseID: r.ToolUseID})
				entry.Decision, entry.Reason = "allow", "allowed once (script modified since prompt)"
			}
		case "deny":
			AppendLine(proj, "denied", r.Command)
			LogDecision(DecisionEntry{SessionID: r.SessionID, Command: r.Command, Cwd: r.Cwd, Layer: "human", Decision: "deny", Source: "ask_rejected", ToolUseID: r.ToolUseID})
			entry.Decision, entry.Reason = "deny", "rejected by the user"
		default:
			fmt.Fprintln(os.Stderr, "yolonot mod resolve: verdict must be allow-once, allow-session or deny")
			os.Exit(2)
		}
		modAppend(r.SessionID, entry)
	case "install":
		dir, err := modInstall(binaryPath())
		if err != nil {
			fmt.Fprintln(os.Stderr, "mod install failed:", err)
			os.Exit(1)
		}
		fmt.Println("Mod installed →", dir)
		fmt.Println("Restart Claude Code to load it.")
	case "uninstall":
		modUninstall()
		fmt.Println("Mod removed.")
	default:
		fmt.Fprintln(os.Stderr, "usage: yolonot mod install | uninstall | resolve")
		os.Exit(2)
	}
}

const explainSystemPrompt = `You explain a shell command that yolonot, a safety gate for AI coding assistants, flagged for the user's review. Answer in at most three short plain-text lines: what the command does, what the judge most likely objected to, and a safer form if one exists. No markdown, no preamble.`

func cmdExplain(args []string) {
	var in struct {
		Command string `json:"command"`
		Reason  string `json:"reason"`
	}
	if len(args) > 0 {
		in.Command = strings.Join(args, " ")
	} else {
		json.NewDecoder(os.Stdin).Decode(&in)
	}
	if in.Command == "" {
		fmt.Fprintln(os.Stderr, "usage: yolonot explain <command>   (or JSON {command, reason} on stdin)")
		os.Exit(2)
	}
	cfg := GetLLMConfig()
	if cfg.Model == "" {
		fmt.Fprintln(os.Stderr, "no chat model configured; run `yolonot models add`")
		os.Exit(2)
	}
	out, err := CallLLM(cfg, explainSystemPrompt, "Command:\n"+in.Command+"\n\nJudge said: "+in.Reason, 300)
	if err != nil {
		fmt.Fprintln(os.Stderr, "explain failed:", err)
		os.Exit(1)
	}
	fmt.Println(strings.TrimSpace(out))
}

func modDir() string { return filepath.Join(YolonotDir(), "mod") }

const pluginDirsKey = "CLAUDE_CODE_PLUGIN_DIRS"

// modInstall writes the plugin folder and names it in Claude's settings env
// block, which Claude reads as CLAUDE_CODE_PLUGIN_DIRS at startup.
func modInstall(bin string) (string, error) {
	dir := modDir()
	files := map[string]string{
		"mod/plugin.json":  ".claude-plugin/plugin.json",
		"mod/hooks.json":   "hooks/hooks.json",
		"mod/register.tsx": "hooks/register.tsx",
	}
	for src, dst := range files {
		b, err := embeddedMod.ReadFile(src)
		if err != nil {
			return "", err
		}
		quoted, _ := json.Marshal(bin)
		s := strings.ReplaceAll(string(b), `'__YOLONOT_BIN__'`, string(quoted))
		s = strings.ReplaceAll(s, "__YOLONOT_VERSION__", strings.TrimPrefix(Version, "v"))
		p := filepath.Join(dir, dst)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			return "", err
		}
		if err := os.WriteFile(p, []byte(s), 0644); err != nil {
			return "", err
		}
	}
	s, err := claudeAdapter().readSettings()
	if err != nil {
		return "", err
	}
	env, _ := s["env"].(map[string]interface{})
	if env == nil {
		env = map[string]interface{}{}
	}
	cur, _ := env[pluginDirsKey].(string)
	if !containsDir(cur, dir) {
		if cur != "" {
			cur += ":"
		}
		cur += dir
	}
	env[pluginDirsKey] = cur
	s["env"] = env
	if err := claudeAdapter().saveSettings(s); err != nil {
		return "", err
	}
	return dir, nil
}

func modUninstall() {
	dir := modDir()
	os.RemoveAll(dir)
	s := loadSettings()
	env, _ := s["env"].(map[string]interface{})
	cur, _ := env[pluginDirsKey].(string)
	if !containsDir(cur, dir) {
		return
	}
	var kept []string
	for _, p := range strings.Split(cur, ":") {
		if p != dir && p != "" {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		delete(env, pluginDirsKey)
	} else {
		env[pluginDirsKey] = strings.Join(kept, ":")
	}
	if len(env) == 0 {
		delete(s, "env")
	}
	saveSettings(s)
}

func containsDir(list, dir string) bool {
	for _, p := range strings.Split(list, ":") {
		if p == dir {
			return true
		}
	}
	return false
}
