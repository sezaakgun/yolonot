package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sezaakgun/yolonot/internal/fastallow"
)

// New multiline commands occupy one physical record. Existing single-line
// session files remain readable; a command can never become several approvals.
func encodeSessionLine(suffix, line string) string {
	if suffix != "approved" && suffix != "approved_unsandboxed" && suffix != "asked" && suffix != "denied" && suffix != "once" {
		return line
	}
	if strings.ContainsAny(line, "\r\n") || strings.HasPrefix(line, "@json:") {
		b, _ := json.Marshal(line)
		return "@json:" + string(b)
	}
	return line
}
func decodeSessionLine(suffix, line string) string {
	if suffix != "approved" && suffix != "approved_unsandboxed" && suffix != "asked" && suffix != "denied" && suffix != "once" {
		return line
	}
	if strings.HasPrefix(line, "@json:") {
		var decoded string
		if json.Unmarshal([]byte(strings.TrimPrefix(line, "@json:")), &decoded) == nil {
			return decoded
		}
	}
	return line
}

func rewriteSessionLines(sid, suffix string, keep func(string) bool) error {
	var lines []string
	for _, line := range ReadLines(sid, suffix) {
		if keep(line) {
			lines = append(lines, encodeSessionLine(suffix, line))
		}
	}
	data := ""
	if len(lines) > 0 {
		data = strings.Join(lines, "\n") + "\n"
	}
	path := sessionPath(sid, suffix)
	if path == "" {
		return fmt.Errorf("invalid session ID")
	}
	return atomicWriteFile(path, []byte(data), 0600)
}

func sessionCommandArgs(args []string) (command, sid, cwd string, err error) {
	sid = resolveSessionID(args)
	cwd, err = os.Getwd()
	if err != nil {
		return
	}
	var words []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			words = append(words, args[i+1:]...)
			break
		}
		switch {
		case a == "--session-id" || a == "--harness" || a == "--cwd":
			if i+1 >= len(args) {
				err = fmt.Errorf("%s requires a value", a)
				return
			}
			i++
			if a == "--cwd" {
				cwd = args[i]
			}
		case strings.HasPrefix(a, "--session-id="), strings.HasPrefix(a, "--harness="), a == "--current":
		case strings.HasPrefix(a, "--cwd="):
			cwd = strings.TrimPrefix(a, "--cwd=")
		default:
			words = append(words, a)
		}
	}
	if len(words) > 1 {
		// Joining words would drop the shell quoting and store a broader command.
		err = fmt.Errorf("pass the command as one quoted argument: '<exact command>'")
		return
	}
	command = strings.Join(words, " ")
	if absolute, e := filepath.Abs(cwd); e != nil {
		err = e
		return
	} else {
		cwd = absolute
	}
	if resolved, e := filepath.EvalSymlinks(cwd); e == nil {
		cwd = resolved
	} else {
		err = fmt.Errorf("working directory: %w", e)
		return
	}
	if info, e := os.Stat(cwd); e != nil || !info.IsDir() {
		err = fmt.Errorf("working directory must exist and be a directory")
		return
	}
	if !IsValidSessionID(sid) {
		err = fmt.Errorf("provide a valid --session-id <id>, --current, or the active harness session environment")
	}
	return
}

func sessionDecision(verb, command, sid, cwd string) error {
	if !IsValidSessionID(sid) {
		return fmt.Errorf("invalid session ID")
	}
	project := ProjectSessionID(sid, cwd)
	if verb == "reset" {
		for _, suffix := range []string{"approved", "approvedhash", "approved_unsandboxed", "approved_unsandboxedhash", "asked", "denied", "once"} {
			path := sessionPath(project, suffix)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		_ = rewriteSessionLines(sid, "codexpre", func(line string) bool {
			var e codexPreEntry
			return json.Unmarshal([]byte(line), &e) != nil || ProjectSessionID(sid, e.Cwd) != project
		})
		// Replay belongs to the base session; remove this project's records only.
		return rewriteSessionLines(sid, "mod", func(line string) bool {
			var e modEntry
			return json.Unmarshal([]byte(line), &e) != nil || ProjectSessionID(sid, e.Cwd) != project
		})
	}
	if strings.TrimSpace(command) == "" || strings.ContainsRune(command, 0) {
		return fmt.Errorf("provide an exact non-empty command")
	}
	cfg := LoadConfig()
	attachOutsideRoot = cfg.AttachOutsideRoot
	fastallow.AddWrappers(cfg.Wrappers...)
	forms := rejectionForms(command)
	removeEquivalent := func(line string) bool {
		for f := range rejectionForms(line) {
			if forms[f] {
				return false
			}
		}
		return true
	}
	if verb == "approve" {
		if err := rewriteSessionLines(project, "denied", removeEquivalent); err != nil {
			return err
		}
		_, hashes := modCommandSnapshot(command, cwd)
		if err := AppendLine(project, "approved", command); err != nil {
			return err
		}
		for _, hash := range hashes {
			if err := AppendLine(project, "approvedhash", hash); err != nil {
				return err
			}
		}
		if err := rewriteSessionLines(project, "asked", removeEquivalent); err != nil {
			return err
		}
	} else {
		if err := rewriteSessionLines(project, "approved", removeEquivalent); err != nil {
			return err
		}
		if err := rewriteSessionLines(project, "approved_unsandboxed", removeEquivalent); err != nil {
			return err
		}
		if err := AppendLine(project, "denied", command); err != nil {
			return err
		}
		if err := rewriteSessionLines(project, "asked", removeEquivalent); err != nil {
			return err
		}
	}
	_ = rewriteSessionLines(sid, "codexpre", func(line string) bool {
		var e codexPreEntry
		return json.Unmarshal([]byte(line), &e) != nil || ProjectSessionID(sid, e.Cwd) != project || removeEquivalent(e.Command)
	})
	// Do not leave an old human/mod replay in authority over a manual update.
	if err := rewriteSessionLines(sid, "mod", func(line string) bool {
		var e modEntry
		return json.Unmarshal([]byte(line), &e) != nil || ProjectSessionID(sid, e.Cwd) != project || removeEquivalent(e.Command)
	}); err != nil {
		return err
	}
	source, decision := "ask_approved", ActionAllow
	if verb == "deny" {
		source, decision = "ask_rejected", ActionDeny
	}
	LogDecision(DecisionEntry{SessionID: sid, Command: command, Cwd: cwd, Layer: "human", Decision: decision, Source: source})
	return nil
}

func cmdSessionDecision(verb string, args []string) {
	command, sid, cwd, err := sessionCommandArgs(args)
	if err == nil {
		err = sessionDecision(verb, command, sid, cwd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "yolonot:", err)
		os.Exit(2)
	}
	fmt.Printf("Session %s: %s in %s\n", sid, verb, cwd)
	if verb == "approve" {
		fmt.Println("Explicit deny rules and host permissions still apply.")
	}
}
