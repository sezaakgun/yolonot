package yolonot

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Rejection equivalence is intentionally separate from approval equivalence:
// recognizing `sh -c 'X'` here must never grant an approval to a shell wrapper.
func matchesRejectedCommand(sessionID, command string) bool {
	if MatchesLineOrWrappedVariant(sessionID, "denied", command) {
		return true
	}
	want := rejectionForms(command)
	for _, rejected := range ReadLines(sessionID, "denied") {
		for form := range rejectionForms(rejected) {
			if want[form] {
				return true
			}
		}
	}
	return false
}

func rejectionForms(command string) map[string]bool {
	forms := make(map[string]bool)
	for depth := 0; depth < 8; depth++ {
		command = strings.TrimSpace(command)
		if command == "" || forms[command] {
			break
		}
		forms[command] = true
		if inner := rejectedShellBody(command); inner != "" {
			command = inner
		} else if inner := UnwrapCommand(command, SessionWrappers()); inner != "" {
			command = inner
		} else {
			break
		}
	}
	return forms
}

func rejectedShellBody(command string) string {
	f, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil || len(f.Stmts) != 1 {
		return ""
	}
	stmt := f.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 || len(call.Assigns) > 0 || stmt.Background || stmt.Negated {
		return ""
	}
	head, ok := rejectionLiteral(call.Args[0])
	if !ok {
		return ""
	}
	switch filepath.Base(head) {
	case "sh", "bash", "zsh", "dash", "ksh":
	default:
		return ""
	}
	for i := 1; i < len(call.Args); i++ {
		arg, literal := rejectionLiteral(call.Args[i])
		if !literal || !strings.HasPrefix(arg, "-") || arg == "--" {
			return ""
		}
		if !strings.HasPrefix(arg, "--") && strings.Contains(arg, "c") && i+1 < len(call.Args) && len(stmt.Redirs) == 0 {
			body, literal := rejectionLiteral(call.Args[i+1])
			if literal {
				return strings.TrimSpace(body)
			}
			return ""
		}
	}
	if len(stmt.Redirs) == 1 {
		r := stmt.Redirs[0]
		if r.Op == syntax.Hdoc || r.Op == syntax.DashHdoc {
			if body, literal := rejectionLiteral(r.Hdoc); literal {
				return strings.TrimSpace(body)
			}
		}
	}
	return ""
}

func rejectionLiteral(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", false
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			inner, ok := rejectionLiteral(&syntax.Word{Parts: p.Parts})
			if !ok {
				return "", false
			}
			b.WriteString(inner)
		default:
			return "", false
		}
	}
	return b.String(), true
}
