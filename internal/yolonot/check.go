package yolonot

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sezaakgun/yolonot/internal/fastallow"
	"github.com/sezaakgun/yolonot/internal/glob"
)

// parseCheckArgs extracts leading check flags (--cwd, --) and rejects unknown
// leading flags so typos like --session-id are not silently treated as the
// command to classify.
func parseCheckArgs(args []string) (rest []string, cwd string, err error) {
	for len(args) > 0 {
		a := args[0]
		switch {
		case a == "--":
			return args[1:], cwd, nil
		case a == "--cwd":
			if len(args) < 2 {
				return nil, "", fmt.Errorf("yolonot check: --cwd requires a directory")
			}
			cwd, args = args[1], args[2:]
		case strings.HasPrefix(a, "--cwd="):
			cwd, args = strings.TrimPrefix(a, "--cwd="), args[1:]
		case strings.HasPrefix(a, "-"):
			return nil, "", fmt.Errorf("yolonot check: unknown flag %s (usage: yolonot check [--cwd <dir>] <command>)", a)
		default:
			return args, cwd, nil
		}
	}
	return nil, cwd, nil
}

// cmdCheck simulates the hook pipeline for a command and prints
// human-readable output showing what each layer would decide.
func cmdCheck(command string) { cmdCheckIn(command, "") }

// cmdCheckIn previews command as if it ran in cwd ("" = this process's).
func cmdCheckIn(command, cwd string) {
	defer prepareHarnessCapabilities(ActiveHarness())()
	fmt.Printf("Command: %s\n\n", command)

	rules := LoadRules(cwd)
	sensitive := LoadSensitivePatterns(cwd)

	step := 1

	// Step: Deny rules (same as hook.go step 0)
	for _, r := range rules {
		if r.Action == "deny" {
			if (r.Type == "cmd" && matchCmd(r.Pattern, command)) ||
				(r.Type == "path" && scriptPathRe.FindStringSubmatch(" "+command) != nil && glob.Match(r.Pattern, scriptPathRe.FindStringSubmatch(" " + command)[1])) {
				fmt.Printf("  [%d] Deny rules:      DENY — matched deny-%s %s\n", step, r.Type, r.Pattern)
				fmt.Println()
				fmt.Printf("  → Result: DENY (layer: rule, absolute block)\n")
				return
			}
		}
	}
	fmt.Printf("  [%d] Deny rules:      no match\n", step)
	step++

	checkCfg := LoadConfig()
	fastallow.AddWrappers(checkCfg.Wrappers...)
	// Dry-run parity: the prompt built by the classifier judge must match
	// what the hook path would build.
	attachOutsideRoot = checkCfg.AttachOutsideRoot

	// Self-policy guard (same as hook.go step 0b): mutating yolonot
	// subcommands always require confirmation (or deny on ask-less hosts).
	if verb := selfPolicyVerb(command); verb != "" {
		decision := "ask"
		if !harnessSupportsAsk(ActiveHarness()) {
			decision = "deny"
		}
		fmt.Printf("  [%d] Self-policy:     %s — yolonot %s changes gate policy\n", step, strings.ToUpper(decision), verb)
		fmt.Println()
		fmt.Printf("  → Result: %s (layer: rule, self-policy)\n", strings.ToUpper(decision))
		return
	}

	// Step: Allow/Ask rules (same as hook.go step 3). Use the SAME priority
	// matcher the hook uses (deny > ask > allow, file-order-independent) so
	// the preview can't report ALLOW on a command the gate would ASK — the
	// first-match MatchRuleWith could pick an earlier allow over a later ask.
	chains := hasChainOperator(command)
	sensitiveFile := hasSensitivePathWith(command, sensitive)
	skipAllow := chains || sensitiveFile

	match := MatchRuleByPriority(command, rules, sensitive)

	if skipAllow {
		// Report why allow rules were skipped
		var reasons []string
		if chains {
			reasons = append(reasons, "chain operators")
		}
		if sensitiveFile {
			reasons = append(reasons, "sensitive files")
		}
		// Check if there was an allow rule that would have matched without skipping
		hasAllowCandidate := false
		for _, r := range rules {
			if r.Action == "allow" {
				if (r.Type == "cmd" && matchCmd(r.Pattern, command)) ||
					(r.Type == "path" && scriptPathRe.FindStringSubmatch(" "+command) != nil && glob.Match(r.Pattern, scriptPathRe.FindStringSubmatch(" " + command)[1])) {
					hasAllowCandidate = true
					break
				}
			}
		}
		if hasAllowCandidate {
			fmt.Printf("  [%d] Allow rules:     skipped — command has %s\n", step, strings.Join(reasons, ", "))
		} else if match != nil && match.Action == "ask" {
			fmt.Printf("  [%d] Ask rules:       ASK — matched ask-%s %s\n", step, match.Type, match.Pattern)
			fmt.Println()
			fmt.Printf("  → Result: ASK (layer: rule)\n")
			return
		} else {
			fmt.Printf("  [%d] Allow rules:     skipped — command has %s\n", step, strings.Join(reasons, ", "))
		}
	} else if match != nil {
		if match.Action == "allow" {
			fmt.Printf("  [%d] Allow rules:     ALLOW — matched allow-%s %s\n", step, match.Type, match.Pattern)
			step++
			fmt.Printf("  [%d] Chain/sensitive:  clean (no chains, no sensitive files)\n", step)
			fmt.Println()
			fmt.Printf("  → Result: ALLOW (layer: rule)\n")
			return
		} else if match.Action == "ask" {
			fmt.Printf("  [%d] Ask rules:       ASK — matched ask-%s %s\n", step, match.Type, match.Pattern)
			fmt.Println()
			fmt.Printf("  → Result: ASK (layer: rule)\n")
			return
		}
	} else {
		fmt.Printf("  [%d] Allow/Ask rules: no match\n", step)
	}
	step++

	// Judge chain — the same chain the hook runs (judge.go), in dry-run:
	// exec judges are never invoked here (they may have side effects).
	specs := checkCfg.JudgeSpecs()
	fmt.Printf("  [%d] Judges:\n", step)
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	in := &JudgeInput{Command: command, Cwd: cwd, Rules: rules, Config: checkCfg, Harness: ActiveHarness(), HookStart: time.Now(), DryRun: true}
	var adopted *Verdict
	var lastErr *judgeError
	for _, spec := range specs {
		if adopted != nil {
			fmt.Printf("      · %s — not reached\n", spec.Use)
			continue
		}
		if spec.Kind() == judgeExec {
			fmt.Printf("      · %s (external, skipped in dry-run)\n", spec.Use)
			continue
		}
		v, ok, err := runJudge(spec, in)
		if err != nil {
			if je, isJE := err.(*judgeError); isJE {
				lastErr = je
			}
			fmt.Printf("      ✗ %s — %v\n", spec.Use, err)
			continue
		}
		if !ok {
			fmt.Printf("      · %s — fall through\n", spec.Use)
			continue
		}
		raw := v.Decision
		if !spec.permit(&v) {
			fmt.Printf("      · %s — %s not permitted for this judge, fall through\n", spec.Use, raw)
			continue
		}
		if v.Dec != nil {
			fmt.Printf("      ✓ %s — %s (risk: %s, %dms)\n", spec.Use, strings.ToUpper(v.Decision), riskOrDash(v.Risk), v.Ms)
			if v.Reason != "" {
				fmt.Printf("        Reasoning: %s\n", v.Reason)
			}
			for _, a := range v.Attached {
				fmt.Printf("        Script shown: %s\n", a)
			}
			for _, w := range v.Withheld {
				fmt.Printf("        Script not shown: %s\n", w)
			}
		} else {
			fmt.Printf("      ✓ %s — %s (%s)\n", spec.Use, strings.ToUpper(v.Decision), v.Reason)
		}
		vv := v
		adopted = &vv
	}
	if adopted != nil && adopted.Dec != nil {
		escalateUncertain(in, adopted)
		esc := adopted.Esc
		switch {
		case esc.Outcome == "":
			fmt.Printf("      · Escalation: not triggered\n")
		case esc.Fired:
			fmt.Printf("      ✓ Escalation: %s → %s (%s, %dms)\n", esc.Model, strings.ToUpper(sanitizeBanner(esc.summary())), esc.Outcome, esc.Ms)
			if esc.Reasoning != "" {
				fmt.Printf("        Reasoning: %s\n", sanitizeBanner(esc.Reasoning))
			}
		default:
			fmt.Printf("      · Escalation: %s\n", esc.Outcome)
		}
	}
	fmt.Println()

	if adopted == nil {
		switch {
		case lastErr == nil:
			fmt.Printf("  → Result: PASS-THROUGH (no judge decided)\n")
		case lastErr.Kind == judgeErrOversize:
			act := failureAction(checkCfg, ActiveHarness(), judgeErrOversize)
			fmt.Printf("  → Result: %s (layer: oversize, %s, profile abstain)\n", strings.ToUpper(act), lastErr.Msg)
		case lastErr.Kind == judgeErrBudget:
			act := failureAction(checkCfg, ActiveHarness(), judgeErrBudget)
			fmt.Printf("  → Result: %s (layer: timeout, %s, profile abstain)\n", strings.ToUpper(act), lastErr.Msg)
		case lastErr.Kind == judgeErrParse:
			fmt.Printf("  → Result: %s (parse error, failure policy)\n", failureActionLabel(failureAction(checkCfg, ActiveHarness(), judgeErrParse)))
		default:
			fmt.Printf("  → Result: %s (LLM unavailable: %s)\n", failureActionLabel(failureAction(checkCfg, ActiveHarness(), judgeErrUnavailable)), lastErr.Msg)
		}
		return
	}

	// Risk map + unresolved policy — same resolution as the hook.
	final, passthrough := applyRiskMap(ActiveHarness(), adopted.Decision, adopted.Risk)
	layer := adopted.Layer
	if passthrough {
		fmt.Printf("  → Result: PASS-THROUGH (layer: %s, risk map defers to host permissions)\n", layer)
		return
	}
	if final == "ask" && adopted.Dec != nil {
		if degrade, reason := escalationUnresolvedDeny(checkCfg, adopted.Esc, adopted.Dec); degrade {
			fmt.Printf("  → Result: DENY (layer: %s, %s)\n", layer, sanitizeBanner(reason))
			return
		}
	}
	if final != adopted.Decision {
		fmt.Printf("  → Result: %s (layer: %s, %s → %s via %s risk map)\n",
			strings.ToUpper(final), layer, adopted.Decision, final, ActiveHarness().Name())
	} else {
		fmt.Printf("  → Result: %s (layer: %s)\n", strings.ToUpper(final), layer)
	}
}

// riskOrDash renders a risk tier or "-" for legacy responses without one.
func riskOrDash(risk string) string {
	if risk == "" {
		return "-"
	}
	return risk
}
