package yolonot

import (
	"fmt"
	"strings"
	"time"

	"github.com/sezaakgun/yolonot/internal/fastallow"
	"github.com/sezaakgun/yolonot/internal/glob"
)

// cmdCheck simulates the hook pipeline for a command and prints
// human-readable output showing what each layer would decide.
func cmdCheck(command string) {
	fmt.Printf("Command: %s\n\n", command)

	rules := LoadRules()
	sensitive := LoadSensitivePatterns()

	step := 1

	// Step: Deny rules (same as hook.go step 0)
	firstToken := command
	if idx := strings.IndexByte(command, ' '); idx > 0 {
		firstToken = command[:idx]
	}
	for _, r := range rules {
		if r.Action == "deny" {
			if (r.Type == "cmd" && matchCmd(r.Pattern, command, firstToken)) ||
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

	// Step: Pre-check hooks (same as hook.go step 0.5).
	// External binaries are NOT invoked during `yolonot check` — they may
	// have side effects. But the fast-allow sentinel is pure and cheap, so
	// we DO evaluate it inline and show the actual verdict.
	checkCfg := LoadConfig()
	fastallow.AddWrappers(checkCfg.Wrappers...)
	if preChecks := checkCfg.PreCheck; len(preChecks) > 0 {
		fmt.Printf("  [%d] Pre-check hooks: %d configured\n", step, len(preChecks))
		fastAllowHit := false
		for _, pc := range preChecks {
			if pc == "" {
				continue
			}
			if pc == FastAllowSentinel {
				if ok, reason := fastallow.IsLocallySafeWith(command, AllowRedirectPatterns(rules)); ok {
					fmt.Printf("      ✓ %s — ALLOW (%s)\n", pc, reason)
					fastAllowHit = true
				} else {
					fmt.Printf("      · %s — fall through\n", pc)
				}
				continue
			}
			fmt.Printf("      · %s (external, skipped in dry-run)\n", pc)
		}
		if fastAllowHit {
			fmt.Println()
			fmt.Printf("  → Result: ALLOW (layer: fast_allow)\n")
			return
		}
		step++
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
				if (r.Type == "cmd" && matchCmd(r.Pattern, command, firstToken)) ||
					(r.Type == "path" && scriptPathRe.FindStringSubmatch(" "+command) != nil && glob.Match(r.Pattern, scriptPathRe.FindStringSubmatch(" " + command)[1])) {
					hasAllowCandidate = true
					break
				}
			}
		}
		if hasAllowCandidate {
			fmt.Printf("  [%d] Allow rules:     skipped — command has %s\n", step, strings.Join(reasons, ", "))
		} else if match != nil && match.Action == "ask" {
			fmt.Printf("  [%d] Ask rules:       ASK — matched ask-%s\n", step, match.Pattern)
			fmt.Println()
			fmt.Printf("  → Result: ASK (layer: rule)\n")
			return
		} else {
			fmt.Printf("  [%d] Allow rules:     skipped — command has %s\n", step, strings.Join(reasons, ", "))
		}
	} else if match != nil {
		if match.Action == "allow" {
			fmt.Printf("  [%d] Allow rules:     ALLOW — matched allow-cmd %s\n", step, match.Pattern)
			step++
			fmt.Printf("  [%d] Chain/sensitive:  clean (no chains, no sensitive files)\n", step)
			fmt.Println()
			fmt.Printf("  → Result: ALLOW (layer: rule)\n")
			return
		} else if match.Action == "ask" {
			fmt.Printf("  [%d] Ask rules:       ASK — matched ask-%s\n", step, match.Pattern)
			fmt.Println()
			fmt.Printf("  → Result: ASK (layer: rule)\n")
			return
		}
	} else {
		fmt.Printf("  [%d] Allow/Ask rules: no match\n", step)
	}
	step++

	// Step: LLM analysis (same as hook.go step 5)
	cfg := GetLLMConfig()
	if cfg.URL == "" {
		fmt.Printf("  [%d] LLM analysis:    skipped — no provider configured\n", step)
		fmt.Println()
		fmt.Printf("  → Result: PASS-THROUGH (no rule matched, no LLM configured)\n")
		return
	}

	userPrompt := BuildAnalyzePrompt(command, "")
	if len(userPrompt) > maxClassifierPromptBytes {
		act := abstainAction(ActiveHarness())
		fmt.Printf("  [%d] LLM analysis:    skipped — prompt %d KB exceeds %d KB budget\n", step, len(userPrompt)/1024, maxClassifierPromptBytes/1024)
		fmt.Println()
		fmt.Printf("  → Result: %s (layer: oversize, profile abstain)\n", strings.ToUpper(act))
		return
	}
	start := time.Now()
	// Use the same augmented system prompt the real hook path uses
	// (hook.go step 5). Without this, `yolonot check` would show
	// different decisions from what Claude Code actually gets, since
	// user hints from ~/.yolonot/config.json + .yolonot walk-up would
	// be invisible to the dry-run.
	sysPrompt := BuildSystemPrompt(LoadConfig().Classifier, LoadHints())
	text, err := CallLLM(cfg, sysPrompt, userPrompt, 4096)
	ms := time.Since(start).Milliseconds()

	if err != nil {
		fmt.Printf("  [%d] LLM analysis:    error — %v\n", step, err)
		fmt.Println()
		fmt.Printf("  → Result: PASS-THROUGH (LLM unavailable)\n")
		return
	}

	d := ParseDecision(text)
	if d == nil {
		fmt.Printf("  [%d] LLM analysis:    error — could not parse response\n", step)
		fmt.Println()
		fmt.Printf("  → Result: PASS-THROUGH (parse error)\n")
		return
	}

	// The classifier emits (decision, risk); the gate's actual action is that
	// pair run through the active harness's risk map + profile (hook.go). The
	// map is applied AFTER the escalation step below, because escalation can
	// change the tier being mapped. Show the model's raw call here, the
	// mapped result at the end — or the preview lies whenever the profile
	// escalates a tier (e.g. critical → deny, high → ask).
	fmt.Printf("  [%d] LLM analysis:    %s (risk: %s, confidence: %.0f%%, %dms)\n",
		step, strings.ToUpper(d.Decision), riskOrDash(d.Risk), d.Confidence*100, ms)
	if d.Reasoning != "" {
		fmt.Printf("      Reasoning: %s\n", d.Reasoning)
	}
	step++

	// Escalation — the identical branch the hook runs after parsing the
	// primary verdict. Must stay in sync with hook.go step 5 or this
	// dry-run lies about what the hook decides.
	escOut, _ := maybeEscalate(ActiveHarness(), checkCfg, d, sysPrompt, userPrompt, time.Now())
	switch {
	case escOut.Outcome == "":
		// unconfigured or not triggered — silent, like the hook.
	case escOut.Fired:
		fmt.Printf("  [%d] Escalation:      %s → %s (%s, %dms)\n",
			step, escOut.Model, strings.ToUpper(sanitizeBanner(escOut.summary())), escOut.Outcome, escOut.Ms)
		if escOut.Reasoning != "" {
			fmt.Printf("      Reasoning: %s\n", sanitizeBanner(escOut.Reasoning))
		}
	default:
		fmt.Printf("  [%d] Escalation:      %s\n", step, escOut.Outcome)
	}

	// Risk map + unresolved policy — same resolution as the hook.
	final, passthrough := applyRiskMap(ActiveHarness(), d.Decision, d.Risk)
	layer := "llm"
	if d.Escalated {
		layer = "llm+esc"
	}
	fmt.Println()
	if passthrough {
		fmt.Printf("  → Result: PASS-THROUGH (layer: %s, risk map defers to host permissions)\n", layer)
		return
	}
	if final == "ask" {
		if degrade, reason := escalationUnresolvedDeny(checkCfg, escOut, d); degrade {
			fmt.Printf("  → Result: DENY (layer: %s, %s)\n", layer, sanitizeBanner(reason))
			return
		}
	}
	if final != d.Decision {
		fmt.Printf("  → Result: %s (layer: %s, %s → %s via %s risk map)\n",
			strings.ToUpper(final), layer, d.Decision, final, ActiveHarness().Name())
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
