package main

import (
	"fmt"
	"strings"
	"time"
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
				(r.Type == "path" && scriptPathRe.FindStringSubmatch(" "+command) != nil && globMatch(r.Pattern, scriptPathRe.FindStringSubmatch(" "+command)[1])) {
				fmt.Printf("  [%d] Deny rules:      DENY — matched deny-%s %s\n", step, r.Type, r.Pattern)
				fmt.Println()
				fmt.Printf("  → Result: DENY (layer: rule, absolute block)\n")
				return
			}
		}
	}
	fmt.Printf("  [%d] Deny rules:      no match\n", step)
	step++

	// Step: Allow/Ask rules (same as hook.go step 3 via MatchRuleWith)
	chains := hasChainOperator(command)
	sensitiveFile := hasSensitivePathWith(command, sensitive)
	skipAllow := chains || sensitiveFile

	match := MatchRuleWith(command, rules, sensitive)

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
					(r.Type == "path" && scriptPathRe.FindStringSubmatch(" "+command) != nil && globMatch(r.Pattern, scriptPathRe.FindStringSubmatch(" "+command)[1])) {
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

	userPrompt := BuildAnalyzePrompt(command)
	start := time.Now()
	text, err := CallLLM(cfg, SystemPrompt, userPrompt, 4096)
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

	decision := strings.ToUpper(d.Decision)
	fmt.Printf("  [%d] LLM analysis:    %s (confidence: %.0f%%, %dms)\n", step, decision, d.Confidence*100, ms)
	if d.Reasoning != "" {
		fmt.Printf("      Reasoning: %s\n", d.Reasoning)
	}
	fmt.Println()
	fmt.Printf("  → Result: %s (layer: llm)\n", decision)
}
