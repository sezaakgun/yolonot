package yolonot

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// escalationCallLLM is the seam unit tests swap to fake the second model.
var escalationCallLLM = CallLLM

// escalationHookBudget: don't start an escalation call once the hook has
// burned this much wall clock. Harnesses kill hooks around 60s, and a
// killed hook falls back to host permissions — worse than any verdict.
const escalationHookBudget = 20 * time.Second

// escalationMaxReasoning caps the escalation reasoning persisted per
// decisions.jsonl line.
const escalationMaxReasoning = 200

// riskRank orders tiers for the harden-upward comparison.
var riskRank = map[string]int{
	RiskSafe:     0,
	RiskLow:      1,
	RiskModerate: 2,
	RiskHigh:     3,
	RiskCritical: 4,
}

// escalationOutcome records what the escalation attempt did, for the
// decision log. Zero value = escalation not configured / not triggered.
type escalationOutcome struct {
	Fired       bool
	Model       string
	Decision    string // escalation model's raw decision
	Risk        string // escalation model's raw tier
	Reasoning   string // truncated
	Ms          int64
	Err         string // timeout | api | transport | parse
	Outcome     string // rescued | hardened | kept | error | skipped:<reason>
	PrimaryRisk string // original tier when the verdict was adopted/hardened
}

// summary renders the escalation verdict for banners/reasons.
func (o escalationOutcome) summary() string {
	if o.Err != "" {
		return "error: " + o.Err
	}
	if o.Decision == "" {
		return "not run"
	}
	return o.Decision + "/" + o.Risk
}

// adoptableTiers returns the subset of {safe, low} that the active risk
// map resolves to a real allow. Under strict/paranoid profiles this
// shrinks or empties — and with it the escalation rescue window.
func adoptableTiers(h Harness) map[string]bool {
	out := map[string]bool{}
	for _, t := range []string{RiskSafe, RiskLow} {
		if final, pass := applyRiskMap(h, "allow", t); !pass && final == "allow" {
			out[t] = true
		}
	}
	return out
}

// escalationGateReason reports why escalation is off: "unconfigured"
// (silent), "env-off", or "disabled". Empty = enabled.
func escalationGateReason(cfg Config, esc LLMConfig) string {
	if esc.URL == "" || esc.Model == "" {
		return "unconfigured"
	}
	if os.Getenv("YOLONOT_ESCALATION") == "off" {
		return "env-off"
	}
	if cfg.Escalation != nil && cfg.Escalation.Disabled {
		return "disabled"
	}
	return ""
}

// classifyLLMError buckets an escalation call failure for the log — an
// unattended run's post-mortem must distinguish "provider down" from
// "model said no".
func classifyLLMError(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "deadline"), strings.Contains(strings.ToLower(s), "timeout"):
		return "timeout"
	case strings.Contains(s, "API error"):
		return "api"
	default:
		return "transport"
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary — byte-slicing multi-byte UTF-8 would persist
	// invalid bytes into decisions.jsonl.
	cut := n - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// maybeEscalate consults the escalation model when the primary verdict d
// is uncertain in a way a second opinion could improve, mutating d in
// place on adoption:
//
//   - rescue: escalation says (allow, safe|low∩adoptable) → adopt wholesale;
//     the safer tier then resolves to allow through the same risk map.
//   - harden: escalation tier strictly more dangerous → adopt the TIER only,
//     keeping the primary decision. Catches ask-less harnesses' fail-open
//     cells (e.g. moderate→allow) without inventing a new deny class.
//
// Trigger = primary raw "ask" (the cross-harness "classifier unsure"
// signal) OR resolved action "ask", excluding critical (unrescuable by
// design), and only when the outcome could actually change under the
// active risk map (paranoid profiles skip entirely).
//
// cacheOK=false means a transient escalation failure should suppress this
// run's script-cache write — otherwise the un-rescued ask freezes into the
// cross-session cache and the one-shot rescue never re-fires.
func maybeEscalate(h Harness, cfg Config, d *Decision, sysPrompt, userPrompt string, hookStart time.Time) (out escalationOutcome, cacheOK bool) {
	cacheOK = true

	esc := GetEscalationConfig()
	switch reason := escalationGateReason(cfg, esc); reason {
	case "":
	case "unconfigured":
		return out, cacheOK
	default:
		out.Outcome = "skipped:" + reason
		return out, cacheOK
	}

	fire, skip := escalationTrigger(h, d)
	if !fire {
		if skip != "" {
			out.Outcome = "skipped:" + skip
		}
		return out, cacheOK
	}
	if time.Since(hookStart) > escalationHookBudget {
		out.Outcome = "skipped:budget"
		// Transient, like an error: don't freeze the un-escalated verdict
		// into the cross-session cache — a faster future run should get
		// its one-shot rescue.
		return out, false
	}

	out.Fired = true
	out.Model = esc.Model
	start := time.Now()
	text, err := escalationCallLLM(esc, sysPrompt, userPrompt, 4096)
	out.Ms = time.Since(start).Milliseconds()
	if err != nil {
		out.Err = classifyLLMError(err)
		out.Outcome = "error"
		return out, false
	}
	d2 := ParseDecision(text)
	if d2 == nil {
		out.Err = "parse"
		out.Outcome = "error"
		return out, false
	}
	out.Decision = d2.Decision
	out.Risk = d2.Risk
	out.Reasoning = truncateStr(strings.TrimSpace(d2.Reasoning), escalationMaxReasoning)

	out.Outcome, out.PrimaryRisk = escalationAdopt(h, d, d2)
	return out, cacheOK
}

// escalationTrigger evaluates whether a primary verdict qualifies for
// escalation under harness h. fire=false with skip="" means "not
// uncertain" (silent); skip="no-effect" means uncertain but no possible
// escalation verdict could change the outcome (e.g. paranoid profiles).
//
// Shared by the hook (maybeEscalate) and the eval cascade mode so the
// measured fire-rate is the production fire-rate.
func escalationTrigger(h Harness, d *Decision) (fire bool, skip string) {
	if d.Risk == RiskCritical {
		return false, ""
	}
	wouldBe, wouldPass := applyRiskMap(h, d.Decision, d.Risk)
	uncertain := d.Decision == "ask" || (!wouldPass && wouldBe == "ask")
	if !uncertain {
		return false, ""
	}
	if !escalationRescuePossible(h, wouldBe, wouldPass) && !escalationHardenPossible(wouldBe, wouldPass) {
		return false, "no-effect"
	}
	return true, ""
}

// escalationRescuePossible: a rescue may only replace a verdict whose
// RESOLVED action is ask or passthrough. A resolved DENY — the user's
// explicit hard-deny risk cell (strict/fast profiles, custom overrides) —
// is a policy statement, never uncertainty; the second model must not be
// able to relax it (same principle as the critical-tier carve-out). A
// resolved allow needs no rescue.
func escalationRescuePossible(h Harness, wouldBe string, wouldPass bool) bool {
	if !wouldPass && wouldBe != "ask" {
		return false
	}
	return len(adoptableTiers(h)) > 0
}

// escalationHardenPossible: hardening only changes the outcome where the
// current resolution is permissive (allow or passthrough).
func escalationHardenPossible(wouldBe string, wouldPass bool) bool {
	return wouldPass || wouldBe == "allow"
}

// escalationAdopt applies the adoption guardrails, mutating d:
// rescue only on an explicit (allow, adoptable-tier) verdict — an (ask,
// low) response must NOT be adopted, it would resolve right back to ask
// and poison the cache; harden adopts the TIER only, never a new decision.
// Shared by hook and eval cascade.
func escalationAdopt(h Harness, d *Decision, d2 *Decision) (outcome, primaryRisk string) {
	adoptable := adoptableTiers(h)
	wouldBe, wouldPass := applyRiskMap(h, d.Decision, d.Risk)

	if escalationRescuePossible(h, wouldBe, wouldPass) && d2.Decision == "allow" && adoptable[d2.Risk] {
		primaryRisk = d.Risk
		*d = *d2
		d.Escalated = true
		return "rescued", primaryRisk
	}
	if riskRank[d2.Risk] > riskRank[d.Risk] {
		primaryRisk = d.Risk
		d.Risk = d2.Risk
		d.Escalated = true
		return "hardened", primaryRisk
	}
	return "kept", ""
}

// escalationLogFields copies an outcome into a DecisionEntry.
func escalationLogFields(e *DecisionEntry, out escalationOutcome) {
	if out.Outcome == "" {
		return
	}
	e.Escalated = out.Fired
	e.EscalationModel = out.Model
	e.EscalationDecision = out.Decision
	e.EscalationRisk = out.Risk
	e.EscalationReasoning = out.Reasoning
	e.EscalationMs = out.Ms
	e.EscalationError = out.Err
	e.EscalationOutcome = out.Outcome
	e.PrimaryRisk = out.PrimaryRisk
}

// escalationUnresolvedDeny reports whether the unresolved policy should
// degrade a post-escalation residual ask to deny, and the banner reason.
func escalationUnresolvedDeny(cfg Config, out escalationOutcome, d *Decision) (bool, string) {
	if !out.Fired || EscalationUnresolved(cfg) != ActionDeny {
		return false, ""
	}
	primaryRisk := d.Risk
	if out.PrimaryRisk != "" {
		primaryRisk = out.PrimaryRisk
	}
	return true, fmt.Sprintf("unresolved after escalation — primary %s/%s, escalation %s; unresolved policy denies",
		d.Decision, primaryRisk, out.summary())
}

// cmdEscalation implements `yolonot escalation [on|off|setup|test]`.
func cmdEscalation(args []string) {
	cfg := LoadConfig()

	if len(args) == 0 {
		printEscalationStatus(cfg)
		return
	}

	switch strings.ToLower(args[0]) {
	case "on", "true", "1", "yes", "y":
		if cfg.Escalation == nil {
			if esc := GetEscalationConfig(); esc.URL != "" && esc.Model != "" {
				fmt.Println("Escalation is configured via LLM_ESCALATION_* env vars (no config block to toggle).")
				fmt.Println("It is on unless YOLONOT_ESCALATION=off is set in the environment.")
				return
			}
			fmt.Println("Escalation is not configured yet. Run: yolonot escalation setup")
			return
		}
		cfg.Escalation.Disabled = false
		SaveConfig(cfg)
		fmt.Printf("Escalation: ON — %s consulted before surfacing an ask.\n", GetEscalationConfig().Model)
	case "off", "false", "0", "no", "n":
		if cfg.Escalation == nil {
			if esc := GetEscalationConfig(); esc.URL != "" && esc.Model != "" {
				fmt.Println("Escalation is configured via LLM_ESCALATION_* env vars.")
				fmt.Println("Disable it with: export YOLONOT_ESCALATION=off")
				return
			}
			fmt.Println("Escalation is not configured; nothing to turn off.")
			return
		}
		// Keep the provider block — re-enabling must not need a re-setup.
		cfg.Escalation.Disabled = true
		SaveConfig(cfg)
		fmt.Println("Escalation: OFF — provider config kept; re-enable with: yolonot escalation on")
	case "setup":
		selected, ok := pickProvider(cfg, true)
		if !ok {
			return
		}
		if cfg.Escalation == nil {
			cfg.Escalation = &EscalationConfig{}
		}
		cfg.Escalation.Provider = selected
		cfg.Escalation.Disabled = false
		SaveConfig(cfg)
		fmt.Printf("\nEscalation provider set: %s via %s\n", selected.Model, selected.URL)
		testProviderConnection(selected)
	case "test":
		// Non-interactive connection test (CI preflight): resolves config
		// including env overrides and inheritance, exits 0/1.
		esc := GetEscalationConfig()
		if esc.URL == "" || esc.Model == "" {
			fmt.Fprintln(os.Stderr, "escalation: not configured (no provider in config.json and no LLM_ESCALATION_URL/LLM_ESCALATION_MODEL)")
			os.Exit(1)
		}
		fmt.Printf("Resolved: %s via %s\n", esc.Model, esc.URL)
		start := time.Now()
		text, err := CallLLM(esc, "Say ok", "ok", 256)
		ms := time.Since(start).Milliseconds()
		if err != nil {
			fmt.Fprintf(os.Stderr, "escalation: connection failed after %dms: %v\n", ms, err)
			os.Exit(1)
		}
		if text == "" {
			fmt.Fprintf(os.Stderr, "escalation: unexpected empty response after %dms\n", ms)
			os.Exit(1)
		}
		fmt.Printf("ok (%dms)\n", ms)
	default:
		fmt.Fprintf(os.Stderr, "Unknown value: %s (expected on|off|setup|test)\n", args[0])
		os.Exit(2)
	}
}

// printEscalationStatus renders the bare `yolonot escalation` view.
func printEscalationStatus(cfg Config) {
	esc := GetEscalationConfig()

	switch {
	case esc.URL == "" || esc.Model == "":
		fmt.Println("Escalation: not configured")
		fmt.Println("  A second, bigger model consulted before surfacing an ask.")
		fmt.Println("  Set up with: yolonot escalation setup")
		return
	case escalationGateReason(cfg, esc) == "env-off":
		fmt.Println("Escalation: OFF (YOLONOT_ESCALATION=off in this environment)")
	case escalationGateReason(cfg, esc) == "disabled":
		fmt.Println("Escalation: OFF (configured; enable with: yolonot escalation on)")
	default:
		fmt.Println("Escalation: ON")
	}

	fmt.Printf("  Model:      %s via %s\n", esc.Model, esc.URL)
	fmt.Println("  Trigger:    primary classifier uncertain (would ask), except critical")
	fmt.Printf("  Unresolved: %s\n", EscalationUnresolved(cfg))
	if prim := GetLLMConfig(); prim.URL == esc.URL && prim.Model == esc.Model {
		fmt.Println("  ⚠ Escalation resolves to the SAME provider+model as the primary —")
		fmt.Println("    asking the same model twice is not a second opinion.")
	}

	fired, rescued, hardened := 0, 0, 0
	for _, e := range ReadRecentDecisions(200) {
		// Cache replays carry Escalated without an outcome — live fires
		// only, same filter as `yolonot stats`.
		if e.Escalated && e.EscalationOutcome != "" {
			fired++
		}
		switch e.EscalationOutcome {
		case "rescued":
			rescued++
		case "hardened":
			hardened++
		}
	}
	if fired > 0 {
		fmt.Printf("  Recent:     %d fired, %d rescued, %d hardened (last 200 decisions)\n", fired, rescued, hardened)
	}
	fmt.Println()
	fmt.Println("Usage: yolonot escalation [on|off|setup|test]")
}
