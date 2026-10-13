package yolonot

import (
	"os"
	"strings"
)

// Risk tiers — one of these is tagged on every classifier result. Defined
// by reversibility + blast radius, not by confidence. A classifier picks a
// named bucket; each harness decides via its RiskMap what to DO with each.
//
// Picked for resolution: 5 tiers lets each harness set its own cutline (e.g.
// Claude asks on moderate, Codex passes it through, Gemini-yolo denies on
// high). 3 tiers was too coarse for that spread; more than 5 is bikeshedding.
const (
	RiskSafe     = "safe"     // read-only, no side effects (ls, cat, kubectl get)
	RiskLow      = "low"      // local, easily reversible writes (touch, mkdir, git add)
	RiskModerate = "moderate" // network/external or scoped state change (curl, git commit, docker build)
	RiskHigh     = "high"     // destructive but bounded (rm file, git push, kill PID)
	RiskCritical = "critical" // irreversible + wide blast radius (rm -rf /, dd of=/dev/sda)
)

// allRiskTiers is the canonical ordering (safest → most dangerous). Used for
// config merging, CLI `yolonot risk` listing, and eval-suite iteration.
var allRiskTiers = []string{RiskSafe, RiskLow, RiskModerate, RiskHigh, RiskCritical}

// isValidRisk reports whether s is one of the defined tiers. Used for input
// validation in the classifier parser + CLI override handler.
func isValidRisk(s string) bool {
	for _, t := range allRiskTiers {
		if s == t {
			return true
		}
	}
	return false
}

// ResolveRiskMap returns the effective tier→action mapping for a harness.
// Layers, highest precedence last:
//  1. Shipped defaults from the harness's RiskMap().
//  2. Active profile (per-harness override or global), translated through
//     the harness's ask-fallback rules.
//  3. ~/.yolonot/config.json policy.harness.<name>.risk_map cells.
//  4. YOLONOT_<HARNESS>_RISK_<TIER>=<action> env vars (per-session).
//
// Values are validated against the {allow, ask, deny, passthrough} set and
// dropped with a Verbosef log line if unknown — defensive against typos in
// hand-edited configs. Harness name must match h.Name() casing; env-var
// tokens are uppercased (YOLONOT_CLAUDE_RISK_CRITICAL=deny).
func ResolveRiskMap(h Harness) map[string]string {
	out := map[string]string{}
	if h == nil {
		return out
	}
	for k, v := range h.RiskMap() {
		out[k] = v
	}
	cfg := LoadConfig()
	if profile := ResolveActiveProfile(cfg, h); profile != nil {
		for tier, action := range TranslateProfile(profile.Map, h) {
			out[tier] = action
		}
	}
	if overrides := cfg.harnessPolicy(h.Name()).RiskMap; len(overrides) > 0 {
		{
			for tier, action := range overrides {
				if !isValidRisk(tier) {
					Verbosef("ResolveRiskMap: unknown tier %q in config for %s, ignored", tier, h.Name())
					continue
				}
				if !isValidAction(action) {
					Verbosef("ResolveRiskMap: unknown action %q for %s/%s, ignored", action, h.Name(), tier)
					continue
				}
				out[tier] = action
			}
		}
	}
	upperName := strings.ToUpper(h.Name())
	for _, tier := range allRiskTiers {
		envKey := "YOLONOT_" + upperName + "_RISK_" + strings.ToUpper(tier)
		if v := os.Getenv(envKey); v != "" {
			v = strings.ToLower(strings.TrimSpace(v))
			if !isValidAction(v) {
				Verbosef("ResolveRiskMap: env %s=%q unknown action, ignored", envKey, v)
				continue
			}
			out[tier] = v
		}
	}
	return out
}

// abstainAction is the decision yolonot emits when it deliberately does NOT
// send a command to the classifier — currently when the assembled prompt
// exceeds maxClassifierPromptBytes. It reuses the active profile's
// critical-tier policy (resolved per-harness via ResolveRiskMap), the most
// cautious cell the user has expressed a policy for, but clamps it so an
// UNJUDGED command is never auto-allowed or passed through (passthrough
// fails open on ask-less harnesses): deny stays deny, everything else — and
// any unset/invalid cell — becomes ask. This needs no new config and no
// profile migration: every profile, built-in or custom, already resolves a
// critical cell.
func abstainAction(h Harness) string {
	if ResolveRiskMap(h)[RiskCritical] == ActionDeny {
		return ActionDeny
	}
	return ActionAsk
}

// isValidAction reports whether a risk-map value is a known action.
func isValidAction(s string) bool {
	switch s {
	case ActionAllow, ActionAsk, ActionDeny, ActionPassthrough:
		return true
	}
	return false
}
