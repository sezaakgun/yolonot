package yolonot

import (
	"context"
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

// ClassifyMeta carries the contextual signals a classifier may want beyond
// the command itself. Extending this struct is source-compatible for
// implementations — unknown fields are ignored.
type ClassifyMeta struct {
	Cwd          string
	GitRoot      string
	ApprovedCmds []string // previously approved commands, for brownfield comparison
}

// RiskResult is the canonical output of any Classifier. The harness layer
// consumes this uniformly regardless of which backend produced it.
type RiskResult struct {
	Decision  string // "allow" or "ask" — classifier never emits "deny" (rules only)
	Risk      string // one of allRiskTiers
	Short     string // ≤60 char banner label
	Reason    string // one-line explanation, written to decisions.jsonl
	Backend   string // classifier name, for log attribution (e.g. "llm")
	LatencyMs int64  // observed wall time of the Classify call
}

// Classifier is the pluggable risk-tagging backend. Phase 1 ships a single
// implementation (LLMClassifier wrapping the existing CallLLM flow). Future
// phases — heuristic AST-based, distilled ML, KNN-over-embeddings — drop in
// as sibling files with no changes to harness / hook / rules code.
//
// Contract:
//   - Classify must be deterministic-modulo-backend: calling twice with the
//     same (cmd, meta) and same config should return the same tier, or at
//     least the same action under the harness risk map. Stochastic backends
//     (LLMs) meet this loosely; deterministic ones (heuristics) meet it
//     strictly.
//   - Empty Command is undefined behaviour; callers filter those out.
//   - Errors are advisory. On error, callers fall through to the next layer
//     (today: transparent / native permissions). Classifiers should NOT
//     fail-closed themselves — the hook pipeline decides fallback policy.
type Classifier interface {
	Name() string
	Classify(ctx context.Context, cmd string, meta ClassifyMeta) (RiskResult, error)
}

// registeredClassifiers holds all backends known to yolonot, populated at
// init-time by each classifier file. Order is registration order; ties
// broken by first-registered. Mirrors the harness registry pattern.
var registeredClassifiers []Classifier

// RegisterClassifier adds a Classifier to the registry. Called from each
// backend's init().
func RegisterClassifier(c Classifier) {
	registeredClassifiers = append(registeredClassifiers, c)
}

// GetClassifier returns the classifier with the given name, or nil. Used
// by ActiveClassifier for config/env lookup and by tests for assertions.
func GetClassifier(name string) Classifier {
	for _, c := range registeredClassifiers {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// Classifiers returns the registered backends in registration order. Used
// by the eval runner and CLI listing.
func Classifiers() []Classifier { return registeredClassifiers }

// ResolveRiskMap returns the effective tier→action mapping for a harness.
// Layers, highest precedence last:
//  1. Shipped defaults from the harness's RiskMap().
//  2. ~/.yolonot/config.json "risk_maps" override for that harness.
//  3. YOLONOT_<HARNESS>_RISK_<TIER>=<action> env vars (per-session).
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
	if cfg.RiskMaps != nil {
		if overrides, ok := cfg.RiskMaps[h.Name()]; ok {
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

// isValidAction reports whether a risk-map value is a known action.
func isValidAction(s string) bool {
	switch s {
	case ActionAllow, ActionAsk, ActionDeny, ActionPassthrough:
		return true
	}
	return false
}

// ActiveClassifier returns the backend yolonot should route classification
// through. Resolution:
//  1. YOLONOT_CLASSIFIER env var (explicit override — handy for CI / offline)
//  2. config.json "classifier" field
//  3. "llm" (historical default; matches Phase 1 ship)
//  4. First registered backend (last-resort for broken configs)
//
// Returns nil only if nothing is registered.
func ActiveClassifier() Classifier {
	if name := os.Getenv("YOLONOT_CLASSIFIER"); name != "" {
		if c := GetClassifier(name); c != nil {
			return c
		}
	}
	cfg := LoadConfig()
	if cfg.Classifier != "" {
		if c := GetClassifier(cfg.Classifier); c != nil {
			return c
		}
	}
	if c := GetClassifier("llm"); c != nil {
		return c
	}
	if len(registeredClassifiers) > 0 {
		return registeredClassifiers[0]
	}
	return nil
}
