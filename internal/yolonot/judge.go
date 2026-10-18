package yolonot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sezaakgun/yolonot/internal/fastallow"
)

// A Judge looks at a command and returns a verdict. Prechecks and the
// classifier used to be two mechanisms with two names; they differ only
// in position and in what they may decide (JudgeSpec.May). Rules and
// session memory are not judges: rules are the user's explicit word and
// always run first; memory replays an earlier verdict instead of forming
// one. Escalation is not a judge either: it re-judges an adopted verdict
// that would surface an ask, and runs once after the chain.
//
// The chain runs in config order; the first verdict a judge is allowed to
// give is adopted. Remote judges cost money and time, so the hook consults
// session similarity and the script cache once, right before the first
// remote judge.

// JudgeSpec is one entry of the "judges" list: fast_allow, exec:<path>, or
// a model name from the catalog. kind is resolved by Config.JudgeSpecs.
type JudgeSpec struct {
	Use  string   `json:"use"`
	May  []string `json:"may,omitempty"` // decisions this judge may hand down; empty = judge default
	kind string
}

// judgeDefaultMay is what a judge may decide when the spec leaves May empty.
var judgeDefaultMay = map[string][]string{
	judgeFastAllow: {"allow"},
	judgeExec:      {"allow"},
	judgeTyped:     {"allow", "ask"},
	judgeChat:      {"allow", "ask"},
}

// Kind is the resolved judge kind (fast_allow | exec | typed | chat | unknown).
func (s JudgeSpec) Kind() string {
	if s.kind != "" {
		return s.kind
	}
	switch {
	case s.Use == judgeFastAllow:
		return judgeFastAllow
	case strings.HasPrefix(s.Use, "exec:"):
		return judgeExec
	}
	return judgeUnknown
}

// effectiveMay is May, or the judge's default when unset.
func (s JudgeSpec) effectiveMay() []string {
	if len(s.May) > 0 {
		return s.May
	}
	return judgeDefaultMay[s.Kind()]
}

func (s JudgeSpec) may(decision string) bool {
	for _, m := range s.effectiveMay() {
		if m == decision {
			return true
		}
	}
	return false
}

// permit reports whether the judge may hand down v. A deny from a judge
// that may ask but not deny becomes ask, in place.
func (s JudgeSpec) permit(v *Verdict) bool {
	if v.Decision == ActionDeny && !s.may(ActionDeny) && s.may(ActionAsk) {
		v.Decision = ActionAsk
		if v.Dec != nil {
			v.Dec.Decision = ActionAsk
		}
	}
	return s.may(v.Decision)
}

// remote reports whether the judge calls a network model.
func (s JudgeSpec) remote() bool {
	switch s.Kind() {
	case judgeTyped, judgeChat:
		return true
	}
	return false
}

// JudgeInput is everything a judge may look at.
type JudgeInput struct {
	Command   string
	Cwd       string
	Canonical []byte // Claude-shape hook JSON, fed to exec judges on stdin
	Rules     []Rule
	Config    Config
	Harness   Harness
	HookStart time.Time
	Context   context.Context // shared hook deadline, including session similarity
	DryRun    bool            // `yolonot check`: never run exec judges
}

// Verdict is a judge's answer. Dec is set by classifier judges and carries
// what the cache and the decision log need; Layer is the historical log
// attribution kept byte-identical for tooling that greps decisions.jsonl.
type Verdict struct {
	Decision string
	Risk     string
	Short    string
	Reason   string
	Layer    string
	Ms       int64

	Dec            *Decision // classifier verdict (llm/decision), mutated by escalation
	CacheKey       string
	CacheContext   string
	ReplayBinding  string   // exact script snapshot the classifier and escalation saw
	ApprovalHashes []string // session approvals use that same snapshot
	Prompt         string   // user prompt the classifier saw; escalation reuses it
	Sys            string
	Attached       []string // script paths shown to the judge
	Withheld       []string // script paths referenced but not shown, with the reason
	Esc            escalationOutcome
	CacheOK        bool
	Override       bool // custom system_prompt override active (parse-error banner)
}

// judgeError kinds. The hook maps them to its existing pass-through
// banners; the chain itself just moves on to the next judge.
const (
	judgeErrUnavailable = "unavailable"
	judgeErrParse       = "parse"
	judgeErrOversize    = "oversize"
	judgeErrBudget      = "budget"
)

type judgeError struct {
	Kind     string
	Msg      string
	Override bool
	Verdict  Verdict // partial (Ms etc.) for logging
}

func (e *judgeError) Error() string { return e.Kind + ": " + e.Msg }

// runJudge executes one spec. ok=false with err=nil means the judge
// abstained (no verdict, nothing to log).
func runJudge(spec JudgeSpec, in *JudgeInput) (v Verdict, ok bool, err error) {
	ctx, cancel := hookBudgetContext(in.Context, in.HookStart)
	defer cancel()
	bounded := *in
	bounded.Context = ctx
	in = &bounded
	if ctx.Err() != nil {
		return Verdict{}, false, budgetJudgeError()
	}
	switch spec.Kind() {
	case judgeFastAllow:
		if pass, reason := fastallow.IsLocallySafeWith(in.Command, AllowRedirectPatterns(in.Rules)); pass {
			return Verdict{Decision: "allow", Risk: RiskSafe, Reason: reason, Layer: "fast_allow"}, true, nil
		}
		return Verdict{}, false, nil
	case judgeExec:
		path := strings.TrimPrefix(spec.Use, "exec:")
		if in.DryRun {
			return Verdict{}, false, nil
		}
		if _, reason, pass := runPreCheckContext(ctx, path, in.Canonical); pass {
			return Verdict{Decision: "allow", Reason: reason, Layer: "exec:" + preCheckShortName(path)}, true, nil
		}
		if ctx.Err() != nil {
			return Verdict{}, false, budgetJudgeError()
		}
		return Verdict{}, false, nil
	case judgeTyped, judgeChat:
		return runClassifierJudge(spec, in)
	}
	Verbosef("judges: unknown judge %q skipped (not fast_allow, exec:<path> or a model name)", spec.Use)
	return Verdict{}, false, nil
}

// runClassifierJudge: attach scripts once, guard the prompt size, call the
// model, parse. The prompt and cache key come from the same filesystem
// snapshot so the cache can never key on bytes the model did not see.
func runClassifierJudge(spec JudgeSpec, in *JudgeInput) (Verdict, bool, error) {
	attached, withheld := collectScripts(in.Command, in.Cwd)
	userPrompt := buildPromptFromCollected(in.Command, attached, withheld)
	// Oversize is checked before the provider: the abstain policy must
	// apply even when no model is configured to receive the prompt.
	if len(userPrompt) > maxClassifierPromptBytes {
		return Verdict{}, false, &judgeError{Kind: judgeErrOversize,
			Msg: fmt.Sprintf("classifier prompt %d KB exceeds %d KB budget", len(userPrompt)/1024, maxClassifierPromptBytes/1024)}
	}
	cfg := in.Config.ModelLLM(spec.Use)
	cfg.Context = in.Context
	if cfg.URL == "" || cfg.Model == "" {
		return Verdict{}, false, &judgeError{Kind: judgeErrUnavailable, Msg: "skipped — no provider configured for " + spec.Use}
	}
	hints := LoadHints(in.Cwd)
	sysPrompt := BuildSystemPrompt(in.Config.Prompt, hints)
	override := HasSystemPromptOverride(in.Config.Prompt, hints)

	replayBinding, approvalHashes := replaySnapshotFromCollected(in.Command, in.Cwd, attached, withheld)
	start := time.Now()
	var text string
	var err error
	if spec.Kind() == judgeTyped {
		text, err = callDecision(cfg, userPrompt+DecisionHints(in.Config.Prompt, hints))
	} else {
		text, err = CallLLM(cfg, sysPrompt, userPrompt, 4096)
	}
	ms := time.Since(start).Milliseconds()
	if err != nil {
		if in.Context != nil && in.Context.Err() != nil {
			return Verdict{}, false, budgetJudgeError()
		}
		if errors.Is(err, errDecisionResponse) {
			return Verdict{}, false, &judgeError{Kind: judgeErrParse, Msg: err.Error(), Verdict: Verdict{Ms: ms}}
		}
		return Verdict{}, false, &judgeError{Kind: judgeErrUnavailable, Msg: err.Error(), Verdict: Verdict{Ms: ms}}
	}
	d := ParseDecision(text)
	if d == nil {
		return Verdict{}, false, &judgeError{Kind: judgeErrParse, Msg: "parse error", Override: override, Verdict: Verdict{Ms: ms}}
	}
	seen, notSeen := describeCollected(attached, withheld)
	return Verdict{
		Decision: d.Decision, Risk: d.Risk, Short: d.Short, Reason: d.Reasoning,
		Layer: spec.Use, Ms: ms, Dec: d, Attached: seen, Withheld: notSeen,
		CacheKey:       hashCollected(in.Command, attached, withheld),
		CacheContext:   classifierContextFingerprint(in.Config, hints, in.Cwd),
		ReplayBinding:  replayBinding,
		ApprovalHashes: approvalHashes,
		Prompt:         userPrompt, Sys: sysPrompt, CacheOK: true, Override: override,
	}, true, nil
}

// escalateUncertain runs the escalation step on the adopted classifier
// verdict. Non-classifier verdicts (fast_allow, exec) carry no Decision to
// refine and are left alone. Guardrails live in maybeEscalate.
func escalateUncertain(in *JudgeInput, v *Verdict) {
	if v.Dec == nil {
		return
	}
	v.Esc, v.CacheOK = maybeEscalateContext(in.Context, in.Harness, in.Config, v.Dec, v.Sys, v.Prompt, in.HookStart)
	v.Decision, v.Risk, v.Short, v.Reason = v.Dec.Decision, v.Dec.Risk, v.Dec.Short, v.Dec.Reasoning
	if v.Dec.Escalated && !strings.HasSuffix(v.Layer, "+esc") {
		v.Layer += "+esc"
	}
}

// RunJudges walks the chain. beforeRemote runs once, before the first
// remote judge, and returns true when it produced a final answer itself
// (session similarity hit, cache hit) — the caller has already emitted.
// Returns the adopted verdict, or nil plus the last error when no judge
// decided.
func RunJudges(specs []JudgeSpec, in *JudgeInput, beforeRemote func() bool) (*Verdict, *judgeError, bool) {
	ctx, cancel := hookBudgetContext(in.Context, in.HookStart)
	defer cancel()
	bounded := *in
	bounded.Context = ctx
	in = &bounded
	var lastErr *judgeError
	memoryDone := false
	for _, spec := range specs {
		if ctx.Err() != nil {
			return nil, budgetJudgeError(), false
		}
		if spec.remote() && !memoryDone {
			memoryDone = true
			if beforeRemote != nil && beforeRemote() {
				return nil, nil, true
			}
			if ctx.Err() != nil {
				return nil, budgetJudgeError(), false
			}
		}
		v, ok, err := runJudge(spec, in)
		if err != nil {
			if je, isJE := err.(*judgeError); isJE {
				lastErr = je
			}
			if ctx.Err() != nil {
				return nil, budgetJudgeError(), false
			}
			continue
		}
		if !ok || !spec.permit(&v) {
			continue
		}
		return &v, lastErr, false
	}
	if ctx.Err() != nil {
		return nil, budgetJudgeError(), false
	}
	return nil, lastErr, false
}

// cmdJudges lists and edits the chain and second-opinion escalation:
// `yolonot judges [add <entry>|remove <n|entry>|move <n> up|down|escalation [on|off|setup|test]]`.
func cmdJudges(args []string) {
	cfg := LoadConfig()
	if len(args) == 0 || args[0] == "list" {
		printJudges(cfg)
		return
	}
	if args[0] == "escalation" || args[0] == "esc" {
		cmdEscalation(args[1:])
		return
	}
	if !requireV1(&cfg) {
		return
	}
	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: yolonot judges add <fast_allow|exec:<path>|model-name>")
			return
		}
		entry := strings.Join(args[1:], " ")
		sp := JudgeSpec{Use: entry}
		if err := validateJudgeSpec(cfg, sp); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for _, e := range cfg.Judges {
			if e.Use == entry {
				fmt.Printf("Already in the chain: %s\n", entry)
				return
			}
		}
		cfg.Judges = append(cfg.Judges, sp)
		mustSaveConfig(cfg)
		printJudges(cfg)
	case "remove", "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: yolonot judges remove <n|entry>")
			return
		}
		i := judgeIndex(cfg.Judges, strings.Join(args[1:], " "))
		if i < 0 {
			fmt.Fprintln(os.Stderr, "no such judge")
			os.Exit(2)
		}
		cfg.Judges = applyJudgeMove(cfg.Judges, i, 2)
		mustSaveConfig(cfg)
		printJudges(cfg)
	case "move":
		if len(args) < 3 || (args[2] != "up" && args[2] != "down") {
			fmt.Fprintln(os.Stderr, "Usage: yolonot judges move <n|entry> up|down")
			return
		}
		i := judgeIndex(cfg.Judges, args[1])
		if i < 0 {
			fmt.Fprintln(os.Stderr, "no such judge")
			os.Exit(2)
		}
		op := 0
		if args[2] == "down" {
			op = 1
		}
		cfg.Judges = applyJudgeMove(cfg.Judges, i, op)
		mustSaveConfig(cfg)
		printJudges(cfg)
	default:
		fmt.Fprintln(os.Stderr, "Usage: yolonot judges [add <entry>|remove <n|entry>|move <n|entry> up|down|escalation [on|off|setup|test]]")
		os.Exit(2)
	}
}

// validateJudgeSpec prevents a saved chain entry from selecting an empty
// executable or an unknown model. The TUI also uses this for JSON edits.
func validateJudgeSpec(cfg Config, spec JudgeSpec) error {
	if cfg.kindOf(spec) == judgeUnknown {
		return fmt.Errorf("%q is not fast_allow, exec:<path> or a model in `yolonot models`", spec.Use)
	}
	if cfg.kindOf(spec) == judgeExec && len(strings.Fields(strings.TrimPrefix(spec.Use, "exec:"))) == 0 {
		return fmt.Errorf("exec judge requires a non-empty executable path")
	}
	for _, decision := range spec.May {
		if decision != ActionAllow && decision != ActionAsk && decision != ActionDeny {
			return fmt.Errorf("judge %q: invalid may decision %q", spec.Use, decision)
		}
	}
	return nil
}

// judgeIndex resolves a 1-based index or an exact entry to a position.
func judgeIndex(specs []JudgeSpec, target string) int {
	if n, err := strconv.Atoi(target); err == nil && n >= 1 && n <= len(specs) {
		return n - 1
	}
	for i, sp := range specs {
		if sp.Use == target {
			return i
		}
	}
	return -1
}

func printJudges(cfg Config) {
	specs := cfg.JudgeSpecs()
	if len(specs) == 0 {
		fmt.Println("Judges: none configured — every command passes through to the host's own permissions.")
		fmt.Println("  Add one with: yolonot judges add fast_allow / yolonot judges add <model>")
	} else {
		fmt.Println("Judges (in order; the first permitted verdict wins):")
		for i, s := range specs {
			if s.Kind() == judgeUnknown {
				fmt.Printf("  [%d] %-24s unknown — not fast_allow, exec:<path> or a model name; skipped\n", i+1, s.Use)
				continue
			}
			fmt.Printf("  [%d] %-24s %-6s may: %s\n", i+1, s.Use, s.Kind(), strings.Join(s.effectiveMay(), ","))
		}
	}
	fmt.Println()
	printEscalationStatus(cfg)
	fmt.Println()
	fmt.Println("Rules and session memory always run before the chain; escalation and the risk map run once after it.")
	fmt.Println("Entries: fast_allow (built-in parser), exec:<path> (hook binary), or a model name from `yolonot models`.")
}
