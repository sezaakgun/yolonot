package yolonot

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// reviewCallLLM is a package-level indirection over CallLLM that lets
// tests mock the review subcommand's model call. Same pattern as
// eval.go's evalCallLLM — keeps production path one extra dereference,
// makes the LLM-side of `yolonot classifier review` testable.
var reviewCallLLM = CallLLM

// cmdClassifier is the CLI entry point for `yolonot classifier ...`. The
// subcommands mirror Claude Code's `claude auto-mode defaults|config|critique`
// (renamed `critique → review`) so users moving between tools share one
// mental model — yolonot's classifier hints are the closest analog to
// autoMode's environment / allow / soft_deny prose.
//
// All subcommands are read-only. Mutators (set/add/remove) are deferred:
// hand-edited config.json and walk-up .yolonot files are the supported
// way to author hints today. See docs/llm-customization.md.
func cmdClassifier(args []string) {
	if len(args) == 0 {
		printClassifierEffective(os.Stdout)
		return
	}
	switch args[0] {
	case "defaults":
		printClassifierDefaults(os.Stdout)
	case "config":
		printClassifierEffective(os.Stdout)
	case "review":
		runClassifierReview()
	case "verify":
		runClassifierVerify()
	case "help", "-h", "--help":
		printClassifierUsage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "yolonot classifier: unknown subcommand %q\n\n", args[0])
		printClassifierUsage(os.Stderr)
		os.Exit(2)
	}
}

func printClassifierUsage(w *os.File) {
	fmt.Fprintln(w, "Usage: yolonot classifier [defaults|config|review|verify]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Inspect and validate the LLM classifier's prompt customization.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  defaults   Print the built-in system prompt and (empty) default hint lists as JSON")
	fmt.Fprintln(w, "  config     Print the resolved hints (config + walk-up, $defaults expanded) as JSON")
	fmt.Fprintln(w, "  review     Ask the active LLM provider to flag ambiguous or redundant custom hints")
	fmt.Fprintln(w, "  verify     Check a custom system_prompt still yields parseable verdicts (round-trips real probes)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Customize via ~/.yolonot/config.json (classifier.{context,allow_hints,ask_hints,system_prompt})")
	fmt.Fprintln(w, "or per-project .yolonot files (context \"...\" / allow-hint \"...\" / ask-hint \"...\" / system-prompt \"...\").")
	fmt.Fprintln(w, "system_prompt fully replaces the built-in base prompt; hints still append on top.")
}

// classifierDefaultsPayload is the schema printed by `yolonot classifier defaults`.
// Stable: documented in docs/llm-customization.md so users can pipe it through jq.
type classifierDefaultsPayload struct {
	SystemPrompt string   `json:"system_prompt"`
	Context      []string `json:"context"`
	AllowHints   []string `json:"allow_hints"`
	AskHints     []string `json:"ask_hints"`
}

func printClassifierDefaults(w *os.File) {
	payload := classifierDefaultsPayload{
		SystemPrompt: SystemPrompt,
		Context:      append([]string{}, builtinClassifierContext...),
		AllowHints:   append([]string{}, builtinClassifierAllowHints...),
		AskHints:     append([]string{}, builtinClassifierAskHints...),
	}
	if payload.Context == nil {
		payload.Context = []string{}
	}
	if payload.AllowHints == nil {
		payload.AllowHints = []string{}
	}
	if payload.AskHints == nil {
		payload.AskHints = []string{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

// classifierEffectivePayload is the schema printed by `yolonot classifier config`.
// Includes the actual system prompt that would be sent on the next LLM call,
// which is the most useful single field for debugging unexpected decisions.
type classifierEffectivePayload struct {
	Backend      string   `json:"backend"`
	Context      []string `json:"context"`
	AllowHints   []string `json:"allow_hints"`
	AskHints     []string `json:"ask_hints"`
	SystemPrompt string   `json:"system_prompt"`
}

func printClassifierEffective(w *os.File) {
	cfg := LoadConfig().Classifier
	walkup := LoadHints()

	context := expandDefaults(cfg.Context, builtinClassifierContext)
	context = append(context, walkup.Context...)
	allow := expandDefaults(cfg.AllowHints, builtinClassifierAllowHints)
	allow = append(allow, walkup.AllowHints...)
	ask := expandDefaults(cfg.AskHints, builtinClassifierAskHints)
	ask = append(ask, walkup.AskHints...)

	backend := cfg.Impl
	if backend == "" {
		backend = "llm"
	}

	payload := classifierEffectivePayload{
		Backend:      backend,
		Context:      context,
		AllowHints:   allow,
		AskHints:     ask,
		SystemPrompt: BuildSystemPrompt(cfg, walkup),
	}
	if payload.Context == nil {
		payload.Context = []string{}
	}
	if payload.AllowHints == nil {
		payload.AllowHints = []string{}
	}
	if payload.AskHints == nil {
		payload.AskHints = []string{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

// classifierReviewPrompt is the meta-prompt used by `yolonot classifier review`
// to audit the user's custom hints. We deliberately ask for a flat JSON
// findings list (no nested structure) so the output is easy to pipe through
// jq and so models that aren't great at nested JSON still produce something
// usable.
const classifierReviewPrompt = `You are auditing safety-classifier hints written by an engineer for a command-safety LLM.

For each hint provided, decide whether it is likely to cause problems and flag:
  (1) ambiguity     — multiple plausible readings; the LLM may interpret it differently than intended
  (2) redundancy    — restates rules the base classifier already applies
  (3) over-broad    — likely to trigger on commands the engineer did not mean to cover
  (4) over-permit   — would silence a real safety check the engineer probably wants

Return ONLY a JSON object with this exact shape:
{"findings":[{"hint":"<verbatim hint text>","kind":"context|allow_hint|ask_hint","severity":"info|warn","note":"one short sentence"}]}

If a hint is fine, do not include it in findings. If all hints are fine, return {"findings":[]}.`

func runClassifierReview() {
	if code := executeClassifierReview(os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
}

// executeClassifierReview is the testable body of `yolonot classifier
// review`. Returns the exit code (0 success, non-zero error) and writes
// to the given streams. Lets unit tests mock reviewCallLLM and assert
// on output without forking a subprocess for os.Exit.
func executeClassifierReview(stdout, stderr io.Writer) int {
	cfg := LoadConfig()
	llm := GetLLMConfig()
	if llm.URL == "" || llm.Model == "" {
		fmt.Fprintln(stderr, "yolonot classifier review: LLM provider not configured. Run `yolonot provider`.")
		return 1
	}
	walkup := LoadHints()
	user := buildClassifierReviewUserPrompt(cfg.Classifier, walkup)
	if user == "" {
		fmt.Fprintln(stdout, "yolonot classifier review: no custom hints to review.")
		return 0
	}

	// Use a longer max_tokens than the classifier (300) — the review can
	// produce one finding per hint plus prose, so cap higher. Timeout is
	// governed by the provider's LLMConfig.TimeoutSeconds (set per
	// provider in setup), not a separate context here.
	raw, err := reviewCallLLM(llm, classifierReviewPrompt, user, 1500)
	if err != nil {
		fmt.Fprintf(stderr, "yolonot classifier review: LLM call failed: %v\n", err)
		return 1
	}
	// Try to pretty-print the JSON if the model obeyed the schema; otherwise
	// fall through to raw output so the user can still see what came back.
	if pretty, ok := tryPrettyJSON(raw); ok {
		fmt.Fprintln(stdout, pretty)
		return 0
	}
	fmt.Fprintln(stdout, strings.TrimSpace(raw))
	return 0
}

// verifyCallLLM is a package-level indirection over CallLLM that lets tests
// mock the verify subcommand's probe calls. Mirrors reviewCallLLM.
var verifyCallLLM = CallLLM

// classifierVerifyProbe is a canned command sent through the real classifier
// pipeline to prove a custom system prompt still yields parseable verdicts.
// danger=true probes are expected to be flagged; a danger probe that comes
// back allow is surfaced as a safety NOTE, not a hard failure — an
// intentionally permissive override is a legitimate (if risky) choice, so
// verify checks that the prompt WORKS, not that the policy is cautious.
type classifierVerifyProbe struct {
	cmd    string
	danger bool
}

var classifierVerifyProbes = []classifierVerifyProbe{
	{"ls -la", false},
	{"rm -rf /", true},
	{"git push --force origin main", true},
}

func runClassifierVerify() {
	if code := executeClassifierVerify(os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
}

// executeClassifierVerify is the testable body of `yolonot classifier
// verify`. It answers one question — will this custom system_prompt actually
// work as a classifier prompt? — in two gates:
//
//	STATIC: the prompt must still instruct the model to emit the
//	        {"decision","risk"} verdict contract. Missing → hard fail, no
//	        LLM call (this is the "wrongfully set it" case).
//	LIVE:   round-trip a few real probe commands through the configured
//	        provider and assert each reply parses to a valid verdict. Skipped
//	        with a note when no provider is configured (static-only).
//
// Returns 0 on pass / static-only-pass / no-override, non-zero when the
// override would not function. Non-zero is scriptable (CI gate).
func executeClassifierVerify(stdout, stderr io.Writer) int {
	cfg := LoadConfig().Classifier
	walkup := LoadHints()

	if !HasSystemPromptOverride(cfg, walkup) {
		fmt.Fprintln(stdout, "No custom system_prompt override set — the built-in base prompt is in use (nothing to verify).")
		return 0
	}
	base, source := resolveBasePromptWithSource(cfg, walkup)
	fmt.Fprintf(stdout, "Verifying custom system prompt (%s)\n\n", source)

	// Gate 1 — static contract check. Cheap, offline, catches the common
	// "I rewrote the prompt and dropped the JSON instruction" mistake.
	if !systemPromptHasContract(base) {
		fmt.Fprintln(stdout, `✗ STATIC: prompt is missing the JSON verdict contract (no "decision"/"risk" keys).`)
		fmt.Fprintln(stdout, `  It must tell the model to output {"decision":"allow|ask","risk":"safe|low|moderate|high|critical",...}.`)
		fmt.Fprintln(stdout, "  Without it the reply can't be parsed and every command falls through to the host's permission layer.")
		return 1
	}
	fmt.Fprintln(stdout, "✓ STATIC: JSON verdict contract present.")

	// Gate 2 — live round-trip. The real test: does the provider, under this
	// prompt, produce parseable verdicts for actual commands?
	llm := GetLLMConfig()
	if llm.URL == "" || llm.Model == "" {
		fmt.Fprintln(stdout, "\n… LIVE: skipped — no LLM provider configured (run `yolonot provider`). Static check only.")
		return 0
	}

	assembled := BuildSystemPrompt(cfg, walkup)
	fmt.Fprintf(stdout, "\nLIVE: sending %d probe(s) to %s …\n", len(classifierVerifyProbes), llm.Model)

	failed := 0
	for _, p := range classifierVerifyProbes {
		raw, err := verifyCallLLM(llm, assembled, BuildAnalyzePrompt(p.cmd, ""), 300)
		if err != nil {
			fmt.Fprintf(stdout, "  ✗ %-30s call failed: %v\n", p.cmd, err)
			failed++
			continue
		}
		d := ParseDecision(raw)
		if d == nil || (d.Decision != ActionAllow && d.Decision != ActionAsk) || !isValidRisk(d.Risk) {
			fmt.Fprintf(stdout, "  ✗ %-30s unparseable / invalid verdict\n", p.cmd)
			fmt.Fprintf(stdout, "      raw: %s\n", clipOneLine(raw, 160))
			failed++
			continue
		}
		fmt.Fprintf(stdout, "  ✓ %-30s → %s / %s\n", p.cmd, d.Decision, d.Risk)
		if p.danger && d.Decision == ActionAllow {
			fmt.Fprintf(stdout, "      ⚠ NOTE: a dangerous command returned allow — this override may have weakened safety.\n")
		}
	}

	fmt.Fprintln(stdout)
	if failed > 0 {
		fmt.Fprintf(stdout, "FAIL: %d/%d probe(s) did not produce a valid verdict. This override will NOT work as a classifier prompt.\n", failed, len(classifierVerifyProbes))
		return 1
	}
	fmt.Fprintln(stdout, "PASS: every probe produced a valid verdict. The custom prompt works.")
	return 0
}

// clipOneLine collapses s to a single line and truncates to max runes so a
// failed probe's raw reply is legible on one terminal row.
func clipOneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}

func buildClassifierReviewUserPrompt(cfg ClassifierConfig, walkup WalkupHints) string {
	context := expandDefaults(cfg.Context, builtinClassifierContext)
	context = append(context, walkup.Context...)
	allow := expandDefaults(cfg.AllowHints, builtinClassifierAllowHints)
	allow = append(allow, walkup.AllowHints...)
	ask := expandDefaults(cfg.AskHints, builtinClassifierAskHints)
	ask = append(ask, walkup.AskHints...)

	if len(context) == 0 && len(allow) == 0 && len(ask) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("Hints to review:\n\n")
	if len(context) > 0 {
		b.WriteString("context:\n")
		for _, s := range context {
			b.WriteString("- ")
			b.WriteString(s)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if len(allow) > 0 {
		b.WriteString("allow_hints:\n")
		for _, s := range allow {
			b.WriteString("- ")
			b.WriteString(s)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if len(ask) > 0 {
		b.WriteString("ask_hints:\n")
		for _, s := range ask {
			b.WriteString("- ")
			b.WriteString(s)
			b.WriteString("\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// tryPrettyJSON re-indents s if it parses as JSON, returning ok=false
// otherwise so the caller can fall back to printing the raw response.
func tryPrettyJSON(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	// Strip a Markdown code fence if the model wrapped its JSON in one.
	if strings.HasPrefix(s, "```") {
		if i := strings.Index(s, "\n"); i > 0 {
			s = s[i+1:]
		}
		if j := strings.LastIndex(s, "```"); j > 0 {
			s = s[:j]
		}
		s = strings.TrimSpace(s)
	}
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", false
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", false
	}
	return string(out), true
}
