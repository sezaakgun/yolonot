package yolonot

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestExtractPrediction is the metric-switch logic from runCase, lifted
// out of the LLM-call path so we can lock it in without standing up a
// CallLLM mock. Three behaviors matter:
//
//   - decision mode: returns d.Decision verbatim (including empty)
//   - risk mode: returns d.Risk verbatim (including empty)
//   - nil Decision: returns "" for both modes (caller records "error")
//
// If this ever regresses, eval scores can silently swap which field
// they grade against — the kind of bug that doesn't fail tests but
// invalidates every previous benchmark.
func TestExtractPrediction(t *testing.T) {
	cases := []struct {
		name   string
		d      *Decision
		metric string
		want   string
	}{
		{"nil decision, decision metric", nil, "", ""},
		{"nil decision, risk metric", nil, "risk", ""},
		{"decision mode reads Decision",
			&Decision{Decision: "allow", Risk: "safe"}, "", "allow"},
		{"explicit decision metric reads Decision",
			&Decision{Decision: "ask", Risk: "high"}, "decision", "ask"},
		{"risk mode reads Risk",
			&Decision{Decision: "ask", Risk: "high"}, "risk", "high"},
		{"risk mode returns empty Risk when model omitted tier",
			&Decision{Decision: "allow", Risk: ""}, "risk", ""},
		{"decision mode returns empty Decision when model returned malformed",
			&Decision{Decision: "", Risk: "safe"}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractPrediction(tc.d, tc.metric)
			if got != tc.want {
				t.Errorf("extractPrediction(%+v, %q) = %q, want %q",
					tc.d, tc.metric, got, tc.want)
			}
		})
	}
}

// TestFilterAnnotatedForRisk locks in the documented behavior of the
// `--metric risk` case filter: only cases with an expected_risk label
// are graded, and the dropped count is reported so users can see why
// their 176-case suite became 102 cases.
func TestFilterAnnotatedForRisk(t *testing.T) {
	in := []EvalCase{
		{ID: "a", ExpectedRisk: "safe"},
		{ID: "b", ExpectedRisk: ""},
		{ID: "c", ExpectedRisk: "high"},
		{ID: "d", ExpectedRisk: ""},
		{ID: "e", ExpectedRisk: "critical"},
	}
	kept, dropped := filterAnnotatedForRisk(in)
	if dropped != 2 {
		t.Errorf("dropped: got %d, want 2", dropped)
	}
	wantIDs := []string{"a", "c", "e"}
	var gotIDs []string
	for _, c := range kept {
		gotIDs = append(gotIDs, c.ID)
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Errorf("kept ids: got %v, want %v", gotIDs, wantIDs)
	}
}

// TestFilterAnnotatedForRiskEmpty handles the edge where every case
// lacks annotation — caller then prints "no annotated cases left".
// Returning nil + dropped=len(in) is the contract.
func TestFilterAnnotatedForRiskEmpty(t *testing.T) {
	in := []EvalCase{{ID: "a"}, {ID: "b"}}
	kept, dropped := filterAnnotatedForRisk(in)
	if len(kept) != 0 {
		t.Errorf("kept: got %d cases, want 0", len(kept))
	}
	if dropped != 2 {
		t.Errorf("dropped: got %d, want 2", dropped)
	}
}

// TestFilterAnnotatedForRiskAllAnnotated covers the inverse — all
// cases pass the filter, dropped count is zero, output preserves
// input order.
func TestFilterAnnotatedForRiskAllAnnotated(t *testing.T) {
	in := []EvalCase{
		{ID: "a", ExpectedRisk: "safe"},
		{ID: "b", ExpectedRisk: "high"},
	}
	kept, dropped := filterAnnotatedForRisk(in)
	if dropped != 0 {
		t.Errorf("dropped: got %d, want 0", dropped)
	}
	if len(kept) != 2 || kept[0].ID != "a" || kept[1].ID != "b" {
		t.Errorf("kept: got %+v, want [a, b] in order", kept)
	}
}

// TestParseEvalArgsMetricFlag locks the positive paths for --metric
// parsing. The negative path (invalid value triggers os.Exit) isn't
// testable in-process without a subprocess fork; covered manually in
// the verification section of docs/eval.md.
func TestParseEvalArgsMetricFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"default empty", []string{"--model", "x"}, ""},
		{"explicit decision", []string{"--metric", "decision", "--model", "x"}, "decision"},
		{"risk", []string{"--metric", "risk", "--model", "x"}, "risk"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := parseEvalArgs(tc.args)
			if opts.Metric != tc.want {
				t.Errorf("Metric: got %q, want %q", opts.Metric, tc.want)
			}
		})
	}
}

// TestParseEvalArgsWithHintsFlag locks the boolean flag — silent flip
// from false to true is a real risk because eval results stop being
// machine-independent the moment it activates.
func TestParseEvalArgsWithHintsFlag(t *testing.T) {
	if opts := parseEvalArgs([]string{"--model", "x"}); opts.WithHints {
		t.Errorf("default WithHints should be false; got true")
	}
	opts := parseEvalArgs([]string{"--with-hints", "--model", "x"})
	if !opts.WithHints {
		t.Errorf("--with-hints did not set WithHints to true")
	}
}

// withMockLLM swaps evalCallLLM for the duration of a test, returning
// the canned responses in order. Restores the real function via
// t.Cleanup so parallel tests don't see the mock. Returning a
// trailing error advances to the next canned response.
func withMockLLM(t *testing.T, responses []string, err error) {
	t.Helper()
	orig := evalCallLLM
	idx := 0
	evalCallLLM = func(cfg LLMConfig, system, user string, maxTokens int) (string, error) {
		if idx >= len(responses) {
			t.Fatalf("mock LLM called more times than responses provided (idx=%d)", idx)
		}
		r := responses[idx]
		idx++
		if err != nil {
			return r, err
		}
		return r, nil
	}
	t.Cleanup(func() { evalCallLLM = orig })
}

// TestRunCaseDecisionModePassing locks the happy path in decision
// mode: model returns valid JSON with decision="allow", suite says
// allow, prediction recorded as allow, Passed() returns true.
func TestRunCaseDecisionModePassing(t *testing.T) {
	withMockLLM(t, []string{
		`{"decision":"allow","risk":"safe","short":"read-only","reasoning":"ls"}`,
	}, nil)

	c := EvalCase{ID: "t1", Command: "ls", Expected: "allow"}
	opts := EvalOptions{Runs: 1, MaxTokens: 500}
	r := runCase(c, LLMConfig{URL: "x", Model: "x"}, "prompt", "greenfield", opts)

	if r.Expected != "allow" {
		t.Errorf("Expected: got %q, want allow", r.Expected)
	}
	if len(r.Predictions) != 1 || r.Predictions[0] != "allow" {
		t.Errorf("Predictions: got %v, want [allow]", r.Predictions)
	}
	if !r.Passed() {
		t.Errorf("Passed() should be true on matching decision")
	}
}

// TestRunCaseRiskModeReadsRiskField confirms the metric switch flows
// all the way through runCase: case has expected_risk, model returns
// risk=high, recorded prediction is "high" (not the decision field).
func TestRunCaseRiskModeReadsRiskField(t *testing.T) {
	withMockLLM(t, []string{
		`{"decision":"ask","risk":"high","short":"prod kubectl delete","reasoning":"x"}`,
	}, nil)

	c := EvalCase{ID: "t2", Command: "kubectl rm pod", Expected: "ask", ExpectedRisk: "high"}
	opts := EvalOptions{Runs: 1, MaxTokens: 500, Metric: "risk"}
	r := runCase(c, LLMConfig{URL: "x", Model: "x"}, "prompt", "greenfield", opts)

	if r.Expected != "high" {
		t.Errorf("Expected (risk mode): got %q, want high", r.Expected)
	}
	if len(r.Predictions) != 1 || r.Predictions[0] != "high" {
		t.Errorf("Predictions: got %v, want [high]", r.Predictions)
	}
	if !r.Passed() {
		t.Errorf("Passed() should be true on matching tier")
	}
}

// TestRunCaseRiskModeMissingRiskFieldIsError covers the regression
// the SystemPrompt fix targeted: pre-fix, models emitted decision
// without risk and we recorded "error". Even with the new prompt
// requiring risk, robustness against malformed responses matters.
func TestRunCaseRiskModeMissingRiskFieldIsError(t *testing.T) {
	withMockLLM(t, []string{
		`{"decision":"allow","reasoning":"no risk emitted"}`,
	}, nil)

	c := EvalCase{ID: "t3", Command: "ls", Expected: "allow", ExpectedRisk: "safe"}
	opts := EvalOptions{Runs: 1, MaxTokens: 500, Metric: "risk"}
	r := runCase(c, LLMConfig{URL: "x", Model: "x"}, "prompt", "greenfield", opts)

	if len(r.Predictions) != 1 || r.Predictions[0] != "error" {
		t.Errorf("Predictions: got %v, want [error]", r.Predictions)
	}
	if r.Passed() {
		t.Errorf("Passed() should be false on error")
	}
}

// TestRunCaseLLMErrorRecordsError confirms transport-layer failures
// (timeout, 5xx, network) are recorded as "error" predictions rather
// than being silently dropped or panicking. Without this, eval would
// over-report accuracy on flaky providers.
func TestRunCaseLLMErrorRecordsError(t *testing.T) {
	t.Helper()
	orig := evalCallLLM
	evalCallLLM = func(cfg LLMConfig, system, user string, maxTokens int) (string, error) {
		return "", fmt.Errorf("simulated network timeout")
	}
	t.Cleanup(func() { evalCallLLM = orig })

	c := EvalCase{ID: "t5", Command: "ls", Expected: "allow"}
	opts := EvalOptions{Runs: 1, MaxTokens: 500}
	r := runCase(c, LLMConfig{URL: "localhost", Model: "x"}, "prompt", "greenfield", opts)

	if len(r.Predictions) != 1 || r.Predictions[0] != "error" {
		t.Errorf("Predictions: got %v, want [error]", r.Predictions)
	}
	if len(r.RawResponses) != 1 || r.RawResponses[0] != "" {
		t.Errorf("RawResponses: got %v, want one empty string", r.RawResponses)
	}
	if r.Passed() {
		t.Errorf("Passed() should be false on error")
	}
}

// TestRunCaseRecordsMultipleRunsAndMajority verifies the consensus
// logic: 3 runs, two return "ask" and one returns "allow", majority
// = "ask", Passed() compares majority to Expected.
func TestRunCaseRecordsMultipleRunsAndMajority(t *testing.T) {
	withMockLLM(t, []string{
		`{"decision":"ask","risk":"high","reasoning":"r1"}`,
		`{"decision":"allow","risk":"low","reasoning":"r2"}`,
		`{"decision":"ask","risk":"high","reasoning":"r3"}`,
	}, nil)

	c := EvalCase{ID: "t4", Command: "x", Expected: "ask"}
	opts := EvalOptions{Runs: 3, MaxTokens: 500}
	r := runCase(c, LLMConfig{URL: "localhost", Model: "x"}, "prompt", "greenfield", opts)

	if len(r.Predictions) != 3 {
		t.Fatalf("Predictions len: got %d, want 3", len(r.Predictions))
	}
	if maj := r.MajorityPrediction(); maj != "ask" {
		t.Errorf("MajorityPrediction: got %q, want ask", maj)
	}
	if !r.Passed() {
		t.Errorf("Passed() should be true (majority matches expected)")
	}
	if c := r.Consistency(); c != 2.0/3.0 {
		t.Errorf("Consistency: got %f, want 0.667", c)
	}
}

// TestParseEvalArgsValidatedRejectsBadMetric covers the validation
// path that the os.Exit-based parseEvalArgs is built on. Locks in
// that a typo like `--metric riks` is rejected with a clear error
// rather than silently grading against the wrong field. parseEvalArgs
// (the os.Exit wrapper) is intentionally not tested here — testing
// os.Exit requires forking a subprocess.
func TestParseEvalArgsValidatedRejectsBadMetric(t *testing.T) {
	_, err := parseEvalArgsValidated([]string{"--metric", "riks"})
	if err == nil {
		t.Fatal("expected error on invalid --metric value")
	}
	if !strings.Contains(err.Error(), `"riks"`) {
		t.Errorf("error should quote the offending value; got %v", err)
	}
}

// TestParseEvalArgsValidatedAcceptsGoodValues mirrors the positive
// paths in TestParseEvalArgsMetricFlag but routes through the
// error-returning entry point so we cover both code paths.
func TestParseEvalArgsValidatedAcceptsGoodValues(t *testing.T) {
	for _, v := range []string{"", "decision", "risk"} {
		args := []string{}
		if v != "" {
			args = []string{"--metric", v}
		}
		opts, err := parseEvalArgsValidated(args)
		if err != nil {
			t.Errorf("unexpected error for %q: %v", v, err)
		}
		if opts.Metric != v {
			t.Errorf("Metric for %q: got %q, want %q", v, opts.Metric, v)
		}
	}
}

// TestParseEvalArgsDefaults sanity-checks the few defaults that are
// load-bearing for the reported numbers: Runs=3 means tests with
// fewer runs are explicit; Timeout/MaxTokens have specific values
// observed in CI configs. Catching accidental default changes here
// is cheap.
func TestParseEvalArgsDefaults(t *testing.T) {
	opts := parseEvalArgs([]string{})
	if opts.Runs != 3 {
		t.Errorf("Runs default: got %d, want 3", opts.Runs)
	}
	if opts.Timeout != 15 {
		t.Errorf("Timeout default: got %d, want 15", opts.Timeout)
	}
	if opts.MaxTokens != 4096 {
		t.Errorf("MaxTokens default: got %d, want 4096", opts.MaxTokens)
	}
	if opts.Verbose || opts.NoThink || opts.WithHints {
		t.Errorf("boolean defaults should all be false; got %+v", opts)
	}
}
