package yolonot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestJudgeFailoverSharesAbsoluteHookDeadline(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "claude")
	var first, second, third atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		switch r.URL.Path {
		case "/first":
			first.Add(1)
			time.Sleep(30 * time.Millisecond)
			fmt.Fprint(w, `{"choices":[{"message":{"content":"invalid decision"}}]}`)
		case "/second":
			second.Add(1)
			select {
			case <-r.Context().Done():
			case <-release:
			}
		case "/third":
			third.Add(1)
			fmt.Fprint(w, `{"choices":[{"message":{"content":"{\"decision\":\"allow\",\"risk\":\"safe\",\"reasoning\":\"late fallback\"}"}}]}`)
		}
	}))
	defer server.Close()
	defer close(release)
	cfg := Config{Models: map[string]ModelConfig{}, Judges: JudgeList{{Use: "first"}, {Use: "second"}, {Use: "third"}}}
	for _, name := range []string{"first", "second", "third"} {
		cfg.Models[name] = ModelConfig{URL: server.URL + "/" + name, Model: name, Timeout: 40}
	}
	start := time.Now()
	in := &JudgeInput{Command: "novel-budget-command", Cwd: t.TempDir(), Config: cfg, Harness: GetHarness("claude"), HookStart: start.Add(-hookDecisionBudget + 200*time.Millisecond)}
	v, jerr, done := RunJudges(cfg.JudgeSpecs(), in, nil)
	if v != nil || done || jerr == nil || jerr.Kind != judgeErrBudget {
		t.Fatalf("expected budget exhaustion, got verdict=%+v err=%+v done=%v", v, jerr, done)
	}
	if first.Load() != 1 || second.Load() != 1 || third.Load() != 0 {
		t.Fatalf("fallback restarted deadline or skipped the first judge: hits=%d,%d,%d", first.Load(), second.Load(), third.Load())
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("shared deadline took %v", elapsed)
	}
}

func TestJudgeBudgetIncludesBeforeRemoteLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := &JudgeInput{Context: ctx, HookStart: time.Now(), Config: Config{Models: map[string]ModelConfig{"chat": {URL: "https://must-not-be-called.invalid", Model: "chat"}}}}
	v, jerr, done := RunJudges(in.Config.JudgeSpecs(), in, nil)
	if v != nil || jerr != nil || done {
		t.Fatal("empty chain should remain transparent")
	}
	in.Config.Judges = JudgeList{{Use: "chat"}}
	v, jerr, done = RunJudges(in.Config.JudgeSpecs(), in, func() bool {
		cancel()
		return false
	})
	if v != nil || done || jerr == nil || jerr.Kind != judgeErrBudget {
		t.Fatalf("lookup exhausted the budget; classifier must not start: verdict=%+v err=%+v done=%v", v, jerr, done)
	}
}

func TestModelBackendsHonorParentDeadline(t *testing.T) {
	for _, path := range []string{"/v1/chat/completions", "/v1/systemone"} {
		t.Run(path, func(t *testing.T) {
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			defer server.Close()
			defer close(release)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := CallLLM(LLMConfig{URL: server.URL + path, Model: "test", Timeout: 40, Context: ctx}, "system", "command", 256)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected parent deadline, got %v", err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("provider timeout restarted parent deadline: %v", elapsed)
			}
		})
	}
}

func TestClaudeCLIAndExecJudgeHonorParentDeadline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec /bin/sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Run("claude", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := CallLLM(LLMConfig{URL: "claude-cli", Model: "test", Timeout: 40, Context: ctx}, "system", "command", 256)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
			t.Fatalf("CLI must honor parent deadline: err=%v elapsed=%v", err, time.Since(start))
		}
	})
	t.Run("exec", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, _, allowed := runPreCheckContext(ctx, path, []byte(`{}`)); allowed || time.Since(start) > 2*time.Second {
			t.Fatalf("exec hook must honor parent deadline: allow=%v elapsed=%v", allowed, time.Since(start))
		}
	})
}

func TestEscalationKeepsPrimaryWhenSharedDeadlineExpires(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "claude")
	isolateEscalationEnv(t)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	cfg := Config{Models: map[string]ModelConfig{"big": {URL: server.URL, Model: "big", Timeout: 40}}, Escalation: &EscalationConfig{Model: "big"}}
	SaveConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	d := Decision{Decision: ActionAsk, Risk: RiskModerate, Reasoning: "primary asks"}
	start := time.Now()
	out, cacheOK := maybeEscalateContext(ctx, GetHarness("claude"), cfg, &d, "system", "command", start)
	if !out.Fired || out.Outcome != "error" || out.Err != "timeout" || cacheOK {
		t.Fatalf("expected uncached escalation timeout, got %+v cache=%v", out, cacheOK)
	}
	if d.Decision != ActionAsk || d.Risk != RiskModerate || d.Escalated || time.Since(start) > 2*time.Second {
		t.Fatalf("primary must survive bounded escalation: decision=%+v elapsed=%v", d, time.Since(start))
	}
}

func TestBudgetFallbackCannotPassThroughAsklessAdapter(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_PROFILE", "balanced")
	for _, name := range []string{"claude", "gemini", "codex", "opencode", "cursor"} {
		t.Run(name, func(t *testing.T) {
			// Even a permissive custom critical cell cannot turn exhaustion
			// into an unsupported ask/passthrough on an ask-less adapter.
			SaveConfig(Config{Policy: PolicyConfig{Harness: map[string]HarnessPolicy{name: {RiskMap: map[string]string{RiskCritical: ActionAllow}}}}})
			want := ActionDeny
			if name == "claude" || name == "gemini" {
				want = ActionAsk
			}
			if got := budgetAbstainAction(GetHarness(name)); got != want {
				t.Fatalf("budget outcome for %s: got %s, want %s", name, got, want)
			}
		})
	}
}

func TestHookBudgetNoVerdictEmitsAskAndDoesNotApprove(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "claude")
	t.Setenv("YOLONOT_PROFILE", "balanced")
	modRun = false
	cwd := t.TempDir()
	payload := makePrePayload("budget-output", "novel-budget-command", cwd)
	project := ProjectSessionID(payload.SessionID, cwd)
	out := captureStdout(func() {
		hookNoVerdict(budgetJudgeError(), payload, "novel-budget-command", cwd, payload.SessionID, project)
	})
	response := parseResponse(t, out)
	if response.HookSpecificOutput.PermissionDecision != ActionAsk || !strings.Contains(response.HookSpecificOutput.PermissionDecisionReason, "timeout") {
		t.Fatalf("budget exhaustion must emit an actionable ask, got %s", out)
	}
	if ContainsLine(project, "approved", "novel-budget-command") || !ContainsLine(project, "asked", "novel-budget-command") {
		t.Fatal("budget exhaustion must ask without writing an approval")
	}
}

func TestCheckHonorsHookTimeoutBudgetAndCacheSymlinkGuard(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "claude")

	// 1. cmdCheckIn shares hookBudgetContext (HookTimeout: 1s) across slow judges.
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)

	SaveConfig(Config{
		HookTimeout: 1,
		Models: map[string]ModelConfig{
			"slow": {URL: server.URL, Model: "slow", Timeout: 30},
		},
		Judges: JudgeList{{Use: "slow"}},
	})
	repo := t.TempDir()
	start := time.Now()
	checkOut := captureStdout(func() {
		cmdCheckIn("custom-unmatched-cmd --flag", repo)
	})
	if time.Since(start) > 3*time.Second || !strings.Contains(checkOut, "budget exhausted") {
		t.Fatalf("expected cmdCheckIn to stop at 1s HookTimeout budget, elapsed=%v:\n%s", time.Since(start), checkOut)
	}

	// 2. checkCacheWithScripts refuses symlinked or oversized (>64KB) cache entries,
	// and openReadOnlyNoFollow refuses symlinks.
	scriptPath := filepath.Join(repo, "run.py")
	if err := os.WriteFile(scriptPath, []byte("print('hi')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(repo, "link.py")
	if err := os.Symlink(scriptPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if f, err := openReadOnlyNoFollow(linkPath); err == nil {
		f.Close()
		t.Fatalf("expected openReadOnlyNoFollow to refuse symlink %s", linkPath)
	}

	cmd := "python3 run.py"
	saveCache(cmd, repo, &Decision{Decision: "allow", Risk: RiskLow, Reasoning: "ok"})
	if d := checkCache(cmd, repo); d == nil || d.Decision != "allow" {
		t.Fatalf("expected valid cache hit before tampering, got %+v", d)
	}

	hash := scriptHash(cmd, repo)
	cacheFile := filepath.Join(cacheDir(), hash+".json")
	victim := filepath.Join(t.TempDir(), "forged.json")
	rawCache, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, rawCache, 0600); err != nil {
		t.Fatal(err)
	}
	os.Remove(cacheFile)
	if err := os.Symlink(victim, cacheFile); err != nil {
		t.Fatal(err)
	}
	if d := checkCache(cmd, repo); d != nil {
		t.Fatalf("expected checkCache to refuse symlinked cache entry, got %+v", d)
	}

	os.Remove(cacheFile)
	if err := os.WriteFile(cacheFile, make([]byte, 70*1024), 0600); err != nil {
		t.Fatal(err)
	}
	if d := checkCache(cmd, repo); d != nil {
		t.Fatalf("expected checkCache to refuse oversized (>64KB) cache entry, got %+v", d)
	}

	// 3. EvaluateRulePriority enforces deny > ask > allow and sensitive suppression.
	rules := []Rule{
		{Action: "allow", Type: "cmd", Pattern: "cat *"},
		{Action: "ask", Type: "cmd", Pattern: "cat secret*"},
		{Action: "deny", Type: "cmd", Pattern: "cat secret-prod*"},
	}
	if tr := EvaluateRulePriority("cat secret-prod.txt", rules, []string{"*.txt"}); tr.Match == nil || tr.Match.Action != "deny" {
		t.Fatalf("expected deny to win over ask/allow/sensitive, got %+v", tr)
	}
	if tr := EvaluateRulePriority("cat secret-dev.txt", rules, []string{"*.txt"}); tr.Match == nil || tr.Match.Action != "ask" {
		t.Fatalf("expected ask to win over allow/sensitive, got %+v", tr)
	}
	if tr := EvaluateRulePriority("cat .env", rules, []string{".env"}); tr.Match != nil || tr.AllowCandidate == nil || !tr.Sensitive {
		t.Fatalf("expected sensitive to suppress allow while recording AllowCandidate and Sensitive, got %+v", tr)
	}
}
