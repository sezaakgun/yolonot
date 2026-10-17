package yolonot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func productControlHome(t *testing.T) string {
	t.Helper()
	home, cleanup := withFakeHome(t)
	t.Cleanup(cleanup)
	t.Setenv("YOLONOT_HARNESS", "claude")
	t.Setenv("YOLONOT_DISABLED", "")
	t.Setenv("YOLONOT_MOD", "")
	return home
}

func TestProductNativeApprovalDoesNotWidenOneTimeGrant(t *testing.T) {
	productControlHome(t)
	cwd := t.TempDir()
	command := "review-sensitive-operation"
	if err := os.WriteFile(filepath.Join(cwd, ".yolonot"), []byte("ask-cmd review-sensitive-operation\n"), 0600); err != nil {
		t.Fatal(err)
	}
	payload := productHookInput(t, command, cwd, "native-once")
	out, err := productCLI(t, payload, "hook", "--harness", "claude")
	if err != nil || productPermission(t, out) != ActionAsk {
		t.Fatalf("first ask: %s %v", out, err)
	}
	var post HookPayload
	if err := json.Unmarshal(payload, &post); err != nil {
		t.Fatal(err)
	}
	post.HookEventName = "PostToolUse"
	data, _ := json.Marshal(post)
	if out, err := productCLI(t, data, "hook", "--harness", "claude"); err != nil {
		t.Fatalf("post: %s %v", out, err)
	}
	project := ProjectSessionID("native-once", cwd)
	if ContainsLine(project, "approved", command) || ContainsLine(project, "asked", command) {
		t.Fatal("one-time grant persisted or stale ask survived")
	}
	if got := loadPrecedents(); len(got) != 0 {
		t.Fatalf("one-time grant learned: %+v", got)
	}
	out, err = productCLI(t, payload, "hook", "--harness", "claude")
	if err != nil || productPermission(t, out) != ActionAsk {
		t.Fatalf("repeat must ask again, not allow or infer rejection: %s %v", out, err)
	}
}

func TestProductGeminiRetirementPreservesCleanup(t *testing.T) {
	productControlHome(t)
	out, err := productCLI(t, nil, "install", "--harness", "gemini")
	if err == nil || !bytes.Contains(out, []byte("support has been retired")) {
		t.Fatalf("retired install accepted: %s %v", out, err)
	}
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"yolonot", "install", "--all"}
	for _, h := range resolveInstallTargets("install") {
		if h.Name() == "gemini" {
			t.Fatal("--all installs retired adapter")
		}
	}
	os.Args = []string{"yolonot", "install"}
	for _, h := range resolveInstallTargets("install") {
		if h.Name() == "gemini" {
			t.Fatal("default installs retired adapter")
		}
	}
	os.Args = []string{"yolonot", "uninstall", "--harness", "gemini"}
	targets := resolveInstallTargets("uninstall")
	if len(targets) != 1 || targets[0].Name() != "gemini" {
		t.Fatal("legacy cleanup unavailable")
	}
}

func TestProductSkillPreservesUnmanagedContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "SKILL.md")
	original := []byte("user-maintained skill\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := installHarnessSkill("codex", dir); err == nil {
		t.Fatal("overwrote unmanaged skill")
	}
	if err := uninstallHarnessSkill(dir); err == nil {
		t.Fatal("removed unmanaged skill")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("user skill changed: %q %v", got, err)
	}
}

func TestProductNativeAskPreservesExistingHardDenyFloor(t *testing.T) {
	productControlHome(t)
	t.Setenv("YOLONOT_OPENCODE_API", "2")
	t.Setenv("YOLONOT_CURSOR_NATIVE_ASK", "1")
	for _, name := range []string{"opencode", "cursor"} {
		h := GetHarness(name)
		if raw := h.RiskMap(); raw[RiskModerate] != ActionAsk || raw[RiskHigh] != ActionDeny || raw[RiskCritical] != ActionDeny {
			t.Fatalf("native asks relaxed %s raw defaults: %v", name, raw)
		}
		got := TranslateProfile(GetBuiltinProfile("balanced").Map, h)
		if got[RiskModerate] != ActionAsk || got[RiskHigh] != ActionDeny || got[RiskCritical] != ActionDeny {
			t.Fatalf("native asks relaxed %s hard-deny floor: %v", name, got)
		}
	}
}

func TestProductDoctorProbeKeepsJSONOutputClean(t *testing.T) {
	productControlHome(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"choices":[{"message":{"content":"OK"}}]}`)
	}))
	defer server.Close()
	SaveConfig(Config{Models: map[string]ModelConfig{"chat": {URL: server.URL, Model: "fixture"}}, Judges: JudgeList{{Use: "chat"}}})
	out, _ := productCLI(t, nil, "doctor", "--harness", "claude", "--json", "--probe-models")
	var checks []diagnosticCheck
	if err := json.Unmarshal(out, &checks); err != nil {
		t.Fatalf("probe corrupted JSON output: %s %v", out, err)
	}
}

func productCLI(t *testing.T, input []byte, args ...string) ([]byte, error) {
	t.Helper()
	commandArgs := append([]string{"-test.run=^TestProductControlCLIHelper$", "--"}, args...)
	cmd := exec.Command(os.Args[0], commandArgs...)
	cmd.Env = append(os.Environ(), "YOLONOT_PRODUCT_CONTROL_CHILD=1", "GORACE=atexit_sleep_ms=0")
	cmd.Stdin = bytes.NewReader(input)
	return cmd.CombinedOutput()
}

func TestProductControlCLIHelper(t *testing.T) {
	if os.Getenv("YOLONOT_PRODUCT_CONTROL_CHILD") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"yolonot"}, os.Args[i+1:]...)
			Run()
			os.Exit(0)
		}
	}
	os.Exit(98)
}

func productHookInput(t *testing.T, command, cwd, session string) []byte {
	t.Helper()
	b, err := json.Marshal(HookPayload{HookEventName: "PreToolUse", ToolName: "Bash", SessionID: session, Cwd: cwd, ToolInput: map[string]interface{}{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func productPermission(t *testing.T, out []byte) string {
	t.Helper()
	if len(bytes.TrimSpace(out)) == 0 {
		return ""
	}
	var response HookResponse
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatalf("invalid hook output: %s: %v", out, err)
	}
	return response.HookSpecificOutput.PermissionDecision
}

func TestProductStrictConfigRejectsMalformedAmbiguousAndInvalidPolicy(t *testing.T) {
	productControlHome(t)
	for name, content := range map[string]string{
		"malformed":             `{"judges":[`,
		"trailing":              `{} {}`,
		"non-object":            `[]`,
		"null":                  `null`,
		"unknown field":         `{"quite_on_allow":true}`,
		"duplicate":             `{"judges":["fast_allow"],"judges":[]}`,
		"case alias":            `{"judges":["fast_allow"],"Judges":[]}`,
		"unknown reference":     `{"judges":["missing"]}`,
		"empty exec":            `{"judges":["exec:"]}`,
		"invalid may":           `{"judges":[{"use":"fast_allow","may":["maybe"]}]}`,
		"unknown profile":       `{"policy":{"profile":"missing"}}`,
		"incomplete profile":    `{"policy":{"profiles":{"custom":{"safe":"allow"}}}}`,
		"unknown harness":       `{"policy":{"harness":{"missing":{"profile":"strict"}}}}`,
		"unknown risk tier":     `{"policy":{"harness":{"claude":{"risk_map":{"medium":"allow"}}}}}`,
		"unsafe failure":        `{"failure":{"timeout":"allow"}}`,
		"budget above host":     `{"hook_timeout":60}`,
		"invalid protocol":      `{"models":{"m":{"url":"https://example.test","model":"m","protocol":"magic"}}}`,
		"CLI protocol mismatch": `{"models":{"m":{"url":"claude-cli","model":"m","protocol":"systemone"}}}`,
		"unsafe endpoint":       `{"models":{"m":{"url":"http://example.test","model":"m"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(configPath(), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readConfig(configPath()); err == nil {
				t.Fatalf("invalid configuration accepted: %s", content)
			}
			if after, _ := os.ReadFile(configPath()); string(after) != content {
				t.Fatal("validation rewrote an invalid file")
			}
		})
	}
	if err := os.WriteFile(configPath(), []byte(goldenV0), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := readConfig(configPath())
	if err != nil || !cfg.Legacy || len(cfg.Models) != 3 {
		t.Fatalf("valid legacy config rejected: legacy=%t models=%d err=%v", cfg.Legacy, len(cfg.Models), err)
	}
	if after, _ := os.ReadFile(configPath()); string(after) != goldenV0 {
		t.Fatal("legacy validation must remain read-only")
	}
}

func TestProductInvalidConfigRealHookDeniesBeforeFastAllow(t *testing.T) {
	productControlHome(t)
	cwd := t.TempDir()
	for _, content := range []string{`{"judges":["fast_allow"],"typo":true}`, `{"judges":["fast_allow"],"Judges":[]}`, `{"judges":["missing"]}`} {
		if err := os.WriteFile(configPath(), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		out, err := productCLI(t, productHookInput(t, "git status", cwd, "invalid-config"), "hook", "--harness", "claude")
		if err != nil || productPermission(t, out) != ActionDeny {
			t.Fatalf("invalid config did not deny: %s err=%v", out, err)
		}
		if ContainsLine(ProjectSessionID("invalid-config", cwd), "approved", "git status") {
			t.Fatal("invalid configuration minted an approval")
		}
	}
}

func TestProductConfigurableFailuresExecuteThroughRealHook(t *testing.T) {
	productControlHome(t)
	cwd := t.TempDir()
	for _, kind := range []string{judgeErrUnavailable, judgeErrParse} {
		for _, action := range []string{ActionAsk, ActionDeny, ActionPassthrough} {
			for _, harness := range []string{"claude", "codex"} {
				t.Run(kind+"/"+action+"/"+harness, func(t *testing.T) {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if kind == judgeErrUnavailable {
							w.WriteHeader(http.StatusServiceUnavailable)
							fmt.Fprint(w, `{"error":"fixture unavailable"}`)
							return
						}
						json.NewEncoder(w).Encode(map[string]interface{}{"choices": []interface{}{map[string]interface{}{"message": map[string]string{"content": "not a verdict"}}}})
					}))
					defer server.Close()
					cfg := Config{Models: map[string]ModelConfig{"chat": {URL: server.URL, Model: "fixture", Protocol: "chat"}}, Judges: JudgeList{{Use: "chat"}}}
					if kind == judgeErrUnavailable {
						cfg.Failure.Unavailable = action
					} else {
						cfg.Failure.Parse = action
					}
					if err := SaveConfig(cfg); err != nil {
						t.Fatal(err)
					}
					out, err := productCLI(t, productHookInput(t, "review-product-command", cwd, ""), "hook", "--harness", harness)
					if err != nil {
						t.Fatalf("hook failed: %s %v", out, err)
					}
					want := action
					if action == ActionPassthrough {
						want = ""
					} else if action == ActionAsk && harness == "codex" {
						want = ActionDeny
					}
					if got := productPermission(t, out); got != want {
						t.Fatalf("failure policy got %q want %q: %s", got, want, out)
					}
				})
			}
		}
	}
}

func TestProductDefaultOversizeCannotBecomeAllowOnAsklessHarness(t *testing.T) {
	productControlHome(t)
	cwd := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("oversized prompt reached the model")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	profile := map[string]string{}
	for _, tier := range allRiskTiers {
		profile[tier] = ActionAllow
	}
	cfg := Config{Models: map[string]ModelConfig{"chat": {URL: server.URL, Model: "fixture"}}, Judges: JudgeList{{Use: "chat"}},
		Policy: PolicyConfig{Profile: "permissive", Profiles: map[string]map[string]string{"permissive": profile}}}
	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	command := strings.Repeat("x", maxClassifierPromptBytes+1)
	out, err := productCLI(t, productHookInput(t, command, cwd, ""), "hook", "--harness", "opencode")
	if err != nil || productPermission(t, out) != ActionDeny {
		t.Fatalf("unjudged oversized command was not blocked on ask-less host: %s %v", out, err)
	}
}

func TestProductConfiguredHookBudgetStopsPendingModel(t *testing.T) {
	productControlHome(t)
	cwd := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer server.Close()
	cfg := Config{Models: map[string]ModelConfig{"chat": {URL: server.URL, Model: "fixture", Timeout: 30}}, Judges: JudgeList{{Use: "chat"}}, HookTimeout: 1,
		Failure: FailurePolicy{Timeout: ActionDeny}}
	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	out, err := productCLI(t, productHookInput(t, "pending-product-command", cwd, ""), "hook", "--harness", "claude")
	if err != nil || productPermission(t, out) != ActionDeny {
		t.Fatalf("deadline did not produce configured denial: %s %v", out, err)
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("1-second shared budget restarted provider timeout: %s", elapsed)
	}
}

func TestProductDiagnosticsHonorExplicitHarness(t *testing.T) {
	productControlHome(t)
	out, err := productCLI(t, nil, "effective", "--harness", "codex", "--json")
	if err != nil {
		t.Fatalf("effective failed: %s %v", out, err)
	}
	var state effectiveState
	if err := json.Unmarshal(out, &state); err != nil || state.Harness != "codex" {
		t.Fatalf("effective ignored explicit harness: %s %v", out, err)
	}
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"yolonot", "doctor", "--harness", "cursor"}
	targets := diagnosticHarnesses(os.Args[2:])
	if len(targets) != 1 || targets[0].Name() != "cursor" {
		t.Fatalf("doctor ignored explicit target: %+v", targets)
	}
}

func TestProductManualDecisionsScopeProjectsAndStoreMultilineAtomically(t *testing.T) {
	productControlHome(t)
	a, b := t.TempDir(), t.TempDir()
	const sid = "manual-controls"
	command := "printf 'first'\nprintf 'second'"
	if err := sessionDecision("approve", command, sid, a); err != nil {
		t.Fatal(err)
	}
	keyA, keyB := ProjectSessionID(sid, a), ProjectSessionID(sid, b)
	if got := ReadLines(keyA, "approved"); !reflect.DeepEqual(got, []string{command}) {
		t.Fatalf("multiline approval split into records: %#v", got)
	}
	for _, partial := range strings.Split(command, "\n") {
		if MatchesLineOrWrappedVariant(keyA, "approved", partial) {
			t.Fatalf("multiline approval authorized a partial command: %q", partial)
		}
	}
	if raw, _ := os.ReadFile(sessionPath(keyA, "approved")); bytes.Count(raw, []byte("\n")) != 1 {
		t.Fatalf("multiline command must occupy one physical record: %q", raw)
	}
	if ContainsLine(keyB, "approved", command) {
		t.Fatal("manual approval crossed project boundary")
	}
	if err := sessionDecision("approve", command, sid, b); err != nil {
		t.Fatal(err)
	}
	if err := sessionDecision("deny", command, sid, a); err != nil {
		t.Fatal(err)
	}
	if ContainsLine(keyA, "approved", command) || !ContainsLine(keyA, "denied", command) || !ContainsLine(keyB, "approved", command) {
		t.Fatal("manual denial did not replace only its project's approval")
	}
	modAppend(sid, modEntry{ID: "a", Cwd: a, Command: command, Decision: ActionAllow})
	modAppend(sid, modEntry{ID: "b", Cwd: b, Command: command, Decision: ActionAllow})
	if err := sessionDecision("reset", "", sid, a); err != nil {
		t.Fatal(err)
	}
	if len(ReadLines(keyA, "denied")) != 0 || !ContainsLine(keyB, "approved", command) || modLookup(sid, "a") != nil || modLookup(sid, "b") == nil {
		t.Fatal("reset failed to isolate project state/replay")
	}
}

func TestProductManualApprovalCannotOverrideDenyRule(t *testing.T) {
	productControlHome(t)
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(YolonotDir(), "rules"), []byte("deny-cmd blocked-command\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := sessionDecision("approve", "blocked-command", "manual-rule", cwd); err != nil {
		t.Fatal(err)
	}
	out, err := productCLI(t, productHookInput(t, "blocked-command", cwd, "manual-rule"), "hook", "--harness", "claude")
	if err != nil || productPermission(t, out) != ActionDeny {
		t.Fatalf("manual approval overrode hard deny: %s %v", out, err)
	}
}

func TestProductManualRelativeCwdMatchesHookScope(t *testing.T) {
	productControlHome(t)
	t.Chdir(t.TempDir())
	want, _ := os.Getwd()
	canonical, _ := filepath.EvalSymlinks(want)
	command, sid, cwd, err := sessionCommandArgs([]string{"example", "--session-id", "relative-cwd", "--cwd", "."})
	if err != nil || cwd != canonical {
		t.Fatalf("relative working directory not normalized: cwd=%q want=%q err=%v", cwd, canonical, err)
	}
	if err := sessionDecision("approve", command, sid, cwd); err != nil {
		t.Fatal(err)
	}
	if !ContainsLine(ProjectSessionID(sid, want), "approved", "example") {
		t.Fatal("relative manual approval missed actual hook project")
	}
}

func TestProductLearningOptOutSurvivesRebuildAndForget(t *testing.T) {
	productControlHome(t)
	cwd := t.TempDir()
	log := func(command string) {
		LogDecision(DecisionEntry{Layer: "human", Source: "ask_approved", Decision: ActionAllow, Cwd: cwd, Command: command})
	}
	log("remember-before")
	off := false
	if err := SaveConfig(Config{Learning: LearningConfig{Enabled: &off}}); err != nil {
		t.Fatal(err)
	}
	log("private-while-off")
	if got := loadPrecedents(); len(got) != 0 {
		t.Fatalf("disabled learning still supplied hints: %+v", got)
	}
	on := true
	if err := SaveConfig(Config{Learning: LearningConfig{Enabled: &on}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(precedentsPath()); err != nil {
		t.Fatal(err)
	}
	if rebuilt := loadPrecedents(); len(rebuilt) != 1 || rebuilt[0].Command != "remember-before" {
		t.Fatalf("rebuild resurrected disabled learning: %+v", rebuilt)
	}
	t.Chdir(cwd)
	captureStdout(func() { cmdLearning([]string{"forget", "remember-before"}) })
	if got := loadPrecedents(); len(got) != 0 {
		t.Fatalf("forget did not remove/rebuild-proof the answer: %+v", got)
	}
}

func TestProductLearningRetentionAndForgetAreProjectScoped(t *testing.T) {
	productControlHome(t)
	a, b := t.TempDir(), t.TempDir()
	now := time.Now().UTC()
	records := []precedent{
		{Ts: now.Add(-30 * 24 * time.Hour).Format(time.RFC3339Nano), Cwd: a, Command: "old", Decision: ActionAllow},
		{Ts: now.Add(-time.Hour).Format(time.RFC3339Nano), Cwd: a, Command: "same-command", Decision: ActionAllow},
		{Ts: now.Add(-30 * time.Minute).Format(time.RFC3339Nano), Cwd: b, Command: "same-command", Decision: ActionDeny},
	}
	if err := writePrecedents(records); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfig(Config{Learning: LearningConfig{RetentionDays: 7, MaxEntries: 2}}); err != nil {
		t.Fatal(err)
	}
	if got := loadPrecedents(); len(got) != 2 || got[0].Command == "old" {
		t.Fatalf("retention/cap not applied: %+v", got)
	}
	t.Chdir(a)
	captureStdout(func() { cmdLearning([]string{"forget", "same-command"}) })
	if got := loadPrecedents(); len(got) != 1 || got[0].Cwd != b {
		t.Fatalf("forget crossed project boundary: %+v", got)
	}
}

func TestProductCacheInvalidatesModelAndPromptChanges(t *testing.T) {
	productControlHome(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	if err := os.WriteFile(filepath.Join(cwd, "review.sh"), []byte("echo cache-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Models: map[string]ModelConfig{"chat": {URL: "https://example.test/v1/chat/completions", Model: "first"}}, Judges: JudgeList{{Use: "chat"}}}
	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	const command = "bash review.sh"
	saveCache(command, cwd, &Decision{Decision: ActionAllow, Risk: RiskSafe})
	if checkCache(command, cwd) == nil {
		t.Fatal("unchanged context did not reuse its cached verdict")
	}
	m := cfg.Models["chat"]
	m.Model = "second"
	cfg.Models["chat"] = m
	SaveConfig(cfg)
	if checkCache(command, cwd) != nil {
		t.Fatal("cached verdict survived deciding-model change")
	}
	m.Model = "first"
	cfg.Models["chat"] = m
	SaveConfig(cfg)
	if checkCache(command, cwd) == nil {
		t.Fatal("restoring unchanged model did not restore cache validity")
	}
	cfg.Prompt.AskHints = []string{"ask for every script"}
	SaveConfig(cfg)
	if checkCache(command, cwd) != nil {
		t.Fatal("cached verdict survived prompt policy change")
	}
}

func TestProductExplicitProtocolsUseCustomEndpointContract(t *testing.T) {
	for _, protocol := range []string{"chat", "anthropic", "systemone", "decisions", "workers-ai"} {
		t.Run(protocol, func(t *testing.T) {
			var received map[string]interface{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewDecoder(r.Body).Decode(&received)
				switch protocol {
				case "chat":
					json.NewEncoder(w).Encode(map[string]interface{}{"choices": []interface{}{map[string]interface{}{"message": map[string]string{"content": `{"decision":"allow","risk":"safe"}`}}}})
				case "anthropic":
					json.NewEncoder(w).Encode(map[string]interface{}{"content": []interface{}{map[string]string{"type": "text", "text": `{"decision":"allow","risk":"safe"}`}}})
				case "workers-ai":
					json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "result": securityTypedFixture(false)})
				default:
					json.NewEncoder(w).Encode(securityTypedFixture(protocol == "decisions"))
				}
			}))
			defer server.Close()
			cfg := LLMConfig{URL: server.URL + "/private-classifier", Model: "fixture", Protocol: protocol}
			text, err := CallLLM(cfg, "system fixture", "command fixture", 100)
			if err != nil || ParseDecision(text) == nil {
				t.Fatalf("explicit %s custom endpoint failed: %s %v", protocol, text, err)
			}
			switch protocol {
			case "chat":
				if received["messages"] == nil || received["system"] != nil || received["questions"] != nil {
					t.Fatalf("chat body used wrong protocol: %#v", received)
				}
			case "anthropic":
				if received["system"] != "system fixture" || received["messages"] == nil {
					t.Fatalf("Anthropic body used wrong protocol: %#v", received)
				}
			case "decisions":
				if received["input"] != "command fixture" || received["state"] != nil {
					t.Fatalf("Decisions body inferred URL instead of explicit protocol: %#v", received)
				}
			default:
				if received["state"] != "command fixture" || received["questions"] == nil || received["messages"] != nil {
					t.Fatalf("typed body inferred URL instead of explicit protocol: %#v", received)
				}
			}
		})
	}
}

func TestSessionCommandArgsRejectsUnquotedWords(t *testing.T) {
	if _, _, _, err := sessionCommandArgs([]string{"echo", "a; rm -rf build", "--session-id", "s"}); err == nil {
		t.Fatal("split words were joined into a broader command")
	}
	command, _, _, err := sessionCommandArgs([]string{"echo \"a; rm -rf build\"", "--session-id", "s"})
	if err != nil || command != `echo "a; rm -rf build"` {
		t.Fatalf("quoted command: %q %v", command, err)
	}
}

func TestLearningSubcommandsRejectStrayWords(t *testing.T) {
	productControlHome(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"learning", "forget", "rm", "-rf", "build"}, "one quoted argument"},
		{[]string{"learning", "clear", "--all", "now"}, "Usage: yolonot learning clear"},
		{[]string{"learning", "prune", "foo"}, "Usage: yolonot learning prune"},
	} {
		out, err := productCLI(t, nil, c.args...)
		if err == nil || !strings.Contains(string(out), c.want) {
			t.Errorf("%v: err=%v out=%s", c.args, err, out)
		}
	}
}

func harnessHookCall(t *testing.T, harness, command, cwd, session string) (decision string, raw string) {
	t.Helper()
	var payload []byte
	args := []string{"hook", "--harness", harness}
	switch harness {
	case "antigravity":
		args = append(args, "--phase", "pre")
		payload, _ = json.Marshal(map[string]interface{}{
			"conversationId": session,
			"toolCall": map[string]interface{}{
				"name": "run_command",
				"args": map[string]interface{}{"CommandLine": command, "Cwd": cwd},
			},
		})
	case "cursor":
		payload, _ = json.Marshal(map[string]interface{}{
			"conversation_id": session,
			"hook_event_name": "beforeShellExecution",
			"command":         command,
			"cwd":             cwd,
		})
	case "codex":
		payload, _ = json.Marshal(map[string]interface{}{
			"hook_event_name": "PermissionRequest",
			"tool_name":       "Bash",
			"session_id":      session,
			"cwd":             cwd,
			"tool_input":      map[string]interface{}{"command": command},
		})
	default: // claude, opencode
		payload = productHookInput(t, command, cwd, session)
	}
	out, err := productCLI(t, payload, args...)
	if err != nil {
		t.Fatalf("%s hook failed: %s (%v)", harness, out, err)
	}
	raw = strings.TrimSpace(string(out))
	if raw == "" {
		return "", raw
	}
	var m map[string]interface{}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("%s invalid json: %s (%v)", harness, raw, err)
	}
	switch harness {
	case "antigravity":
		decision, _ = m["decision"].(string)
	case "cursor":
		decision, _ = m["permission"].(string)
	case "codex":
		if hso, ok := m["hookSpecificOutput"].(map[string]interface{}); ok {
			if dec, ok := hso["decision"].(map[string]interface{}); ok {
				decision, _ = dec["behavior"].(string)
			}
		}
	default: // claude, opencode
		decision = productPermission(t, out)
	}
	return decision, raw
}

func TestCrossHarnessBugFixesEndToEnd(t *testing.T) {
	harnesses := []struct {
		name      string
		wantAllow string
	}{
		{"claude", "allow"},
		{"codex", "allow"},
		{"opencode", "allow"},
		{"antigravity", "auto_approve"},
		{"cursor", "allow"},
	}

	for _, h := range harnesses {
		t.Run(h.name, func(t *testing.T) {
			home := productControlHome(t)
			workDir := filepath.Join(home, "work")
			mainRepo := filepath.Join(workDir, "main")
			os.MkdirAll(filepath.Join(mainRepo, ".git", "worktrees", "wt1"), 0755)
			os.WriteFile(filepath.Join(workDir, ".yolonot"), []byte(`context "HOME-PARENT-CONTEXT"`+"\n"), 0644)
			os.WriteFile(filepath.Join(mainRepo, ".yolonot"), []byte(`allow-hint "MAIN-REPO-HINT"`+"\n"), 0644)

			wt1 := filepath.Join(t.TempDir(), "wt1")
			os.MkdirAll(filepath.Join(wt1, "scripts"), 0755)
			os.WriteFile(filepath.Join(wt1, ".git"), []byte("gitdir: "+filepath.Join(mainRepo, ".git", "worktrees", "wt1")+"\n"), 0644)
			os.WriteFile(filepath.Join(wt1, "scripts", "gate.sh"), []byte("echo WT-GATE-BODY-MARKER\n"), 0755)

			var primaryCalls, escCalls int
			var lastSys, lastUser string
			primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				primaryCalls++
				var body struct {
					Messages []struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"messages"`
				}
				json.NewDecoder(r.Body).Decode(&body)
				for _, m := range body.Messages {
					if m.Role == "system" {
						lastSys = m.Content
					} else if m.Role == "user" {
						lastUser = m.Content
					}
				}
				json.NewEncoder(w).Encode(map[string]interface{}{
					"choices": []map[string]interface{}{
						{"message": map[string]string{"content": `{"decision":"ask","risk":"moderate","reasoning":"primary unsure"}`}},
					},
				})
			}))
			defer primarySrv.Close()

			escSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				escCalls++
				json.NewEncoder(w).Encode(map[string]interface{}{
					"choices": []map[string]interface{}{
						{"message": map[string]string{"content": `{"decision":"allow","risk":"moderate","reasoning":"escalation rescued moderate"}`}},
					},
				})
			}))
			defer escSrv.Close()

			// 1. Under fast profile (moderate -> allow), primary ask/moderate escalates and is rescued by allow/moderate.
			cfg := Config{
				Models: map[string]ModelConfig{
					"primary": {URL: primarySrv.URL, Model: "small", Protocol: "chat"},
					"esc":     {URL: escSrv.URL, Model: "big", Protocol: "chat"},
				},
				Judges:     JudgeList{{Use: "primary"}},
				Escalation: &EscalationConfig{Model: "esc"},
				Policy:     PolicyConfig{Profile: "fast"},
			}
			if err := SaveConfig(cfg); err != nil {
				t.Fatal(err)
			}

			cmd1 := "chmod +x ./scripts/gate.sh && ./scripts/gate.sh"
			dec1, raw1 := harnessHookCall(t, h.name, cmd1, wt1, "sess-esc-"+h.name)
			if dec1 != h.wantAllow {
				t.Fatalf("%s escalation rescue: got decision=%q (raw=%s), want %q", h.name, dec1, raw1, h.wantAllow)
			}
			if primaryCalls != 1 || escCalls != 1 {
				t.Fatalf("%s expected 1 primary and 1 escalation call, got primary=%d esc=%d", h.name, primaryCalls, escCalls)
			}
			if !strings.Contains(lastSys, "MAIN-REPO-HINT") || !strings.Contains(lastSys, "HOME-PARENT-CONTEXT") {
				t.Errorf("%s system prompt missing worktree/home-parent walkup hints:\n%s", h.name, lastSys)
			}
			if !strings.Contains(lastUser, "WT-GATE-BODY-MARKER") {
				t.Errorf("%s user prompt missing attached script body after chmod:\n%s", h.name, lastUser)
			}

			// 2. With force_allow on moderate, primary ask/moderate is overridden to allow directly without escalation.
			cfg.Policy.Harness = map[string]HarnessPolicy{
				h.name: {RiskMap: map[string]string{RiskModerate: ActionForceAllow}},
			}
			if err := SaveConfig(cfg); err != nil {
				t.Fatal(err)
			}
			cmd2 := "git status && ./scripts/gate.sh --second"
			dec2, raw2 := harnessHookCall(t, h.name, cmd2, wt1, "sess-force-"+h.name)
			if dec2 != h.wantAllow {
				t.Fatalf("%s force_allow: got decision=%q (raw=%s), want %q", h.name, dec2, raw2, h.wantAllow)
			}
			if escCalls != 1 {
				t.Errorf("%s force_allow should not trigger escalation, escCalls=%d", h.name, escCalls)
			}
		})
	}
}

