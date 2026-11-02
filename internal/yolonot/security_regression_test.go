package yolonot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type securityDecisionTransport func(*http.Request) (*http.Response, error)

func (f securityDecisionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func securityTypedFixture(openai bool) map[string]interface{} {
	if openai {
		answers := []interface{}{map[string]interface{}{"name": "risk", "type": "choice", "choice": RiskSafe, "confidence": 0.99}}
		for _, condition := range decisionAskConditions {
			answers = append(answers, map[string]interface{}{"name": condition.id, "type": "predicate", "probability": 0.0})
		}
		return map[string]interface{}{"answers": answers}
	}
	answers := map[string]interface{}{"risk": map[string]interface{}{"type": "choice", "choice": RiskSafe, "confidence": 0.99}}
	for _, condition := range decisionAskConditions {
		answers[condition.id] = map[string]interface{}{"type": "noul", "noul": 0.0}
	}
	return map[string]interface{}{"answers": answers}
}

func securityTypedCall(t *testing.T, fixture interface{}, openai bool, status int) (string, error) {
	t.Helper()
	body, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	old := http.DefaultTransport
	http.DefaultTransport = securityDecisionTransport(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = old })
	endpoint := "https://typed-test.invalid/systemone"
	if openai {
		endpoint = "https://typed-test.invalid/decisions"
	}
	return callDecision(LLMConfig{URL: endpoint, Model: "fixture"}, "Command: ls")
}

func TestSecurityTypedAnswersValidatePresenceTypeAndRange(t *testing.T) {
	for _, openai := range []bool{false, true} {
		for _, test := range []string{"valid_zero", "missing_answer", "null_answer", "missing_probability", "null_probability", "negative_probability", "above_one_probability", "string_probability", "wrong_type", "wrong_risk_type", "null_confidence", "invalid_confidence"} {
			t.Run(fmt.Sprintf("openai=%t/%s", openai, test), func(t *testing.T) {
				fixture := securityTypedFixture(openai)
				var answer, risk map[string]interface{}
				key := "noul"
				if openai {
					answers := fixture["answers"].([]interface{})
					risk = answers[0].(map[string]interface{})
					answer = answers[1].(map[string]interface{})
					key = "probability"
					if test == "missing_answer" {
						fixture["answers"] = append(answers[:1], answers[2:]...)
					}
					if test == "null_answer" {
						answers[1] = nil
					}
				} else {
					answers := fixture["answers"].(map[string]interface{})
					risk = answers["risk"].(map[string]interface{})
					answer = answers[decisionAskConditions[0].id].(map[string]interface{})
					if test == "missing_answer" {
						delete(answers, decisionAskConditions[0].id)
					}
					if test == "null_answer" {
						answers[decisionAskConditions[0].id] = nil
					}
				}
				switch test {
				case "missing_probability":
					delete(answer, key)
				case "null_probability":
					answer[key] = nil
				case "negative_probability":
					answer[key] = -0.1
				case "above_one_probability":
					answer[key] = 1.1
				case "string_probability":
					answer[key] = "0.0"
				case "wrong_type":
					answer["type"] = "choice"
				case "wrong_risk_type":
					risk["type"] = "predicate"
				case "null_confidence":
					risk["confidence"] = nil
				case "invalid_confidence":
					risk["confidence"] = -0.1
				}
				raw, err := securityTypedCall(t, fixture, openai, http.StatusOK)
				if test == "valid_zero" {
					if err != nil || ParseDecision(raw) == nil || ParseDecision(raw).Decision != "allow" {
						t.Fatalf("valid zero should allow: %s %v", raw, err)
					}
				} else if err == nil {
					t.Fatalf("invalid answer accepted: %s", raw)
				}
			})
		}
	}
}

func TestSecurityTypedRejectsNonSuccessHTTPWithAnswerBody(t *testing.T) {
	for _, openai := range []bool{false, true} {
		for _, status := range []int{400, 401, 429, 500} {
			t.Run(fmt.Sprintf("openai=%t/status=%d", openai, status), func(t *testing.T) {
				if raw, err := securityTypedCall(t, securityTypedFixture(openai), openai, status); err == nil {
					t.Fatalf("non-success HTTP accepted: %s", raw)
				}
			})
		}
	}
}

func TestSecurityTypedRejectsAmbiguousAnswerFields(t *testing.T) {
	for _, openai := range []bool{false, true} {
		for _, test := range []string{"duplicate_probability", "case_alias_probability", "null_risk_probabilities", "duplicate_answers"} {
			t.Run(fmt.Sprintf("openai=%t/%s", openai, test), func(t *testing.T) {
				fixture := securityTypedFixture(openai)
				if test == "null_risk_probabilities" {
					if openai {
						fixture["answers"].([]interface{})[0].(map[string]interface{})["probabilities"] = nil
					} else {
						fixture["answers"].(map[string]interface{})["risk"].(map[string]interface{})["probabilities"] = nil
					}
				}
				raw, err := json.Marshal(fixture)
				if err != nil {
					t.Fatal(err)
				}
				body := string(raw)
				key, alias := "noul", "Noul"
				if openai {
					key, alias = "probability", "Probability"
				}
				switch test {
				case "duplicate_probability":
					body = strings.Replace(body, `"`+key+`":0`, `"`+key+`":0.9,"`+key+`":0`, 1)
				case "case_alias_probability":
					body = strings.Replace(body, `"`+key+`":0`, `"`+key+`":0.9,"`+alias+`":-1`, 1)
				case "duplicate_answers":
					if openai {
						body = strings.Replace(body, `{"answers":[`, `{"answers":[{"name":"risk","type":"choice","choice":"safe"},`, 1)
					} else {
						body = strings.Replace(body, `{"answers":{`, `{"answers":{"risk":{"type":"choice","choice":"safe"},`, 1)
					}
				}
				if result, err := securityTypedCall(t, json.RawMessage(body), openai, 200); err == nil {
					t.Fatalf("ambiguous response accepted: %s", result)
				}
			})
		}
	}
}

func TestSecurityLegacyEscalationTimeoutInheritance(t *testing.T) {
	for _, timeout := range []int{0, 2} {
		cfg := Config{Provider: ProviderConfig{URL: "https://chat.invalid", Model: "small", Timeout: 30}, Escalation: &EscalationConfig{Provider: ProviderConfig{Model: "large", Timeout: timeout}}}
		cfg.normalize()
		want := timeout
		if want == 0 {
			want = 30
		}
		if got := cfg.Models[cfg.Escalation.Model].Timeout; got != want {
			t.Fatalf("explicit=%d normalized=%d want=%d", timeout, got, want)
		}
		cfg.normalize()
		if cfg.Models[cfg.Escalation.Model].Timeout != want {
			t.Fatal("second normalization changed timeout")
		}
	}
}

func TestSecurityModelNamesCannotShadowExecOrTimeout(t *testing.T) {
	for _, name := range []string{"exec:model", "exec:", "timeout"} {
		if ValidModelName(name) == nil {
			t.Errorf("reserved model name accepted: %q", name)
		}
		key := modelKey(ModelConfig{Model: name})
		if ValidModelName(key) != nil {
			t.Errorf("derived catalog key still reserved: %q", key)
		}
	}
	if err := ValidModelName("gemma4:e4b"); err != nil {
		t.Fatal(err)
	}
}

func securityHookHome(t *testing.T) string {
	t.Helper()
	home, cleanup := withFakeHome(t)
	t.Cleanup(cleanup)
	t.Setenv("YOLONOT_HARNESS", "claude")
	t.Setenv("YOLONOT_DISABLED", "")
	t.Setenv("YOLONOT_MOD", "")
	t.Setenv("YOLONOT_PROFILE", "")
	t.Setenv("YOLONOT_CLAUDE_PROFILE", "")
	t.Cleanup(func() {
		modRun, modSessionID, modToolUseID, modCommand, modCwd, modBinding = false, "", "", "", "", ""
		modApprovalHashes = nil
	})
	return home
}

func TestSecurityReplayCurrentDenyWins(t *testing.T) {
	home := securityHookHome(t)
	command, cwd := "review-replay-command", t.TempDir()
	payload := makePrePayload("replay-deny", command, cwd)
	payload.ToolUseID = "same-tool"
	runModResolve(t, modResolve{SessionID: payload.SessionID, ToolUseID: payload.ToolUseID, Command: command, Cwd: cwd, Verdict: "allow-once"})
	if got := parseResponse(t, runHookWithStruct(t, payload)).HookSpecificOutput.PermissionDecision; got != "allow" {
		t.Fatalf("unchanged replay=%s", got)
	}
	writeGlobalRules(t, home, "deny-cmd review-replay-command\n")
	if got := parseResponse(t, runHookWithStruct(t, payload)).HookSpecificOutput.PermissionDecision; got != "deny" {
		t.Fatalf("new deny must override prior replay: %s", got)
	}
}

func TestSecurityRewrittenToolIDUsesCurrentPipeline(t *testing.T) {
	home := securityHookHome(t)
	cwd, original := t.TempDir(), "review-original-command"
	payload := makePrePayload("replay-rewrite", original, cwd)
	payload.ToolUseID = "preserved-tool-id"
	runModResolve(t, modResolve{SessionID: payload.SessionID, ToolUseID: payload.ToolUseID, Command: original, Cwd: cwd, Verdict: "allow-once"})
	writeGlobalRules(t, home, "ask-cmd review-rewritten-command\n")
	payload.ToolInput = map[string]interface{}{"command": "review-rewritten-command"}
	if got := parseResponse(t, runHookWithStruct(t, payload)).HookSpecificOutput.PermissionDecision; got != "ask" {
		t.Fatalf("rewritten command reused original allow instead of current ask rule: %s", got)
	}
}

func TestSecurityNewAllowOverridesModRejection(t *testing.T) {
	home := securityHookHome(t)
	cwd, command := t.TempDir(), "review-explicit-allow"
	payload := makePrePayload("replay-new-allow", command, cwd)
	payload.ToolUseID = "same-tool"
	runModResolve(t, modResolve{SessionID: payload.SessionID, ToolUseID: payload.ToolUseID, Command: command, Cwd: cwd, Verdict: "deny"})
	writeGlobalRules(t, home, "allow-cmd review-explicit-allow\n")
	if got := parseResponse(t, runHookWithStruct(t, payload)).HookSpecificOutput.PermissionDecision; got != "allow" {
		t.Fatalf("new allow failed to override mod rejection: %s", got)
	}
}

func TestSecurityReplayBindsCommandCwdAndScriptSnapshot(t *testing.T) {
	securityHookHome(t)
	root := t.TempDir()
	script := filepath.Join(root, "run.sh")
	if err := os.WriteFile(script, []byte("echo before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := "bash ./run.sh"
	runModResolve(t, modResolve{SessionID: "replay-binding", ToolUseID: "tool", Command: command, Cwd: root, Verdict: "allow-once"})
	if modLookupBound("replay-binding", "tool", command, root) == nil {
		t.Fatal("unchanged snapshot must replay")
	}
	if modLookupBound("replay-binding", "tool", "bash ./other.sh", root) != nil {
		t.Fatal("rewritten command replayed")
	}
	if modLookupBound("replay-binding", "tool", command, t.TempDir()) != nil {
		t.Fatal("changed cwd replayed")
	}
	if err := os.WriteFile(script, []byte("echo after\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if modLookupBound("replay-binding", "tool", command, root) != nil {
		t.Fatal("edited script replayed")
	}
	modAppend("replay-binding", modEntry{ID: "legacy", Decision: "allow"})
	if modLookupBound("replay-binding", "legacy", command, root) != nil {
		t.Fatal("unbound legacy record replayed")
	}
}

func TestSecurityHumanResolvePreservesOriginalScriptSnapshot(t *testing.T) {
	home := securityHookHome(t)
	root := t.TempDir()
	script := filepath.Join(root, "run.sh")
	os.WriteFile(script, []byte("echo original\n"), 0600)
	command := "bash ./run.sh"
	writeGlobalRules(t, home, "ask-cmd bash *\n")
	payload := makePrePayload("dialog-edit", command, root)
	payload.ToolUseID = "tool"
	t.Setenv("YOLONOT_MOD", "1")
	if got := parseResponse(t, runHookWithStruct(t, payload)).HookSpecificOutput.PermissionDecision; got != "ask" {
		t.Fatal(got)
	}
	os.WriteFile(script, []byte("echo changed-during-dialog\n"), 0600)
	runModResolve(t, modResolve{SessionID: payload.SessionID, ToolUseID: payload.ToolUseID, Command: command, Cwd: root, Verdict: "allow-once"})
	if modLookupBound(payload.SessionID, payload.ToolUseID, command, root) != nil {
		t.Fatal("answer silently approved edited script")
	}
}

func TestSecurityReplayBindsAdoptedClassifierSnapshot(t *testing.T) {
	for _, escalation := range []bool{false, true} {
		t.Run(fmt.Sprintf("escalation=%t", escalation), func(t *testing.T) {
			securityHookHome(t)
			t.Setenv("YOLONOT_MOD", "1")
			t.Setenv("YOLONOT_ESCALATION", "")
			root := t.TempDir()
			script := filepath.Join(root, "run.sh")
			before, classified := []byte("echo initial-snapshot-A\n"), []byte("echo classified-snapshot-B\n")
			if err := os.WriteFile(script, before, 0600); err != nil {
				t.Fatal(err)
			}
			// A real abstaining exec judge edits the script between hook entry
			// and classifier collection, without sleeps or timing assumptions.
			mutator := filepath.Join(root, "mutator.sh")
			quotedPath := "'" + strings.ReplaceAll(script, "'", "'\\''") + "'"
			if err := os.WriteFile(mutator, []byte("#!/bin/sh\nprintf 'echo classified-snapshot-B\\n' > "+quotedPath+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			cfg := Config{Models: map[string]ModelConfig{"primary": {URL: "https://snapshot.invalid/primary", Model: "primary"}}, Judges: JudgeList{{Use: "exec:" + mutator}, {Use: "primary"}}}
			if escalation {
				cfg.Models["larger"] = ModelConfig{URL: "https://snapshot.invalid/larger", Model: "larger"}
				cfg.Escalation = &EscalationConfig{Model: "larger"}
			}
			SaveConfig(cfg)
			calls := 0
			oldTransport := http.DefaultTransport
			http.DefaultTransport = securityDecisionTransport(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				if !strings.Contains(string(body), "classified-snapshot-B") || strings.Contains(string(body), "initial-snapshot-A") {
					t.Errorf("model received wrong script snapshot: %s", body)
				}
				calls++
				if escalation && req.URL.Path == "/primary" {
					// Escalation must keep the primary prompt, even after files
					// change while the primary is being classified.
					if err := os.WriteFile(script, []byte("echo changed-during-primary-C\n"), 0600); err != nil {
						return nil, err
					}
				}
				response := `{"choices":[{"message":{"content":"{\"decision\":\"ask\",\"risk\":\"moderate\",\"reasoning\":\"snapshot review\"}"}}]}`
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(response)), Request: req}, nil
			})
			t.Cleanup(func() { http.DefaultTransport = oldTransport })
			payload := makePrePayload("classifier-snapshot", "bash ./run.sh", root)
			payload.ToolUseID = "snapshot-tool"
			if got := parseResponse(t, runHookWithStruct(t, payload)).HookSpecificOutput.PermissionDecision; got != "ask" {
				t.Fatal(got)
			}
			wantCalls := 1
			if escalation {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("model calls=%d want=%d", calls, wantCalls)
			}
			runModResolve(t, modResolve{SessionID: payload.SessionID, ToolUseID: payload.ToolUseID, Command: "bash ./run.sh", Cwd: root, Verdict: "allow-once"})
			if err := os.WriteFile(script, classified, 0600); err != nil {
				t.Fatal(err)
			}
			if modLookupBound(payload.SessionID, payload.ToolUseID, "bash ./run.sh", root) == nil {
				t.Fatal("replay must match the snapshot actually classified")
			}
			if err := os.WriteFile(script, before, 0600); err != nil {
				t.Fatal(err)
			}
			if modLookupBound(payload.SessionID, payload.ToolUseID, "bash ./run.sh", root) != nil {
				t.Fatal("earlier hook-entry snapshot incorrectly earned replay approval")
			}
		})
	}
}

func TestSecurityApprovalSnapshotSurvivesPrePostLifecycle(t *testing.T) {
	for _, when := range []string{"during_classification", "during_execution"} {
		t.Run(when, func(t *testing.T) {
			securityHookHome(t)
			t.Setenv("YOLONOT_MOD", "1")
			cwd, command := t.TempDir(), "bash ./run.sh"
			script := filepath.Join(cwd, "run.sh")
			os.WriteFile(script, []byte("echo approved-snapshot-B\n"), 0600)
			SaveConfig(Config{Models: map[string]ModelConfig{"primary": {URL: "https://snapshot.invalid/chat", Model: "primary"}}, Judges: JudgeList{{Use: "primary"}}})
			calls := 0
			oldTransport := http.DefaultTransport
			http.DefaultTransport = securityDecisionTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				decision := "allow"
				if calls > 1 {
					decision = "ask"
				}
				if calls == 1 && when == "during_classification" {
					os.WriteFile(script, []byte("echo changed-snapshot-C\n"), 0600)
				}
				content := fmt.Sprintf(`{"decision":%q,"risk":"low","reasoning":"snapshot"}`, decision)
				body, _ := json.Marshal(map[string]interface{}{"choices": []interface{}{map[string]interface{}{"message": map[string]interface{}{"content": content}}}})
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
			})
			t.Cleanup(func() { http.DefaultTransport = oldTransport })
			pre := makePrePayload("snapshot-lifecycle", command, cwd)
			pre.ToolUseID = "snapshot-lifecycle-tool"
			if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != "allow" {
				t.Fatal(got)
			}
			if when == "during_execution" {
				os.WriteFile(script, []byte("echo changed-snapshot-C\n"), 0600)
			}
			project := ProjectSessionID(pre.SessionID, cwd)
			if sessionContentOK(project, command, cwd) {
				t.Fatal("new content inherited the classified snapshot approval")
			}
			t.Setenv("YOLONOT_MOD", "")
			post := pre
			post.HookEventName = "PostToolUse"
			runHookWithStruct(t, post)
			if sessionContentOK(project, command, cwd) {
				t.Fatal("PostToolUse laundered approval for changed script contents")
			}
			if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != "ask" {
				t.Fatalf("changed script must be rejudged: %s", got)
			}
			if calls != 2 {
				t.Fatalf("changed script bypassed classifier: calls=%d", calls)
			}
		})
	}
}

func TestSecurityHumanSessionApprovalPinsDialogSnapshot(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed_during_dialog=%t", changed), func(t *testing.T) {
			home := securityHookHome(t)
			t.Setenv("YOLONOT_MOD", "1")
			cwd, command := t.TempDir(), "bash ./run.sh"
			script := filepath.Join(cwd, "run.sh")
			os.WriteFile(script, []byte("echo dialog-snapshot-B\n"), 0600)
			writeGlobalRules(t, home, "ask-cmd bash *\n")
			pre := makePrePayload("human-snapshot", command, cwd)
			pre.ToolUseID = "human-snapshot-tool"
			if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != "ask" {
				t.Fatal(got)
			}
			if changed {
				os.WriteFile(script, []byte("echo changed-during-dialog-C\n"), 0600)
			}
			runModResolve(t, modResolve{SessionID: pre.SessionID, ToolUseID: pre.ToolUseID, Command: command, Cwd: cwd, Verdict: "allow-session"})
			t.Setenv("YOLONOT_MOD", "")
			classic := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision
			if changed && classic == "allow" {
				t.Fatal("dialog answer approved a different snapshot")
			}
			if !changed && classic != "allow" {
				t.Fatalf("unchanged human approval must replay: %s", classic)
			}
			post := pre
			post.HookEventName = "PostToolUse"
			runHookWithStruct(t, post)
			project := ProjectSessionID(pre.SessionID, cwd)
			if changed {
				if ContainsLine(project, "approved", command) || sessionContentOK(project, command, cwd) {
					t.Fatal("PostToolUse remembered contents changed during the dialog")
				}
			} else {
				if !ContainsLine(project, "approved", command) || !sessionContentOK(project, command, cwd) {
					t.Fatal("unchanged session answer must persist its snapshot")
				}
				os.WriteFile(script, []byte("echo changed-after-execution-C\n"), 0600)
				if sessionContentOK(project, command, cwd) {
					t.Fatal("human session answer approved future edits")
				}
			}
		})
	}
}

func TestSecurityFreshNativeAskDoesNotPersistChangedScript(t *testing.T) {
	home := securityHookHome(t)
	cwd, sid, command := t.TempDir(), "fresh-native-ask", "bash ./run.sh"
	script := filepath.Join(cwd, "run.sh")
	os.WriteFile(script, []byte("echo old-approved-B\n"), 0600)
	project := ProjectSessionID(sid, cwd)
	saveApproved(project, command, cwd)
	os.WriteFile(script, []byte("echo fresh-human-reviewed-C\n"), 0600)
	writeGlobalRules(t, home, "ask-cmd bash *\n")
	pre := makePrePayload(sid, command, cwd)
	if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != "ask" {
		t.Fatalf("stale approval must ask again: %s", got)
	}
	post := pre
	post.HookEventName = "PostToolUse"
	runHookWithStruct(t, post)
	if ContainsLine(project, "approved", command) {
		t.Fatal("a one-time native approval persisted a new script snapshot")
	}
	if ContainsLine(project, "asked", command) {
		t.Fatal("resolved ask marker must be consumed")
	}
}

func TestSecurityCoreRejectionHonorsPauseAndNewAllow(t *testing.T) {
	for _, variant := range []string{"review-rejected", "bash -lc 'review-rejected'", "sh <<'EOF'\nreview-rejected\nEOF"} {
		t.Run(variant, func(t *testing.T) {
			home := securityHookHome(t)
			cwd, sid := t.TempDir(), "rejection-current-policy"
			AppendLine(ProjectSessionID(sid, cwd), "denied", "review-rejected")
			payload := makePrePayload(sid, variant, cwd)
			if got := parseResponse(t, runHookWithStruct(t, payload)).HookSpecificOutput.PermissionDecision; got != "deny" {
				t.Fatalf("rejected wrapped command=%s", got)
			}
			paused := filepath.Join(SessionDir(), sid+".paused")
			os.WriteFile(paused, nil, 0600)
			if got := strings.TrimSpace(runHookWithStruct(t, payload)); got != "" {
				t.Fatalf("pause ignored: %s", got)
			}
			os.Remove(paused)
			if variant == "review-rejected" {
				writeGlobalRules(t, home, "allow-cmd review-rejected\n")
				if got := parseResponse(t, runHookWithStruct(t, payload)).HookSpecificOutput.PermissionDecision; got != "allow" {
					t.Fatalf("explicit allow ignored: %s", got)
				}
			}
		})
	}
}

func TestSecurityRejectionShellEquivalenceDoesNotGrantApproval(t *testing.T) {
	securityHookHome(t)
	AppendLine("shell-equivalence", "denied", "sh -c 'review-rejected'")
	if !matchesRejectedCommand("shell-equivalence", "review-rejected") {
		t.Fatal("backward shell rejection missing")
	}
	AppendLine("shell-equivalence", "approved", "review-rejected")
	if MatchesLineOrWrappedVariant("shell-equivalence", "approved", "sh -c 'review-rejected'") {
		t.Fatal("shell-body rejection equivalence granted approval")
	}
	if rejectedShellBody("sh -c \"$DYNAMIC\"") != "" {
		t.Fatal("dynamic shell body treated as literal")
	}
}

func TestSecurityModMiddlewarePolicyLifecycle(t *testing.T) {
	bun, err := exec.LookPath("bun")
	if err != nil {
		t.Skip("Bun is required to execute the Claude mod middleware regression")
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate mod test fixture")
	}
	fixture := filepath.Join(filepath.Dir(sourceFile), "mod", "register.test.ts")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bun, "test", fixture)
	cmd.Dir = filepath.Dir(fixture)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mod middleware lifecycle: %v\n%s", err, output)
	}
}

func TestSecurityModGrantScopeSurvivesDuplicatePostHooks(t *testing.T) {
	for _, verdict := range []string{"allow-once", "allow-session", "legacy"} {
		t.Run(verdict, func(t *testing.T) {
			home := securityHookHome(t)
			cwd, command := t.TempDir(), "touch ASK-MOD-SCOPE.marker"
			writeGlobalRules(t, home, "ask-cmd touch *\n")
			t.Setenv("YOLONOT_MOD", "1")
			pre := makePrePayload("duplicate-post-scope", command, cwd)
			pre.ToolUseID = "original-tool"
			if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != "ask" {
				t.Fatal(got)
			}
			if verdict == "legacy" {
				binding, hashes := modCommandSnapshot(command, cwd)
				modAppend(pre.SessionID, modEntry{ID: pre.ToolUseID, Command: command, Cwd: cwd, Binding: binding, ApprovalHashes: hashes, Decision: "allow", Layer: "human", Reason: "allowed for this session"})
			} else {
				runModResolve(t, modResolve{SessionID: pre.SessionID, ToolUseID: pre.ToolUseID, Command: command, Cwd: cwd, Verdict: verdict})
			}
			t.Setenv("YOLONOT_MOD", "")
			if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != "allow" {
				t.Fatalf("answer did not replay: %s", got)
			}
			post := pre
			post.HookEventName = "PostToolUse"
			for i := 0; i < 3; i++ {
				runHookWithStruct(t, post)
			}
			project := ProjectSessionID(pre.SessionID, cwd)
			wantSession := verdict == "allow-session"
			if got := ContainsLine(project, "approved", command); got != wantSession {
				t.Fatalf("persistent approval=%t, want %t for %s", got, wantSession, verdict)
			}
			pre.ToolUseID = "next-tool"
			want := "ask"
			if wantSession {
				want = "allow"
			}
			if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != want {
				t.Fatalf("next call=%s, want %s", got, want)
			}
		})
	}
}
