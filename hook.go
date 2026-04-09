package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HookPayload is the JSON sent by Claude Code to hooks.
type HookPayload struct {
	HookEventName string                 `json:"hook_event_name"`
	ToolName      string                 `json:"tool_name"`
	SessionID     string                 `json:"session_id"`
	Cwd           string                 `json:"cwd"`
	ToolInput     map[string]interface{} `json:"tool_input"`
}

// HookResponse is the JSON returned to Claude Code.
type HookResponse struct {
	HookSpecificOutput struct {
		HookEventName          string `json:"hookEventName"`
		PermissionDecision     string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

func hookResponse(decision, reason string) string {
	r := HookResponse{}
	r.HookSpecificOutput.HookEventName = "PreToolUse"
	r.HookSpecificOutput.PermissionDecision = decision
	r.HookSpecificOutput.PermissionDecisionReason = reason
	data, _ := json.Marshal(r)
	return string(data)
}

func cmdHook() {
	// Read payload from stdin
	input, _ := io.ReadAll(os.Stdin)
	if len(input) == 0 {
		// Try env var fallback
		if toolInput := os.Getenv("CLAUDE_TOOL_INPUT"); toolInput != "" {
			input = []byte(fmt.Sprintf(`{"hook_event_name":"%s","tool_name":"%s","session_id":"%s","tool_input":%s}`,
				envOr("CLAUDE_HOOK_EVENT_NAME", "PreToolUse"),
				envOr("CLAUDE_TOOL_NAME", "Bash"),
				envOr("CLAUDE_SESSION_ID", "unknown"),
				toolInput))
		}
	}

	var payload HookPayload
	if err := json.Unmarshal(input, &payload); err != nil {
		return
	}

	command, _ := payload.ToolInput["command"].(string)
	sessionID := payload.SessionID
	cwd := payload.Cwd

	// Clean old sessions (background, non-blocking)
	go CleanOldSessions()

	// PostToolUse: command ran → user approved → save to .approved
	if payload.HookEventName == "PostToolUse" {
		if sessionID != "" && command != "" {
			AppendLine(sessionID, "approved", command)
		}
		return
	}

	// --- PreToolUse pipeline ---

	if command == "" {
		return
	}

	// Step 0: Deny rules — checked first, absolute, no override
	rules := LoadRules()
	sensitive := LoadSensitivePatterns()
	firstToken := command
	if idx := strings.IndexByte(command, ' '); idx > 0 {
		firstToken = command[:idx]
	}
	for _, r := range rules {
		if r.Action == "deny" {
			if (r.Type == "cmd" && matchCmd(r.Pattern, command, firstToken)) ||
				(r.Type == "path" && scriptPathRe.FindStringSubmatch(" "+command) != nil && globMatch(r.Pattern, scriptPathRe.FindStringSubmatch(" "+command)[1])) {
				LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "rule", Decision: "deny", Reasoning: fmt.Sprintf("matched rule: deny-%s %s", r.Type, r.Pattern)})
				fmt.Println(hookResponse("deny", fmt.Sprintf("yolonot: rule %s", r.Pattern)))
				return
			}
		}
	}

	// Step 1: Session exact match → allow
	if sessionID != "" && ContainsLine(sessionID, "approved", command) {
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session", Decision: "allow", Source: "exact_match"})
		fmt.Println(hookResponse("allow", "yolonot: previously approved this session"))
		return
	}

	// Step 1.5: Session deny
	if sessionID != "" {
		// Check explicit deny list
		if ContainsLine(sessionID, "denied", command) {
			LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session_deny", Decision: "ask", Source: "previously_rejected"})
			fmt.Println(hookResponse("deny", "yolonot: previously rejected this session"))
			return
		}
		// Check asked-but-not-approved
		if ContainsLine(sessionID, "asked", command) && !ContainsLine(sessionID, "approved", command) {
			AppendLine(sessionID, "denied", command)
			LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session_deny", Decision: "ask", Source: "asked_not_approved"})
			fmt.Println(hookResponse("deny", "yolonot: previously rejected this session"))
			return
		}
	}

	// Step 2: Session similarity (LLM compare)
	if sessionID != "" {
		approved := ReadLines(sessionID, "approved")
		if len(approved) > 0 {
			cfg := GetLLMConfig()
			userPrompt := BuildComparePrompt(command, approved)
			start := time.Now()
			text, err := CallLLM(cfg, ComparePrompt, userPrompt, 256)
			ms := time.Since(start).Milliseconds()
			if err == nil {
				d := ParseDecision(text)
				if d != nil && d.Decision == "allow" {
					AppendLine(sessionID, "approved", command)
					LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session_llm", Decision: "allow", Reasoning: d.Reasoning, DurationMs: ms})
					fmt.Println(hookResponse("allow", "yolonot: similar to approved — "+d.Reasoning))
					return
				}
			}
		}
	}

	// Step 3: Rule matching (allow/ask — deny already handled in step 0)
	if match := MatchRuleWith(command, rules, sensitive); match != nil {
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "rule", Decision: match.Action, Reasoning: fmt.Sprintf("matched rule: %s-%s", match.Action, match.Pattern)})
		if match.Action == "allow" {
			if sessionID != "" {
				AppendLine(sessionID, "approved", command)
			}
			fmt.Println(hookResponse("allow", fmt.Sprintf("yolonot: rule %s", match.Pattern)))
			return
		} else if match.Action == "deny" {
			fmt.Println(hookResponse("deny", fmt.Sprintf("yolonot: rule %s", match.Pattern)))
			return
		} else {
			// ask rule
			if sessionID != "" {
				AppendLine(sessionID, "asked", command)
			}
			fmt.Println(hookResponse("ask", fmt.Sprintf("yolonot: rule %s", match.Pattern)))
			return
		}
	}

	// Step 4: Script cache check
	if cached := checkCache(command); cached != nil {
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "cache", Decision: cached.Decision, Confidence: cached.Confidence, Reasoning: "(cached) " + cached.Reasoning})
		if cached.Decision == "allow" {
			if sessionID != "" {
				AppendLine(sessionID, "approved", command)
			}
			fmt.Println(hookResponse("allow", "yolonot: "+cached.Reasoning))
		} else {
			if sessionID != "" {
				AppendLine(sessionID, "asked", command)
			}
			fmt.Println(hookResponse("ask", "yolonot: "+cached.Reasoning))
		}
		return
	}

	// Step 5: LLM analysis
	cfg := GetLLMConfig()
	userPrompt := BuildAnalyzePrompt(command)
	start := time.Now()
	text, err := CallLLM(cfg, SystemPrompt, userPrompt, 4096)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		// LLM unavailable → go transparent, let Claude Code decide
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "llm", Decision: "passthrough", Reasoning: "LLM unavailable", DurationMs: ms})
		return
	}

	d := ParseDecision(text)
	if d == nil {
		// Parse error → go transparent, let Claude Code decide
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "llm", Decision: "passthrough", Reasoning: "parse error", DurationMs: ms})
		return
	}

	// Cache the decision if it involved a script file
	saveCache(command, d)

	LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "llm", Decision: d.Decision, Confidence: d.Confidence, Reasoning: d.Reasoning, DurationMs: ms})

	if d.Decision == "allow" {
		if sessionID != "" {
			AppendLine(sessionID, "approved", command)
		}
		fmt.Println(hookResponse("allow", "yolonot: "+d.Reasoning))
	} else {
		if sessionID != "" {
			AppendLine(sessionID, "asked", command)
		}
		fmt.Println(hookResponse("ask", "yolonot: "+d.Reasoning))
	}
}

// --- Script cache ---

func cacheDir() string {
	return filepath.Join(YolonotDir(), "cache")
}

func scriptHash(command string) string {
	m := scriptPathRe.FindStringSubmatch(" " + command)
	if len(m) < 2 {
		return ""
	}
	path := m[1]
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(append(data, []byte(command)...))
	return fmt.Sprintf("%x", h[:8])
}

func checkCache(command string) *Decision {
	hash := scriptHash(command)
	if hash == "" {
		return nil
	}
	path := filepath.Join(cacheDir(), hash+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var d Decision
	if err := json.Unmarshal(data, &d); err != nil {
		return nil
	}
	return &d
}

func saveCache(command string, d *Decision) {
	hash := scriptHash(command)
	if hash == "" {
		return
	}
	dir := cacheDir()
	os.MkdirAll(dir, 0755)
	data, err := json.Marshal(d)
	if err != nil {
		return
	}
	os.WriteFile(filepath.Join(dir, hash+".json"), data, 0644)
}
