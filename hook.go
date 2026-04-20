package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
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
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
	SystemMessage string `json:"systemMessage,omitempty"`
}

// quietOnAllow is set once per `yolonot hook` invocation from Config. The
// hook process is invoked fresh per command by Claude Code (not concurrent
// within a single process), so a package-level var is safe here.
var quietOnAllow bool

// maxBannerRunes caps systemMessage / permissionDecisionReason length to bound
// terminal-spoof damage from an untrusted pre-check hook. Measured in runes so
// multi-byte sequences (emoji) don't get byte-sliced into invalid UTF-8.
const maxBannerRunes = 512

// sanitizeBanner strips control characters, ANSI sequences, and other
// renderable escape vectors from strings embedded in our hook response
// (especially pre-check passthrough). Caps length by rune count so UTF-8
// multi-byte sequences stay intact.
//
// What we drop:
//   - C0 controls (0x00-0x1F) except tab (→ space). This includes ESC (0x1B),
//     the prefix for 7-bit ANSI CSI/OSC sequences.
//   - DEL (0x7F).
//   - C1 controls (U+0080–U+009F). These are 8-bit equivalents of ESC+<letter>
//     sequences; U+009B is CSI, U+009D is OSC. Some terminals (xterm, VTE
//     variants) honor them when 8-bit controls are enabled.
//   - U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR — renderable line
//     breaks that would split the banner across lines.
//   - BiDi override + isolate runes: U+202A–U+202E (LRE/RLE/PDF/LRO/RLO —
//     the Trojan-Source primitives, CVE-2021-42574) and U+2066–U+2069 (BiDi
//     isolates). These reorder visible text, enabling banners that read
//     differently than the bytes claim.
//   - U+FEFF BOM/ZWNBSP — invisible outside of file-header contexts.
//
// We deliberately preserve U+200D ZWJ (used in emoji joiner sequences like
// 🧑‍🚀) and U+200B–U+200F in general (used by legitimate text shaping).
// These don't reorder text; they're not the CVE primitive.
func sanitizeBanner(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	count := 0
	for _, r := range s {
		if count >= maxBannerRunes-3 {
			b.WriteString("...")
			return b.String()
		}
		if r == '\t' {
			b.WriteRune(' ')
			count++
			continue
		}
		if r < 0x20 || r == 0x7F {
			continue
		}
		if r >= 0x80 && r <= 0x9F {
			continue
		}
		if r == 0x2028 || r == 0x2029 {
			continue
		}
		if r >= 0x202A && r <= 0x202E {
			continue
		}
		if r >= 0x2066 && r <= 0x2069 {
			continue
		}
		if r == 0xFEFF {
			continue
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

// buildHookResponse assembles a canonical HookResponse for the given decision.
//
// Banner format varies by decision:
//   - allow: "🧑‍🚀 <layer> -> <command>" in systemMessage.
//     permissionDecisionReason left empty so the TUI doesn't prefix it with
//     "PreToolUse:Bash says:" (which was duplicating the banner).
//   - ask: "🧑‍🚀 <layer> -> <reason>" in permissionDecisionReason.
//     Command is omitted because the TUI already renders the command
//     front-and-center in the permission prompt — showing it twice is noise.
//     The reason is what the user actually needs to decide.
//   - deny: "🧑‍🚀 <layer> -> <command>\n<reason>". Command is kept here
//     because the user doesn't get an interactive prompt; the full context
//     (what was blocked + why) needs to live in the reason.
//   - quietOnAllow suppresses the allow banner entirely.
//
// All user-visible text flows through sanitizeBanner — rule messages,
// pre-check output and LLM reasoning can all carry attacker-chosen bytes.

// applyRiskMap resolves the final hook action from the classifier's
// decision + risk tier through the active harness's risk map.
//
// Escalate-only safety invariant: the risk map can make things stricter
// (allow→ask, allow→deny, ask→deny, allow→passthrough) but cannot relax
// a classifier "ask" back to "allow". This asymmetry is deliberate — if
// the LLM already saw something worth asking about, a permissive tier
// mapping shouldn't override that judgement.
//
// passthrough returns ("", true); callers emit nothing and defer to the
// host's native permission engine. Any unknown action falls back to the
// classifier's original decision.
func applyRiskMap(h Harness, origDecision, risk string) (final string, passthrough bool) {
	if h == nil || risk == "" {
		return origDecision, false
	}
	action := ResolveRiskMap(h)[risk]
	switch action {
	case ActionPassthrough:
		return "", true
	case ActionDeny:
		return "deny", false
	case ActionAsk:
		if origDecision == "allow" {
			return "ask", false
		}
		return origDecision, false
	case ActionAllow:
		return origDecision, false
	}
	return origDecision, false
}

func buildHookResponse(decision, layer, reason, command string) HookResponse {
	layer = sanitizeBanner(layer)
	reason = sanitizeBanner(reason)
	r := HookResponse{}
	r.HookSpecificOutput.HookEventName = "PreToolUse"
	r.HookSpecificOutput.PermissionDecision = decision

	switch decision {
	case "allow":
		if !quietOnAllow {
			r.SystemMessage = fmt.Sprintf("🧑‍🚀 %s -> %s", layer, command)
		}
	case "ask":
		body := reason
		if body == "" {
			body = command
		}
		r.HookSpecificOutput.PermissionDecisionReason = fmt.Sprintf("🧑‍🚀 %s -> %s", layer, body)
	case "deny":
		banner := fmt.Sprintf("🧑‍🚀 %s -> %s", layer, command)
		if reason != "" {
			banner = banner + "\n" + reason
		}
		r.HookSpecificOutput.PermissionDecisionReason = banner
	}
	return r
}

// hookResponse is the stringified form of buildHookResponse, routed through
// the active harness adapter so non-Claude harnesses can emit their own
// JSON shape. For Claude (the canonical shape) this is a plain marshal.
// Returns empty string when the adapter opted out of emitting a response
// (e.g. Codex for allow decisions) — callers pair this with emitHook() so
// no stray newline reaches stdout.
func hookResponse(decision, layer, reason, command string) string {
	r := buildHookResponse(decision, layer, reason, command)
	return activeHarnessFormat(r)
}

// emitHook prints a hook response to stdout, skipping entirely when the
// adapter returned "" (Codex's "allow = silence" contract). Using this
// instead of fmt.Println keeps us from emitting a blank line that Codex
// would try to parse as JSON.
func emitHook(response string) {
	if response == "" {
		return
	}
	fmt.Println(response)
}

// activeHarnessFormat delegates to the active harness adapter's
// FormatHookResponse, with a canonical JSON fallback if no harness is
// registered (only possible in broken builds — every adapter registers
// itself in init()).
func activeHarnessFormat(r HookResponse) string {
	if h := ActiveHarness(); h != nil {
		return h.FormatHookResponse(r)
	}
	data, _ := json.Marshal(r)
	return string(data)
}

func cmdHook() {
	// Read payload from stdin; adapter handles env var fallback and
	// harness-specific JSON decoding.
	raw, _ := io.ReadAll(os.Stdin)

	// Allow `yolonot hook --harness <name>` to pin the adapter. Harness
	// CLIs don't all expose a stable session-id env var (Codex, OpenCode
	// don't), so auto-detection at hook time isn't reliable — install
	// writes this flag into the hook command so we route to the right
	// adapter regardless of env.
	for i := 2; i < len(os.Args); i++ {
		a := os.Args[i]
		if a == "--harness" && i+1 < len(os.Args) {
			os.Setenv("YOLONOT_HARNESS", os.Args[i+1])
			break
		}
		if strings.HasPrefix(a, "--harness=") {
			os.Setenv("YOLONOT_HARNESS", strings.TrimPrefix(a, "--harness="))
			break
		}
	}

	harness := ActiveHarness()
	if harness == nil {
		return
	}
	payload, err := harness.ParseHookInput(raw)
	if err != nil {
		return
	}
	if payload.HookEventName == "" {
		return
	}

	// Pre-check binaries (Dippy et al.) follow Claude's PreToolUse contract,
	// so always feed them the canonical Claude JSON — never the raw stdin
	// bytes (which could be Codex/OpenCode shape when those harnesses are
	// active). Canonical ↔ Claude shape, so json.Marshal(payload) suffices.
	canonicalInput, _ := json.Marshal(payload)

	command, _ := payload.ToolInput["command"].(string)
	sessionID := payload.SessionID
	cwd := payload.Cwd

	// Scope session to project
	projSessionID := ProjectSessionID(sessionID, cwd)

	// Clean old sessions (background, non-blocking)
	go CleanOldSessions()

	// Disabled via env var — total bypass (applies to Post too, so paused
	// sessions don't silently accumulate pre-approvals).
	if os.Getenv("YOLONOT_DISABLED") == "1" {
		return
	}

	// Paused for this session — total bypass (same: Post writes are gated
	// too, so unpausing doesn't reveal a pile of "pre-approved" commands
	// that yolonot never actually vetted).
	if sessionID != "" {
		if _, err := os.Stat(filepath.Join(YolonotDir(), "sessions", sessionID+".paused")); err == nil {
			return
		}
	}

	// PostToolUse: command ran → user approved → save to .approved
	if payload.HookEventName == "PostToolUse" {
		if sessionID != "" && command != "" {
			AppendLine(projSessionID, "approved", command)
		}
		return
	}

	// --- PreToolUse pipeline ---

	if command == "" {
		return
	}

	// Load config once — used by pre-check, risk-map resolution, and the
	// quiet-on-allow banner suppression. Keeps disk reads down to one per
	// hook invocation.
	config := LoadConfig()
	quietOnAllow = config.QuietOnAllow

	// User rules reflect the user's *current* intent, so they take priority
	// over session memory — with one deliberate exception:
	//
	//   Step 0:    rule deny        — hard gate
	//   Step 0.4:  rule allow       — explicit user approval; overrides prior
	//                                 session_deny so newly-added allow rules
	//                                 actually unblock previously-rejected cmds
	//   Step 0.5:  session approved — prior approval bypasses newly-added ask
	//                                 rule (so users aren't re-prompted mid-flow)
	//   Step 0.55: session deny     — prior rejection blocks re-asking
	//   Step 0.6:  rule ask         — only fires if session has no opinion
	//
	// Rule priority is deny > ask > allow (file order irrelevant), handled by
	// MatchRuleByPriority.
	rules := LoadRules()
	sensitive := LoadSensitivePatterns()
	ruleMatch := MatchRuleByPriority(command, rules, sensitive)
	if ruleMatch != nil && ruleMatch.Action == "deny" {
		userReason := fmt.Sprintf("rule %s", ruleMatch.Pattern)
		if ruleMatch.Message != "" {
			userReason = ruleMatch.Message
		}
		reasoning := fmt.Sprintf("matched rule: deny-%s", ruleMatch.Pattern)
		if ruleMatch.Message != "" {
			reasoning += " — " + ruleMatch.Message
		}
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "rule", Decision: "deny", Reasoning: reasoning})
		emitHook(hookResponse("deny", "rule", userReason, command))
		return
	}

	// Step 0.4: Rule allow. Placed above session_deny so an explicitly added
	// allow-cmd clears a prior rejection — symmetric with deny-cmd overriding
	// a prior approval.
	if ruleMatch != nil && ruleMatch.Action == "allow" {
		userReason := fmt.Sprintf("rule %s", ruleMatch.Pattern)
		if ruleMatch.Message != "" {
			userReason = ruleMatch.Message
		}
		reasoning := fmt.Sprintf("matched rule: allow-%s", ruleMatch.Pattern)
		if ruleMatch.Message != "" {
			reasoning += " — " + ruleMatch.Message
		}
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "rule", Decision: "allow", Reasoning: reasoning})
		if sessionID != "" {
			AppendLine(projSessionID, "approved", command)
		}
		emitHook(hookResponse("allow", "rule", userReason, command))
		return
	}

	// Step 0.5: Session exact match → allow. Placed here (before ask rule)
	// so a prior approval bypasses a newly-added ask-cmd.
	if sessionID != "" && ContainsLine(projSessionID, "approved", command) {
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session", Decision: "allow", Source: "exact_match"})
		emitHook(hookResponse("allow", "session", "previously approved this session", command))
		return
	}

	// Step 0.55: Session deny. If the user previously rejected this exact
	// command (or was asked about it and didn't approve), honor that before
	// falling into an ask-rule that would just re-prompt forever.
	if sessionID != "" {
		if ContainsLine(projSessionID, "denied", command) {
			LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session_deny", Decision: "deny", Source: "previously_rejected"})
			emitHook(hookResponse("deny", "session_deny", "previously rejected this session", command))
			return
		}
		if ContainsLine(projSessionID, "asked", command) && !ContainsLine(projSessionID, "approved", command) {
			// Before inferring rejection, check if the command was approved
			// as a wrapped variant (e.g. rtk rewrote `curl X` → `rtk curl X`
			// between our ask and actual execution). Record the plain form
			// so future checks are an exact match.
			if ApprovedAsWrappedVariant(projSessionID, command) {
				AppendLine(projSessionID, "approved", command)
				LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session", Decision: "allow", Source: "wrapped_variant"})
				emitHook(hookResponse("allow", "session", "previously approved as wrapped command this session", command))
				return
			}
			AppendLine(projSessionID, "denied", command)
			LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session_deny", Decision: "deny", Source: "asked_not_approved"})
			emitHook(hookResponse("deny", "session_deny", "previously rejected this session", command))
			return
		}
	}

	// Step 0.6: Rule ask. Deny/allow already handled above; remaining
	// matches are ask-rules that fall through session checks.
	if ruleMatch != nil && ruleMatch.Action == "ask" {
		userReason := fmt.Sprintf("rule %s", ruleMatch.Pattern)
		if ruleMatch.Message != "" {
			userReason = ruleMatch.Message
		}
		reasoning := fmt.Sprintf("matched rule: ask-%s", ruleMatch.Pattern)
		if ruleMatch.Message != "" {
			reasoning += " — " + ruleMatch.Message
		}
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "rule", Decision: "ask", Reasoning: reasoning})
		if sessionID != "" {
			AppendLine(projSessionID, "asked", command)
		}
		emitHook(hookResponse("ask", "rule", userReason, command))
		return
	}

	// Step 1: Pre-check hooks. Fast deterministic gates that run before
	// yolonot's own pipeline, in the order configured. Only "allow"
	// short-circuits — ask/deny/empty all fall through to the next hook and
	// ultimately to yolonot's own rules/LLM (matches the common chain-hook
	// convention).
	//
	// Two kinds of entries share this list:
	//   1. FastAllowSentinel — dispatches to the built-in Go bash parser
	//      (no fork/exec). Cheap, strict, always available.
	//   2. Anything else — treated as an external binary path and invoked
	//      with the standard Claude Code hook JSON on stdin (e.g. Dippy).
	for _, preCheck := range config.PreCheck {
		if preCheck == "" {
			continue
		}
		if preCheck == FastAllowSentinel {
			// Any rule match already short-circuited at step 0, so reaching
			// fast_allow means no user rule applies — safe to consult the
			// built-in parser.
			if ok, reason := IsLocallySafeWith(command, AllowRedirectPatterns(rules)); ok {
				if sessionID != "" {
					AppendLine(projSessionID, "approved", command)
				}
				LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "fast_allow", Decision: "allow", Reasoning: reason})
				emitHook(hookResponse("allow", "fast_allow", reason, command))
				return
			}
			continue
		}
		if _, reason, ok := runPreCheck(preCheck, canonicalInput); ok {
			if sessionID != "" {
				AppendLine(projSessionID, "approved", command)
			}
			LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "pre_check", Decision: "allow", Reasoning: reason})
			layer := "pre_check (" + preCheckShortName(preCheck) + ")"
			emitHook(hookResponse("allow", layer, reason, command))
			return
		}
	}

	// Step 2: Session similarity (LLM compare)
	if sessionID != "" {
		approved := ReadLines(projSessionID, "approved")
		candidates := filterByPrefix(command, approved)
		if len(candidates) > 0 {
			cfg := GetLLMConfig()
			userPrompt := BuildComparePrompt(command, candidates)
			start := time.Now()
			text, err := CallLLM(cfg, ComparePrompt, userPrompt, 256)
			ms := time.Since(start).Milliseconds()
			if err == nil {
				d := ParseDecision(text)
				if d != nil && d.Decision == "allow" {
					// The compare layer says "similar enough to an already
					// approved command" — that approval already flowed
					// through a risk map once. Don't re-map here.
					AppendLine(projSessionID, "approved", command)
					LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session_llm", Decision: "allow", Short: d.Short, Reasoning: d.Reasoning, DurationMs: ms})
					emitHook(hookResponse("allow", "session_llm", d.Reasoning, command))
					return
				}
			}
		}
	}

	// Step 4: Script cache check
	if cached := checkCache(command); cached != nil {
		// Route cached decisions through the risk map so cache + live LLM
		// paths apply the same policy. Older cache entries without a Risk
		// tier fall through with their original decision (no map applied).
		finalDecision, passthrough := applyRiskMap(ActiveHarness(), cached.Decision, cached.Risk)
		LogDecision(DecisionEntry{
			SessionID: sessionID, Command: command, Cwd: cwd, Layer: "cache",
			Decision: finalDecision, Risk: cached.Risk, Confidence: cached.Confidence, Short: cached.Short,
			Reasoning: fmt.Sprintf("orig=%s → %s (cached) %s", cached.Decision, finalDecision, cached.Reasoning),
		})
		if passthrough {
			emitHook("")
			return
		}
		switch finalDecision {
		case "allow":
			if sessionID != "" {
				AppendLine(projSessionID, "approved", command)
			}
			emitHook(hookResponse("allow", "cache", cached.Reasoning, command))
		case "deny":
			emitHook(hookResponse("deny", "cache", cached.Reasoning, command))
		default: // ask
			if sessionID != "" {
				AppendLine(projSessionID, "asked", command)
			}
			emitHook(hookResponse("ask", "cache", cached.Reasoning, command))
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
		// LLM unavailable → transparent passthrough. Route through the
		// active adapter so Codex/Gemini see their native wire shape
		// (empty stdout = host-decides), not Claude's nested envelope.
		// Claude still gets a user-visible systemMessage banner because
		// its adapter preserves it; non-Claude adapters return empty for
		// a decisionless response (see harness_codex.go / harness_gemini.go
		// FormatHookResponse).
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "llm", Decision: "passthrough", Reasoning: "LLM unavailable: " + err.Error(), DurationMs: ms})
		r := HookResponse{}
		r.SystemMessage = "yolonot: 🧑‍🚀 LLM unreachable, falling back to host permissions"
		emitHook(activeHarnessFormat(r))
		return
	}

	d := ParseDecision(text)
	if d == nil {
		// Parse error → same transparent fallback as LLM-unreachable.
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "llm", Decision: "passthrough", Reasoning: "parse error", DurationMs: ms})
		r := HookResponse{}
		r.SystemMessage = "yolonot: 🧑‍🚀 LLM response parse error, falling back to host permissions"
		emitHook(activeHarnessFormat(r))
		return
	}

	// Cache the decision if it involved a script file
	saveCache(command, d)

	// Risk map: classifier gave us (decision, risk). Active harness
	// decides the final action per its RiskMap. "passthrough" returns an
	// empty response; the host's native permission engine takes over.
	finalDecision, passthrough := applyRiskMap(ActiveHarness(), d.Decision, d.Risk)
	LogDecision(DecisionEntry{
		SessionID: sessionID, Command: command, Cwd: cwd, Layer: "llm",
		Decision: finalDecision, Risk: d.Risk, Confidence: d.Confidence, Short: d.Short,
		Reasoning: fmt.Sprintf("orig=%s → %s %s", d.Decision, finalDecision, d.Reasoning),
		DurationMs: ms,
	})
	if passthrough {
		emitHook("")
		return
	}
	switch finalDecision {
	case "allow":
		if sessionID != "" {
			AppendLine(projSessionID, "approved", command)
		}
		emitHook(hookResponse("allow", "llm", d.Reasoning, command))
	case "deny":
		emitHook(hookResponse("deny", "llm", d.Reasoning, command))
	default: // ask
		if sessionID != "" {
			AppendLine(projSessionID, "asked", command)
		}
		emitHook(hookResponse("ask", "llm", d.Reasoning, command))
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

// runPreCheck invokes an external hook binary with the same JSON stdin
// Claude Code would send. Returns (parsed response, reason, ok) where ok
// is true only if the hook returned an "allow" permissionDecision. Any other
// outcome (ask/deny/empty/error/timeout) returns ok=false so yolonot's
// pipeline continues. The caller is responsible for re-serializing (and may
// mutate systemMessage before doing so — e.g. to brand the banner).
func runPreCheck(cmdPath string, input []byte) (*HookResponse, string, bool) {
	parts := strings.Fields(cmdPath)
	if len(parts) == 0 {
		return nil, "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil, "", false
	}

	var resp HookResponse
	if err := json.Unmarshal(bytes.TrimSpace(out), &resp); err != nil {
		return nil, "", false
	}
	if resp.HookSpecificOutput.PermissionDecision != "allow" {
		return nil, "", false
	}
	reason := resp.HookSpecificOutput.PermissionDecisionReason
	if reason == "" {
		reason = "allowed by pre-check hook"
	}
	return &resp, reason, true
}

// preCheckShortName returns a short label for a pre-check hook command,
// used to brand the forwarded systemMessage (e.g. "yolonot (via dippy-hook): ...").
// Falls back to the first field of the command if filepath.Base is empty.
func preCheckShortName(cmdPath string) string {
	parts := strings.Fields(cmdPath)
	if len(parts) == 0 {
		return "pre-check"
	}
	name := filepath.Base(parts[0])
	if name == "" || name == "." || name == "/" {
		return parts[0]
	}
	return name
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
	os.WriteFile(filepath.Join(dir, hash+".json"), data, 0600)
}
