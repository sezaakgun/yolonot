package yolonot

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sezaakgun/yolonot/internal/fastallow"
)

// HookPayload is the JSON sent by Claude Code to hooks.
type HookPayload struct {
	HookEventName  string                 `json:"hook_event_name"`
	ToolName       string                 `json:"tool_name"`
	SessionID      string                 `json:"session_id"`
	Cwd            string                 `json:"cwd"`
	ToolInput      map[string]interface{} `json:"tool_input"`
	ToolUseID      string                 `json:"tool_use_id,omitempty"`
	PermissionMode string                 `json:"permission_mode,omitempty"` // Claude Code only
	BypassSandbox  bool                   `json:"bypass_sandbox,omitempty"`
	AgentID        string                 `json:"agent_id,omitempty"` // Claude Code, subagent and teammate calls
	AgentType      string                 `json:"agent_type,omitempty"`
}

func extractToolInputBypassSandbox(toolInput map[string]interface{}) bool {
	if len(toolInput) == 0 {
		return false
	}
	if b, ok := toolInput["dangerouslyDisableSandbox"].(bool); ok && b {
		return true
	}
	if b, ok := toolInput["BypassSandbox"].(bool); ok && b {
		return true
	}
	if sp, ok := toolInput["sandbox_permissions"].(string); ok && sp == "require_escalated" {
		return true
	}
	if b, ok := toolInput["with_escalated_permissions"].(bool); ok && b {
		return true
	}
	return false
}

func approvedSuffix() string {
	if currentBypassSandbox {
		return "approved_unsandboxed"
	}
	return "approved"
}

func approvedHashSuffix() string {
	if currentBypassSandbox {
		return "approved_unsandboxedhash"
	}
	return "approvedhash"
}

// HookResponse is the JSON returned to Claude Code.
type HookResponse struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision,omitempty"`
		PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	} `json:"hookSpecificOutput"`
	SystemMessage string `json:"systemMessage,omitempty"`
}

// maxHookInputBytes caps the hook stdin payload. A real PreToolUse payload
// is a few KB; 4 MB is generous headroom while still bounding the work the
// downstream quote-aware scanners do on the command string.
const maxHookInputBytes = 4 << 20

// quietOnAllow is set once per `yolonot hook` invocation from Config. The
// hook process is invoked fresh per command by Claude Code (not concurrent
// within a single process), so a package-level var is safe here.
var quietOnAllow bool

// currentPermissionMode mirrors HookPayload.PermissionMode for the active
// hook invocation. Claude Code only — empty on other harnesses.
var currentPermissionMode string

// currentBypassSandbox mirrors HookPayload.BypassSandbox for the active hook invocation.
var currentBypassSandbox bool

// currentAgentID, currentAgentType and currentToolUseID mirror the same
// payload fields into every decision logged by this invocation.
var currentAgentID, currentAgentType, currentToolUseID string

// PermissionRequest is a second policy phase in Codex: it can approve a
// host permission request, unlike PreToolUse's deny-only enforcement.
var currentHookEventName string

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
// Scope note: this invariant governs TIER-MAPPING only. The escalation
// layer (escalation.go) may replace the classifier verdict upstream of
// this function with a deliberate second judgment from a bigger model —
// that is a sanctioned re-classification, not a relaxation, and its own
// guardrails forbid relaxing a resolved deny.
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
	case ActionForceAllow:
		if risk != RiskCritical && origDecision != "deny" {
			return "allow", false
		}
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
	if currentHookEventName == "PermissionRequest" {
		r.HookSpecificOutput.HookEventName = "PermissionRequest"
	}
	modRecord(decision, layer, reason)
	codexRecordPre(modSessionID, modCommand, modCwd, modRuleAction, decision, layer, reason, false)
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
	// Similarity, judges and escalation share one budget, leaving room to
	// emit a decision before the host's 60-second hook timeout.
	hookStart := time.Now()
	hookContext, cancel := hookBudgetContext(context.Background(), hookStart)
	defer cancel()

	// Read payload from stdin; adapter handles env var fallback and
	// harness-specific JSON decoding. Cap the read: the command string is
	// processed by quote-aware scanners downstream, so an unbounded payload
	// would be an easy CPU/memory amplifier.
	raw, _ := io.ReadAll(io.LimitReader(os.Stdin, maxHookInputBytes))

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

	// Disabled via env var — total bypass (applies to Post too, so paused
	// sessions don't silently accumulate pre-approvals).
	if os.Getenv("YOLONOT_DISABLED") == "1" {
		return
	}

	harness := ActiveHarness()
	if harness == nil {
		return
	}
	payload, err := harness.ParseHookInput(raw)
	if err != nil {
		if f, ok := harness.(interface{ ParseFailure([]byte, error) string }); ok {
			emitHook(f.ParseFailure(raw, err))
		}
		return
	}
	if payload.HookEventName == "" {
		return
	}
	if !payload.BypassSandbox {
		payload.BypassSandbox = extractToolInputBypassSandbox(payload.ToolInput)
	}
	currentPermissionMode = payload.PermissionMode
	currentBypassSandbox = payload.BypassSandbox
	currentAgentID, currentAgentType, currentToolUseID = payload.AgentID, payload.AgentType, payload.ToolUseID
	currentHookEventName = payload.HookEventName
	modRun = os.Getenv("YOLONOT_MOD") == "1"
	modSessionID, modToolUseID, modStart = payload.SessionID, payload.ToolUseID, hookStart

	// Pre-check binaries (Dippy et al.) follow Claude's PreToolUse contract,
	// so always feed them the canonical Claude JSON — never the raw stdin
	// bytes (which could be Codex/OpenCode shape when those harnesses are
	// active). Canonical ↔ Claude shape, so json.Marshal(payload) suffices.
	canonicalPayload := payload
	if canonicalPayload.HookEventName == "PermissionRequest" {
		canonicalPayload.HookEventName = "PreToolUse"
	}
	canonicalInput, _ := json.Marshal(canonicalPayload)

	command, _ := payload.ToolInput["command"].(string)
	sessionID := payload.SessionID
	cwd := payload.Cwd

	// Scope session to project
	projSessionID := ProjectSessionID(sessionID, cwd)

	// Clean old sessions (background, non-blocking)
	go CleanOldSessions()

	// An agent or skill may never execute `yolonot pause --global` or
	// `yolonot resume --global`, even when the current session is paused or
	// running under bypassPermissions.
	if payload.HookEventName != "PostToolUse" && command != "" {
		if verb := selfPolicyVerb(command); strings.HasSuffix(verb, "--global") {
			reason := fmt.Sprintf("yolonot %s affects all sessions globally and cannot be run by an agent; run it directly in your terminal", verb)
			LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "self", Decision: ActionDeny, Reasoning: reason})
			emitHook(hookResponse(ActionDeny, "self", reason, command))
			return
		}
	}

	// Claude Code --dangerously-skip-permissions — total bypass, same shape
	// as YOLONOT_DISABLED. User asked the host to skip its own permission
	// engine; yolonot honors that and stays out of the way. Post writes are
	// gated too so resuming a normal session doesn't reveal a pile of
	// "pre-approved" commands yolonot never vetted.
	if harness.Name() == "claude" && payload.PermissionMode == "bypassPermissions" {
		return
	}

	// Paused globally or for this session — total bypass (same: Post writes
	// are gated too, so unpausing doesn't reveal a pile of "pre-approved"
	// commands that yolonot never actually vetted).
	if isPaused(sessionID) {
		return
	}

	// Load config once — used by pre-check, risk-map resolution, quiet-on-
	// allow banner suppression, and the script-attach boundary. Keeps disk
	// reads down to one per hook invocation. Loaded BEFORE the PostToolUse
	// branch: saveApproved hashes attached script contents, so the attach
	// boundary (attachOutsideRoot) must match what PreToolUse used —
	// otherwise open-mode approvals for outside-root scripts never stick.
	config := LoadConfig()
	if config.LoadError != nil {
		if payload.HookEventName == "PostToolUse" {
			return
		}
		emitFailure(config, payload, command, cwd, sessionID, projSessionID, "invalid_config", config.LoadError.Error())
		return
	}
	quietOnAllow = config.QuietOnAllow && !modRun
	attachOutsideRoot = config.AttachOutsideRoot
	// Register user-defined wrappers (Config.Wrappers) with fast_allow so
	// `mycli ls` unwraps to `ls`. Idempotent — safe to call every hook.
	fastallow.AddWrappers(config.Wrappers...)

	// PostToolUse preserves already-bound yolonot grants and explicit mod
	// session answers. Native completion alone cannot establish a persistent
	// human grant or a new inspected script snapshot.
	if payload.HookEventName == "PostToolUse" {
		if sessionID != "" && command != "" {
			if answer := modLookupBound(sessionID, payload.ToolUseID, command, cwd); answer != nil && answer.Decision == "allow" {
				// A completed tool ID cannot replay a one-call grant again.
				// Duplicate completion callbacks remain harmless.
				answer.Completed = true
				defer modAppend(sessionID, *answer)
			}
			if dropLineOrVariant(projSessionID, "once", command) {
				return
			}
			pendingAsk := MatchesLineOrWrappedVariant(projSessionID, "asked", command)
			if MatchesLineOrWrappedVariant(projSessionID, approvedSuffix(), command) && !pendingAsk {
				// PreToolUse already saved the judged snapshot. Running a
				// script must not grant approval to edits made while it ran.
				return
			}
			modAnswer := modLookup(sessionID, payload.ToolUseID)
			if modAnswer != nil && (modAnswer.Decision != "allow" || modAnswer.Layer != "human" ||
				modLookupBound(sessionID, payload.ToolUseID, command, cwd) == nil) {
				// The answer must match its original dialog snapshot.
				return
			}
			if modAnswer != nil && modAnswer.Grant != "allow-session" {
				// Duplicate callbacks must not widen a consumed one-time
				// grant. Legacy records with unknown scope are one-time too.
				dropLineOrVariant(projSessionID, "asked", command)
				return
			}
			// Native PostToolUse does not say whether the user chose a
			// one-time or session grant. Never widen an ambiguous approval.
			// Explicit session grants use the CLI or the mod's human answer.
			if modAnswer == nil {
				if pendingAsk {
					dropLineOrVariant(projSessionID, "asked", command)
					dropLineOrVariant(projSessionID, approvedSuffix(), command)
					// Cursor CLI also emits afterShellExecution after Skip,
					// indistinguishable from an empty-output successful call.
					// Codex defers asks to its own approval policy, which may run
					// the command with no human involved.
					// Clear the pending ask so a later call can ask again,
					// but never fabricate a human approval from this event.
					if harnessSupportsAsk(harness) && harness.Name() != "cursor" && harness.Name() != "codex" {
						LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "human", Decision: "allow", Source: "allow_once"})
					}
				}
				// Passthrough and host-only approvals are equally ambiguous.
				// PreToolUse already records yolonot's own allow verdicts.
				return
			}
			if pendingAsk {
				dropLineOrVariant(projSessionID, "asked", command)
				LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "human", Decision: "allow", Source: "ask_approved"})
			}
			saveApprovedSnapshot(projSessionID, command, modAnswer.ApprovalHashes)
		}
		return
	}

	// --- PreToolUse pipeline ---

	if command == "" {
		return
	}
	modCommand, modCwd = command, cwd
	modRuleAction = ""
	modBinding = ""
	modApprovalHashes = nil
	if modRun && payload.ToolUseID != "" {
		modBinding, modApprovalHashes = modCommandSnapshot(command, cwd)
	}

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
	rules := LoadRules(cwd)
	sensitive := LoadSensitivePatterns(cwd)
	ruleMatch := MatchRuleByPriority(command, rules, sensitive)
	if ruleMatch != nil {
		modRuleAction = ruleMatch.Action
	}
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

	// Step 0.3: an agent changing yolonot's own grants. These verbs record
	// human answers and session grants, so the user must see each call;
	// allow rules, session memory and judges never clear it. Global pause
	// (--global) is hard-denied so an agent or skill can never execute it.
	if verb := selfPolicyVerb(command); verb != "" {
		action := ActionAsk
		reason := fmt.Sprintf("yolonot %s changes yolonot's own approvals; the user must run or confirm it", verb)
		if !harnessSupportsAsk(harness) || strings.HasSuffix(verb, "--global") {
			action = ActionDeny
		}
		if strings.HasSuffix(verb, "--global") {
			reason = fmt.Sprintf("yolonot %s affects all sessions globally and cannot be run by an agent; run it directly in your terminal", verb)
		}
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "self", Decision: action, Reasoning: reason})
		emitHook(hookResponse(action, "self", reason, command))
		return
	}

	// Codex fires PreToolUse followed immediately by PermissionRequest for
	// the same command when host approval is requested. If no new deny rule
	// intervened above, reuse the paired PreToolUse verdict without logging
	// or calling remote judges a second time.
	if harness.Name() == "codex" && payload.HookEventName == "PermissionRequest" && sessionID != "" {
		if pre := codexConsumePre(sessionID, command, cwd, modRuleAction); pre != nil {
			if pre.Passthrough {
				emitHook("")
				return
			}
			emitHook(hookResponse(pre.Decision, pre.Layer, pre.Reason, command))
			return
		}
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
			saveApproved(projSessionID, command, cwd)
		}
		emitHook(hookResponse("allow", "rule", userReason, command))
		return
	}

	// Replay only after the current deny/allow rules have had their say.
	// Tool IDs survive middleware rewrites; the binding must also match
	// this command, cwd and script snapshot before reusing a verdict.
	if !modRun {
		if e := modLookupBound(sessionID, payload.ToolUseID, command, cwd); e != nil {
			quietOnAllow = true
			emitHook(hookResponse(e.Decision, e.Layer, e.Reason, command))
			return
		}
	}

	// Step 0.5: Session match → allow. Wrapper-aware lookup: matches if
	// `command` was previously approved exactly, OR is a wrapped variant of
	// an approved plain command (`rtk ls` against approved `ls`), OR is the
	// plain form of an approved wrapped command (`ls` against approved
	// `rtk ls`). See MatchesLineOrWrappedVariant + SessionWrappers. When
	// the match lands via wrapper equivalence we also record the current
	// form so the next invocation hits the fast exact-match path.
	// contentStale marks "this exact command was session-approved, but its
	// attached script contents have changed since". It suppresses every
	// string-level replay of that approval (exact match here, and the
	// similarity layer below, which would trivially see the identical
	// string in the approved list and re-allow) — the content-keyed
	// cache/LLM layers judge the new contents instead.
	contentStale := false
	if sessionID != "" && MatchesLineOrWrappedVariant(projSessionID, approvedSuffix(), command) {
		// Content gate: a string match is not enough when the command
		// attaches script contents — the approval was granted for the
		// contents that existed then. If the script has been edited since,
		// fall through so the cache/LLM judge the NEW contents instead of
		// replaying an approval about the old ones.
		if !sessionContentOK(projSessionID, command, cwd) {
			contentStale = true
			Verbosef("session: approved command %q has changed script contents; re-judging", command)
		} else {
			source := "exact_match"
			if !ContainsLine(projSessionID, approvedSuffix(), command) {
				saveApproved(projSessionID, command, cwd)
				source = "wrapped_variant"
			}
			LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session", Decision: "allow", Source: source})
			emitHook(hookResponse("allow", "session", "previously approved this session", command))
			return
		}
	}

	// Step 0.55: Session deny. If the user previously rejected this exact
	// command (or a wrapped variant), honor that before falling into an
	// ask-rule that would just re-prompt forever. Symmetric wrapper lookup
	// keeps `rtk curl evil` denied when plain `curl evil` was denied, and
	// vice versa.
	if sessionID != "" {
		if matchesRejectedCommand(projSessionID, command) {
			LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session_deny", Decision: "deny", Source: "previously_rejected"})
			emitHook(hookResponse("deny", "session_deny", "previously rejected this session", command))
			return
		}
		// An unanswered ask is not evidence of rejection. Duplicate hooks,
		// cancellation and interrupted calls all leave pending markers.
		// Only an explicit human/mod/CLI denial may populate denied.
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

	// The judge chain (prechecks, classifier), then escalation on an
	// adopted classifier verdict. Session similarity and the script cache
	// are consulted once, right before the first remote judge.
	specs := config.JudgeSpecs()
	in := &JudgeInput{Command: command, Cwd: cwd, Canonical: canonicalInput, Rules: rules,
		Config: config, Harness: ActiveHarness(), HookStart: hookStart, Context: hookContext}
	beforeRemote := func() bool {
		return hookMemoryLookup(hookContext, command, cwd, sessionID, projSessionID, contentStale)
	}
	v, jerr, done := RunJudges(specs, in, beforeRemote)
	if done {
		return
	}
	if v == nil {
		hookNoVerdict(jerr, payload, command, cwd, sessionID, projSessionID)
		return
	}
	if v.Dec != nil {
		// Earlier exec judges may have changed scripts after hook entry.
		// Pin replay to the snapshot actually sent to the adopted model.
		modBinding = v.ReplayBinding
		modApprovalHashes = v.ApprovalHashes
	}
	escalateUncertain(in, v)

	// Non-classifier verdict (fast_allow / exec hook): allow-only today.
	if v.Dec == nil {
		finalDecision, passthrough := applyRiskMap(ActiveHarness(), v.Decision, v.Risk)
		loggedDecision := finalDecision
		if passthrough {
			loggedDecision = ActionPassthrough
		}
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: v.Layer, Decision: loggedDecision, OrigDecision: v.Decision, Risk: v.Risk, Reasoning: v.Reason})
		if passthrough {
			codexRecordPre(modSessionID, modCommand, modCwd, modRuleAction, "", v.Layer, "", true)
			emitHook("")
			return
		}
		switch finalDecision {
		case "allow":
			if sessionID != "" {
				saveApproved(projSessionID, command, cwd)
			}
			emitHook(hookResponse("allow", v.Layer, v.Reason, command))
		case "deny":
			emitHook(hookResponse("deny", v.Layer, v.Reason, command))
		default:
			if sessionID != "" {
				AppendLine(projSessionID, "asked", command)
			}
			emitHook(hookResponse("ask", v.Layer, v.Reason, command))
		}
		return
	}

	d := v.Dec
	escOut, escCacheOK := v.Esc, v.CacheOK
	ms := v.Ms

	// Risk map: classifier gave us (decision, risk). Active harness
	// decides the final action per its RiskMap. "passthrough" returns an
	// empty response; the host's native permission engine takes over.
	finalDecision, passthrough := applyRiskMap(ActiveHarness(), d.Decision, d.Risk)

	// Unresolved policy (unattended runs): escalation fired and the result
	// still resolves to ask — nobody is there to answer it. "deny" degrades
	// it to a definitive verdict carrying both opinions.
	unresolvedReason := ""
	if !passthrough && finalDecision == "ask" {
		if degrade, reason := escalationUnresolvedDeny(config, escOut, d); degrade {
			finalDecision = "deny"
			unresolvedReason = reason
		}
	}

	// Cache the decision if it involved a script file, keyed to the exact
	// snapshot the LLM just judged. Skipped when the escalation call failed
	// transiently (caching would freeze the un-rescued ask for this content
	// and the one-shot rescue would never re-fire) and when the unresolved
	// policy degraded the verdict — the cache path can't re-apply that
	// policy, and a cached "ask" would contradict this run's deny on every
	// replay.
	if escCacheOK && unresolvedReason == "" {
		saveCacheHash(v.CacheKey, d, v.CacheContext)
	}

	loggedDecision := finalDecision
	if passthrough {
		loggedDecision = ActionPassthrough
	}
	entry := DecisionEntry{
		SessionID: sessionID, Command: command, Cwd: cwd, Layer: strings.TrimSuffix(v.Layer, "+esc"),
		Decision: loggedDecision, OrigDecision: d.Decision, Risk: d.Risk, Confidence: d.Confidence, Short: d.Short,
		Reasoning:  fmt.Sprintf("orig=%s → %s %s", d.Decision, loggedDecision, d.Reasoning),
		DurationMs: ms, Attached: v.Attached, Withheld: v.Withheld,
	}
	escalationLogFields(&entry, escOut)
	if unresolvedReason != "" {
		entry.Reasoning = unresolvedReason + " | " + entry.Reasoning
	}
	LogDecision(entry)

	if passthrough {
		codexRecordPre(modSessionID, modCommand, modCwd, modRuleAction, "", v.Layer, "", true)
		emitHook("")
		return
	}
	layer := v.Layer
	switch finalDecision {
	case "allow":
		if sessionID != "" {
			saveApprovedSnapshot(projSessionID, command, v.ApprovalHashes)
		}
		emitHook(hookResponse("allow", layer, d.Reasoning, command))
	case "deny":
		reason := d.Reasoning
		if escOut.Outcome == "hardened" && escOut.Reasoning != "" {
			// The harden is what turned this into a deny — show the
			// rationale that caused it, not the milder primary one.
			reason = escOut.Reasoning
		}
		if unresolvedReason != "" {
			reason = unresolvedReason
		}
		emitHook(hookResponse("deny", layer, reason, command))
	default: // ask
		if sessionID != "" {
			AppendLine(projSessionID, "asked", command)
		}
		emitHook(hookResponse("ask", layer, d.Reasoning, command))
	}
}

// hookMemoryLookup is the former steps 2 and 4: session similarity (LLM
// compare) and the script cache. Returns true when it emitted a response.
func hookMemoryLookup(ctx context.Context, command, cwd, sessionID, projSessionID string, contentStale bool) bool {
	// Session similarity. Skipped when the content gate flagged this exact
	// command as stale — the identical string sits in the approved list,
	// so the compare would trivially answer "same command, allow" and
	// launder the stale approval right back in.
	if sessionID != "" && !contentStale {
		approved := ReadLines(projSessionID, approvedSuffix())
		candidates := filterByPrefix(command, approved)
		cfg := GetLLMConfig()
		cfg.Context = ctx
		// A decision model cannot answer a free-text compare; the command falls
		// through to the cache/classifier like any un-approved one.
		if len(candidates) > 0 && requireChatModel(cfg) == nil {
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
					saveApproved(projSessionID, command, cwd)
					LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session_llm", Decision: "allow", Short: d.Short, Reasoning: d.Reasoning, DurationMs: ms})
					emitHook(hookResponse("allow", "session_llm", d.Reasoning, command))
					return true
				}
			}
		}
	}

	// Script cache.
	cached, seen, notSeen := checkCacheWithScripts(command, cwd)
	if cached == nil {
		return false
	}
	// Route cached decisions through the risk map so cache + live LLM
	// paths apply the same policy. Older cache entries without a Risk
	// tier fall through with their original decision (no map applied).
	finalDecision, passthrough := applyRiskMap(ActiveHarness(), cached.Decision, cached.Risk)
	loggedDecision := finalDecision
	if passthrough {
		loggedDecision = ActionPassthrough
	}
	LogDecision(DecisionEntry{
		SessionID: sessionID, Command: command, Cwd: cwd, Layer: "cache",
		Decision: loggedDecision, OrigDecision: cached.Decision, Risk: cached.Risk, Confidence: cached.Confidence, Short: cached.Short,
		Reasoning: fmt.Sprintf("orig=%s → %s (cached) %s", cached.Decision, loggedDecision, cached.Reasoning),
		// A cache hit on a big-model-earned verdict must keep its
		// provenance — otherwise every replay looks like a plain
		// primary decision in the audit trail.
		Escalated: cached.Escalated, Attached: seen, Withheld: notSeen,
	})
	if passthrough {
		codexRecordPre(modSessionID, modCommand, modCwd, modRuleAction, "", "cache", "", true)
		emitHook("")
		return true
	}
	switch finalDecision {
	case "allow":
		if sessionID != "" {
			saveApproved(projSessionID, command, cwd)
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
	return true
}

// hookNoVerdict handles a chain that produced nothing: an oversize prompt
// applies the profile abstain action; a classifier failure emits the
// decisionless envelope so the host's own permission layer takes over.
func hookNoVerdict(jerr *judgeError, payload HookPayload, command, cwd, sessionID, projSessionID string) {
	if jerr != nil {
		cfg := LoadConfig()
		configured := cfg.Failure.Unavailable
		switch jerr.Kind {
		case judgeErrParse:
			configured = cfg.Failure.Parse
		case judgeErrOversize:
			configured = cfg.Failure.Oversize
		case judgeErrBudget:
			configured = cfg.Failure.Timeout
		}
		if configured != "" {
			emitFailure(cfg, payload, command, cwd, sessionID, projSessionID, jerr.Kind, jerr.Msg)
			return
		}
	}
	if jerr == nil {
		// Nothing configured that could decide — transparent.
		emitHook("")
		return
	}
	switch jerr.Kind {
	case judgeErrOversize, judgeErrBudget:
		// Do not ship an oversized prompt to any model. Apply the active
		// profile's abstain action (its critical policy, never more
		// permissive than ask) instead of silently deferring to the host —
		// which fails open on ask-less harnesses. Uncached: the oversized
		// content is exactly what we could not judge.
		act := failureAction(LoadConfig(), ActiveHarness(), judgeErrOversize)
		layer := "oversize"
		if jerr.Kind == judgeErrBudget {
			layer = "timeout"
			act = budgetAbstainAction(ActiveHarness())
		}
		reason := fmt.Sprintf("%s; profile abstain → %s", jerr.Msg, act)
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: layer, Decision: act, Reasoning: reason})
		if act == "deny" {
			emitHook(hookResponse("deny", layer, reason, command))
		} else { // abstainAction only ever returns deny or ask
			if sessionID != "" {
				AppendLine(projSessionID, "asked", command)
			}
			emitHook(hookResponse("ask", layer, reason, command))
		}
	case judgeErrParse:
		// When a custom system_prompt override is active, name it as the
		// likely cause and point at `verify` — this is the one signal a
		// wrongly-set override reliably surfaces at runtime.
		reason := "parse error"
		banner := "yolonot: 🧑‍🚀 LLM response parse error, falling back to host permissions"
		if jerr.Override {
			reason = "parse error (custom system_prompt override active)"
			banner = "yolonot: 🧑‍🚀 LLM reply unparseable — custom system_prompt may be malformed; run `yolonot prompt verify`. Falling back to host permissions"
		}
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: passthroughLayer(), Decision: "passthrough", Reasoning: reason, DurationMs: jerr.Verdict.Ms})
		r := HookResponse{}
		r.HookSpecificOutput.HookEventName = payload.HookEventName
		r.SystemMessage = banner
		emitHook(activeHarnessFormat(r))
	default:
		// LLM unavailable → decisionless envelope with the incoming
		// hookEventName so Claude Code's schema accepts it (permissionDecision
		// omitted via omitempty so CC defers to host permissions). The
		// systemMessage banner surfaces the failure in the user's terminal.
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: passthroughLayer(), Decision: "passthrough", Reasoning: "LLM unavailable: " + jerr.Msg, DurationMs: jerr.Verdict.Ms})
		r := HookResponse{}
		r.HookSpecificOutput.HookEventName = payload.HookEventName
		r.SystemMessage = "yolonot: 🧑‍🚀 LLM unreachable, falling back to host permissions"
		emitHook(activeHarnessFormat(r))
	}
}

// --- Script cache ---

func cacheDir() string {
	return filepath.Join(YolonotDir(), "cache")
}

// hashCollected keys the decision cache on the exact attached-script set
// BuildAnalyzePrompt shows the LLM, plus the identities of any withheld
// refs and the command. Hashing a script the classifier never saw (the old
// behavior for out-of-project paths) froze "ask" decisions against
// invisible content; folding in the withheld identities means swapping the
// decoy set that surrounds an attached script also invalidates the entry.
// Each file is framed with its path and length so boundary-shifted edits
// across multiple files can't collide. Returns "" (cache disabled) when
// nothing was attached.
func hashCollected(command string, attached []attachedScript, withheld []withheldScript) string {
	if len(attached) == 0 {
		return ""
	}
	// Refuse to cache when an in-root script was crowded out by the attach
	// cap: the classifier judged an incomplete view (only a note for that
	// script), so pinning an allow to the attached bytes would reuse the
	// decision for content the model never saw. A content change in the
	// crowded-out file would not change this key otherwise.
	for _, w := range withheld {
		if w.reason == whReasonCapReached {
			return ""
		}
	}
	h := sha256.New()
	for _, a := range attached {
		// Frame each file as path\0<full-file digest>. The digest is the
		// sha256 of the WHOLE attached content (files over the attach cap
		// are withheld, never truncated), so an edit anywhere changes the key.
		fmt.Fprintf(h, "%s\x00", a.ref.abs)
		h.Write(a.digest[:])
	}
	h.Write([]byte("\x01"))
	names := make([]string, 0, len(withheld))
	for _, w := range withheld {
		names = append(names, w.ref.raw)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(h, "%s\x00", n)
	}
	h.Write([]byte(command))
	if currentBypassSandbox {
		h.Write([]byte("\x00unsandboxed"))
	}
	sum := h.Sum(nil)
	return fmt.Sprintf("%x", sum[:8])
}

// scriptHash is the convenience form used by the pre-LLM cache read and by
// callers that don't already hold a collected snapshot.
func scriptHash(command, cwd string) string {
	attached, withheld := collectScripts(command, cwd)
	return hashCollected(command, attached, withheld)
}

// saveApproved records a session approval: the command line itself plus,
// when the command attaches script contents, the content-keyed hash into
// the .approvedhash session file. The hash is what keeps the session
// exact-match layer content-aware — an approval granted while a script
// held content X must not silently extend to content Y (the decision that
// earned the approval was made about X). The unwrapped inner form's hash
// is stored too, so a plain re-run of a wrapper-approved command still
// passes the content gate.
func saveApproved(projSessionID, command, cwd string) {
	_, hashes := modCommandSnapshot(command, cwd)
	saveApprovedSnapshot(projSessionID, command, hashes)
}

func approvalHashesFromCollected(command string, attached []attachedScript, withheld []withheldScript) []string {
	var hashes []string
	if hash := hashCollected(command, attached, withheld); hash != "" {
		hashes = append(hashes, hash)
	}
	if inner := UnwrapCommand(command, SessionWrappers()); inner != "" {
		if hash := hashCollected(inner, attached, withheld); hash != "" {
			hashes = append(hashes, hash)
		}
	}
	return hashes
}

func saveApprovedSnapshot(projSessionID, command string, hashes []string) {
	AppendLine(projSessionID, approvedSuffix(), command)
	for _, hash := range hashes {
		AppendLine(projSessionID, approvedHashSuffix(), hash)
	}
	dropLineOrVariant(projSessionID, "asked", command)
}

// sessionContentOK reports whether a session-approved command's attached
// script contents still match what was approved. Commands that attach no
// script content (h == "") carry no content stake — the string match is
// the whole story, as before. For attaching commands the current
// content-keyed hash must be present in .approvedhash; a missing hash
// (script edited since approval, or approval predates hashing) makes the
// session layer fall through so the cache/LLM re-judge the new contents.
func sessionContentOK(projSessionID, command, cwd string) bool {
	inner := UnwrapCommand(command, SessionWrappers())
	for _, form := range []string{command, inner} {
		if form != "" && !nativeSnapshotOK(projSessionID, form, cwd) {
			return false
		}
	}
	h := scriptHash(command, cwd)
	if h == "" && inner != "" {
		h = scriptHash(inner, cwd)
	}
	if h == "" {
		return true
	}
	return ContainsLine(projSessionID, approvedHashSuffix(), h)
}

func nativeSnapshotOK(projSessionID, command, cwd string) bool {
	identity, _ := nativeExecutableIdentity(command, cwd)
	prefix := executableApprovalPrefix(command)
	hadNativeSnapshot := false
	for _, hash := range ReadLines(projSessionID, approvedHashSuffix()) {
		if strings.HasPrefix(hash, prefix) {
			hadNativeSnapshot = true
			break
		}
	}
	if identity == "" && !hadNativeSnapshot {
		return true
	}
	return identity != "" && ContainsLine(projSessionID, approvedHashSuffix(), prefix+identity)
}

func checkCache(command, cwd string) *Decision {
	d, _, _ := checkCacheWithScripts(command, cwd)
	return d
}

// checkCacheWithScripts returns the cached decision for the command's
// current script snapshot, plus the attached and withheld script lists of
// that snapshot so a replay logs the same provenance as a live judge call.
func checkCacheWithScripts(command, cwd string) (*Decision, []string, []string) {
	attached, withheld := collectScripts(command, cwd)
	hash := hashCollected(command, attached, withheld)
	if hash == "" {
		return nil, nil, nil
	}
	seen, notSeen := describeCollected(attached, withheld)
	path := filepath.Join(cacheDir(), hash+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil
	}
	var entry cachedDecision
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, nil, nil
	}
	if entry.Context == "" || entry.Context != currentCacheContext(command, cwd) {
		return nil, nil, nil
	}
	return &entry.Decision, seen, notSeen
}

// runPreCheck invokes an external hook binary with the same JSON stdin
// Claude Code would send. Returns (parsed response, reason, ok) where ok
// is true only if the hook returned an "allow" permissionDecision. Any other
// outcome (ask/deny/empty/error/timeout) returns ok=false so yolonot's
// pipeline continues. The caller is responsible for re-serializing (and may
// mutate systemMessage before doing so — e.g. to brand the banner).
func runPreCheck(cmdPath string, input []byte) (*HookResponse, string, bool) {
	return runPreCheckContext(context.Background(), cmdPath, input)
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

func saveCache(command, cwd string, d *Decision) {
	saveCacheHash(scriptHash(command, cwd), d, currentCacheContext(command, cwd))
}

// saveCacheHash persists a decision under a precomputed script-cache key.
// A "" key (no attachable script) is a no-op.
func saveCacheHash(hash string, d *Decision, contextKey string) {
	if hash == "" || contextKey == "" || d == nil {
		return
	}
	dir := cacheDir()
	os.MkdirAll(dir, 0700)
	data, err := json.Marshal(cachedDecision{Decision: *d, Context: contextKey})
	if err != nil {
		return
	}
	cachePath := filepath.Join(dir, hash+".json")
	atomicWriteFile(cachePath, data, 0600)
}

// passthroughLayer attributes an unavailable-model passthrough to the first
// chat model in the chain, or "model" when the chain names none.
func passthroughLayer() string {
	if n := LoadConfig().ChatModelName(); n != "" {
		return n
	}
	return "model"
}
