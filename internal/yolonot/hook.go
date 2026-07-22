package yolonot

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
	PermissionMode string                 `json:"permission_mode,omitempty"` // Claude Code only
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
	// Wall-clock anchor for the escalation budget guard — harnesses kill
	// hooks around 60s, so late escalation calls are skipped, not risked.
	hookStart := time.Now()

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
	currentPermissionMode = payload.PermissionMode

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

	// Claude Code --dangerously-skip-permissions — total bypass, same shape
	// as YOLONOT_DISABLED. User asked the host to skip its own permission
	// engine; yolonot honors that and stays out of the way. Post writes are
	// gated too so resuming a normal session doesn't reveal a pile of
	// "pre-approved" commands yolonot never vetted.
	if payload.PermissionMode == "bypassPermissions" {
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

	// Load config once — used by pre-check, risk-map resolution, quiet-on-
	// allow banner suppression, and the script-attach boundary. Keeps disk
	// reads down to one per hook invocation. Loaded BEFORE the PostToolUse
	// branch: saveApproved hashes attached script contents, so the attach
	// boundary (attachOutsideRoot) must match what PreToolUse used —
	// otherwise open-mode approvals for outside-root scripts never stick.
	config := LoadConfig()
	quietOnAllow = config.QuietOnAllow
	attachOutsideRoot = config.AttachOutsideRoot
	// Register user-defined wrappers (Config.Wrappers) with fast_allow so
	// `mycli ls` unwraps to `ls`. Idempotent — safe to call every hook.
	fastallow.AddWrappers(config.Wrappers...)

	// PostToolUse: command ran → user approved → save to .approved (plus
	// the content hash of any attached scripts, so the approval stays
	// pinned to the contents the user actually saw run).
	if payload.HookEventName == "PostToolUse" {
		if sessionID != "" && command != "" {
			// Human verdict: this run resolves a pending ask. The command
			// sits on the asked list with no approval recorded yet, and
			// PostToolUse means the user answered yes — log that as a
			// layer:"human" entry so decision history carries real user
			// answers, not just yolonot's own verdicts. Commands that were
			// auto-allowed (never asked) or already approved this session
			// don't produce one.
			if MatchesLineOrWrappedVariant(projSessionID, "asked", command) &&
				!MatchesLineOrWrappedVariant(projSessionID, "approved", command) {
				LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "human", Decision: "allow", Source: "ask_approved"})
			}
			saveApproved(projSessionID, command, cwd)
		}
		return
	}

	// --- PreToolUse pipeline ---

	if command == "" {
		return
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
			saveApproved(projSessionID, command, cwd)
		}
		emitHook(hookResponse("allow", "rule", userReason, command))
		return
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
	if sessionID != "" && MatchesLineOrWrappedVariant(projSessionID, "approved", command) {
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
			if !ContainsLine(projSessionID, "approved", command) {
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
		if MatchesLineOrWrappedVariant(projSessionID, "denied", command) {
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
				// Same content gate as step 0.5. Stale contents fall through
				// to re-judging — NOT to the denied branch below: an edited
				// script is new evidence, not a prior user rejection.
				if sessionContentOK(projSessionID, command, cwd) {
					saveApproved(projSessionID, command, cwd)
					LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session", Decision: "allow", Source: "wrapped_variant"})
					emitHook(hookResponse("allow", "session", "previously approved as wrapped command this session", command))
					return
				}
				Verbosef("session: wrapper-approved command %q has changed script contents; re-judging", command)
			} else {
				AppendLine(projSessionID, "denied", command)
				// Human verdict (inferred): we asked, no PostToolUse ever
				// recorded an approval, and the agent is retrying the same
				// command — the user answered no. Logged as its own
				// layer:"human" entry (alongside the session_deny gate entry
				// below) so history mining sees the rejection the moment we
				// can infer it. Weaker than ask_approved: a rejection where
				// the agent never retries is never observed.
				LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "human", Decision: "deny", Source: "ask_rejected"})
				LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session_deny", Decision: "deny", Source: "asked_not_approved"})
				emitHook(hookResponse("deny", "session_deny", "previously rejected this session", command))
				return
			}
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
			if ok, reason := fastallow.IsLocallySafeWith(command, AllowRedirectPatterns(rules)); ok {
				if sessionID != "" {
					saveApproved(projSessionID, command, cwd)
				}
				LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "fast_allow", Decision: "allow", Reasoning: reason})
				emitHook(hookResponse("allow", "fast_allow", reason, command))
				return
			}
			continue
		}
		if _, reason, ok := runPreCheck(preCheck, canonicalInput); ok {
			if sessionID != "" {
				saveApproved(projSessionID, command, cwd)
			}
			LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "pre_check", Decision: "allow", Reasoning: reason})
			layer := "pre_check (" + preCheckShortName(preCheck) + ")"
			emitHook(hookResponse("allow", layer, reason, command))
			return
		}
	}

	// Step 2: Session similarity (LLM compare). Skipped when the content
	// gate flagged this exact command as stale — the identical string sits
	// in the approved list, so the compare would trivially answer "same
	// command, allow" and launder the stale approval right back in.
	if sessionID != "" && !contentStale {
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
					saveApproved(projSessionID, command, cwd)
					LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "session_llm", Decision: "allow", Short: d.Short, Reasoning: d.Reasoning, DurationMs: ms})
					emitHook(hookResponse("allow", "session_llm", d.Reasoning, command))
					return
				}
			}
		}
	}

	// Step 4: Script cache check
	if cached := checkCache(command, cwd); cached != nil {
		// Route cached decisions through the risk map so cache + live LLM
		// paths apply the same policy. Older cache entries without a Risk
		// tier fall through with their original decision (no map applied).
		finalDecision, passthrough := applyRiskMap(ActiveHarness(), cached.Decision, cached.Risk)
		LogDecision(DecisionEntry{
			SessionID: sessionID, Command: command, Cwd: cwd, Layer: "cache",
			Decision: finalDecision, Risk: cached.Risk, Confidence: cached.Confidence, Short: cached.Short,
			Reasoning: fmt.Sprintf("orig=%s → %s (cached) %s", cached.Decision, finalDecision, cached.Reasoning),
			// A cache hit on a big-model-earned verdict must keep its
			// provenance — otherwise every replay looks like a plain
			// primary decision in the audit trail.
			Escalated: cached.Escalated,
		})
		if passthrough {
			emitHook("")
			return
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
		return
	}

	// Step 5: LLM analysis. Collect the referenced scripts ONCE so the
	// prompt the LLM sees and the cache key we later persist are computed
	// from the same filesystem snapshot — re-reading after the round-trip
	// could hash bytes the classifier never judged.
	cfg := GetLLMConfig()
	attachedScripts, withheldScripts := collectScripts(command, cwd)
	userPrompt := buildPromptFromCollected(command, attachedScripts, withheldScripts)

	// Oversize guard: if the assembled prompt exceeds the budget, do not ship
	// it to the LLM. Apply the active profile's abstain action (its critical
	// policy, never more permissive than ask) instead of silently deferring
	// to the host — which fails open on ask-less harnesses. Uncached: the
	// oversized content is exactly what we could not judge.
	if len(userPrompt) > maxClassifierPromptBytes {
		act := abstainAction(ActiveHarness())
		reason := fmt.Sprintf("classifier prompt %d KB exceeds %d KB budget; profile abstain → %s",
			len(userPrompt)/1024, maxClassifierPromptBytes/1024, act)
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "oversize", Decision: act, Reasoning: reason})
		if act == "deny" {
			emitHook(hookResponse("deny", "oversize", reason, command))
		} else { // abstainAction only ever returns deny or ask
			if sessionID != "" {
				AppendLine(projSessionID, "asked", command)
			}
			emitHook(hookResponse("ask", "oversize", reason, command))
		}
		return
	}

	cacheKey := hashCollected(command, attachedScripts, withheldScripts)
	start := time.Now()
	// Augment the base prompt with the user's classifier hints — the
	// classifier block from config.json plus context/allow-hint/ask-hint
	// directives from the .yolonot walk-up chain. Must stay in sync with
	// cmdCheck: if this passes the bare SystemPrompt const, `yolonot check`
	// reports decisions the hook will not actually make.
	hints := LoadHints()
	sysPrompt := BuildSystemPrompt(config.Classifier, hints)
	// A full base-prompt override is the most likely cause of an
	// unparseable reply (a malformed custom prompt), so remember it for the
	// parse-error banner below — the reactive backstop to `classifier verify`.
	overrideActive := HasSystemPromptOverride(config.Classifier, hints)
	text, err := CallLLM(cfg, sysPrompt, userPrompt, 4096)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		// LLM unavailable → emit decisionless envelope with the
		// incoming hookEventName so Claude Code's schema accepts it
		// (literal match on hookEventName, permissionDecision omitted
		// via omitempty so CC defers to host permissions). The
		// systemMessage banner surfaces the failure in the user's
		// terminal. Codex/Cursor/Gemini adapters short-circuit on
		// empty PermissionDecision and emit "" — banner is Claude/
		// OpenCode-only by design.
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "llm", Decision: "passthrough", Reasoning: "LLM unavailable: " + err.Error(), DurationMs: ms})
		r := HookResponse{}
		r.HookSpecificOutput.HookEventName = payload.HookEventName
		r.SystemMessage = "yolonot: 🧑‍🚀 LLM unreachable, falling back to host permissions"
		emitHook(activeHarnessFormat(r))
		return
	}

	d := ParseDecision(text)
	if d == nil {
		// Parse error → same envelope shape as LLM-unreachable, with
		// a parse-specific banner. When a custom system_prompt override is
		// active, name it as the likely cause and point at `verify` — this
		// is the one signal a wrongly-set override reliably surfaces at
		// runtime (Verbosef is -v-only and invisible on the hook path).
		reason := "parse error"
		banner := "yolonot: 🧑‍🚀 LLM response parse error, falling back to host permissions"
		if overrideActive {
			reason = "parse error (custom system_prompt override active)"
			banner = "yolonot: 🧑‍🚀 LLM reply unparseable — custom system_prompt may be malformed; run `yolonot classifier verify`. Falling back to host permissions"
		}
		LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: "llm", Decision: "passthrough", Reasoning: reason, DurationMs: ms})
		r := HookResponse{}
		r.HookSpecificOutput.HookEventName = payload.HookEventName
		r.SystemMessage = banner
		emitHook(activeHarnessFormat(r))
		return
	}

	// Escalation: when the primary verdict is uncertain in a way a second,
	// bigger model could improve, consult it once and adopt under the
	// guardrails in maybeEscalate. Mutates d on adoption, so the cache
	// write below persists the post-adoption verdict (with provenance) and
	// the risk map resolves the adopted tier like any other.
	escOut, escCacheOK := maybeEscalate(ActiveHarness(), config, d, sysPrompt, userPrompt, hookStart)

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
		saveCacheHash(cacheKey, d)
	}

	entry := DecisionEntry{
		SessionID: sessionID, Command: command, Cwd: cwd, Layer: "llm",
		Decision: finalDecision, Risk: d.Risk, Confidence: d.Confidence, Short: d.Short,
		Reasoning:  fmt.Sprintf("orig=%s → %s %s", d.Decision, finalDecision, d.Reasoning),
		DurationMs: ms,
	}
	escalationLogFields(&entry, escOut)
	if unresolvedReason != "" {
		entry.Reasoning = unresolvedReason + " | " + entry.Reasoning
	}
	LogDecision(entry)

	if passthrough {
		emitHook("")
		return
	}
	layer := "llm"
	if d.Escalated {
		layer = "llm+esc"
	}
	switch finalDecision {
	case "allow":
		if sessionID != "" {
			saveApproved(projSessionID, command, cwd)
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
	AppendLine(projSessionID, "approved", command)
	if h := scriptHash(command, cwd); h != "" {
		AppendLine(projSessionID, "approvedhash", h)
	}
	if inner := UnwrapCommand(command, SessionWrappers()); inner != "" {
		if h := scriptHash(inner, cwd); h != "" {
			AppendLine(projSessionID, "approvedhash", h)
		}
	}
}

// sessionContentOK reports whether a session-approved command's attached
// script contents still match what was approved. Commands that attach no
// script content (h == "") carry no content stake — the string match is
// the whole story, as before. For attaching commands the current
// content-keyed hash must be present in .approvedhash; a missing hash
// (script edited since approval, or approval predates hashing) makes the
// session layer fall through so the cache/LLM re-judge the new contents.
func sessionContentOK(projSessionID, command, cwd string) bool {
	h := scriptHash(command, cwd)
	if h == "" {
		if inner := UnwrapCommand(command, SessionWrappers()); inner != "" {
			h = scriptHash(inner, cwd)
		}
	}
	if h == "" {
		return true
	}
	return ContainsLine(projSessionID, "approvedhash", h)
}

func checkCache(command, cwd string) *Decision {
	hash := scriptHash(command, cwd)
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

func saveCache(command, cwd string, d *Decision) {
	saveCacheHash(scriptHash(command, cwd), d)
}

// saveCacheHash persists a decision under a precomputed script-cache key.
// A "" key (no attachable script) is a no-op.
func saveCacheHash(hash string, d *Decision) {
	if hash == "" {
		return
	}
	dir := cacheDir()
	os.MkdirAll(dir, 0700)
	data, err := json.Marshal(d)
	if err != nil {
		return
	}
	cachePath := filepath.Join(dir, hash+".json")
	os.WriteFile(cachePath, data, 0600)
	os.Chmod(cachePath, 0600)
}
