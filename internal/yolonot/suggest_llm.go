package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// suggestCallLLM is the indirection used by smart-suggest, mirroring
// evalCallLLM and reviewCallLLM. Production code path = CallLLM; tests
// swap it via t.Cleanup. Pattern is the same across all three: the
// underlying API stays exported and unchanged for direct callers.
var suggestCallLLM = CallLLM

// SmartSuggestion is the structured recommendation returned by the LLM
// for one evolveFinding. Action is one of:
//
//	allow-hint, ask-hint, allow-cmd, deny-cmd, ask-cmd, skip
//
// Text is either:
//   - prose body for *-hint actions
//   - glob pattern for *-cmd actions
//   - ignored for skip
//
// Reason is a one-line justification the user sees in the TUI so they
// can decide whether to trust the recommendation without re-reading
// the examples themselves.
type SmartSuggestion struct {
	Action string `json:"action"`
	Text   string `json:"text"`
	Reason string `json:"reason"`
}

// suggestSystemPrompt is the meta-prompt for smart-suggest. It binds
// the LLM to the same vocabulary the rest of yolonot uses (allow/ask/
// deny + hint vs cmd) and forces JSON output for parser stability.
const suggestSystemPrompt = `You are auditing a recurring command pattern from a developer's shell history.
The pattern was repeatedly flagged for confirmation, indicating the developer
either keeps approving it (and a rule could remove the prompt) or keeps
asking themselves whether it is safe (and a hint could document the answer).

Given the bucket name and example commands, pick the smallest, safest, most
useful next step.

Available actions:
  allow-hint  Prose telling the safety classifier this pattern is routine. Use
              when the bucket mixes specific shapes that look risky but are
              actually safe in context (e.g. "uv run python -c reading config
              files is read-only inspection").
  ask-hint    Prose telling the classifier to always ask. Use when the bucket
              mixes shapes that *might* be safe but the developer wants
              confirmation every time.
  allow-cmd   Exact glob pattern auto-allows future matches. Use ONLY when the
              bucket is a single command shape with no risky siblings. Risk: a
              wildcard glob may match destructive ops you didn't see in the
              examples.
  deny-cmd    Exact glob pattern blocks future matches. Use when the bucket is
              consistently dangerous and the developer is asking by mistake.
  ask-cmd     Glob that forces a prompt even if the pattern would be allowed.
              Use for sensitive-but-routine patterns where the prompt is the
              point.
  skip        No recommendation fits; leave the bucket alone.

PREFER hint over cmd when the examples show varied resources, namespaces, or
flags — a glob would either over-allow destructive siblings or block useful
reads. Examples bucketed under "kubectl delete deployment" with varied
target names and namespaces are a hint case, not a glob case.

PREFER cmd only when the examples are tightly identical AND clearly safe or
clearly dangerous. A bucket like "git status" is allow-cmd; "rm -rf $HOME" is
deny-cmd.

Output ONLY JSON: {"action": "<one of the six>", "text": "<prose or glob>", "reason": "<one short line>"}`

// suggestSmart asks the configured LLM to recommend an action for one
// finding. Falls through silently (returns zero-value, ok=false) when:
//   - no LLM provider is configured (offline use)
//   - the LLM call fails for any reason
//   - the response can't be parsed
//
// On any of these the caller falls back to the manual TUI options.
// This is the right failure mode: smart-suggest is opt-in convenience,
// not load-bearing safety.
func suggestSmart(f evolveFinding) (SmartSuggestion, bool) {
	llm := GetLLMConfig()
	if llm.URL == "" || llm.Model == "" {
		return SmartSuggestion{}, false
	}

	user := buildSuggestUserPrompt(f)
	raw, err := suggestCallLLM(llm, suggestSystemPrompt, user, 400)
	if err != nil {
		Verbosef("smart-suggest LLM error for %q: %v", f.Pattern, err)
		return SmartSuggestion{}, false
	}
	s, ok := parseSmartSuggestion(raw)
	if !ok {
		Verbosef("smart-suggest unparseable response for %q: %s", f.Pattern, raw)
		return SmartSuggestion{}, false
	}
	return s, true
}

func buildSuggestUserPrompt(f evolveFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Bucket pattern: %q\n", f.Pattern)
	fmt.Fprintf(&b, "Occurrences: %d (weighted %.1f)\n\n", f.Count, f.Weighted)
	b.WriteString("Example commands:\n")
	for _, ex := range f.Examples {
		cmd := ex
		if len(cmd) > 180 {
			cmd = cmd[:177] + "..."
		}
		fmt.Fprintf(&b, "  - %s\n", cmd)
	}
	return b.String()
}

// parseSmartSuggestion tolerates the same model quirks ParseDecision
// does — code-fence wrappers and trailing prose around the JSON object.
// We don't accept malformed action values: an unknown action returns
// ok=false so the user falls back to manual selection rather than the
// TUI defaulting to a nonsensical "deny-cmd" or similar.
func parseSmartSuggestion(text string) (SmartSuggestion, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return SmartSuggestion{}, false
	}
	// Strip a leading ```json fence if present.
	if strings.HasPrefix(text, "```") {
		if i := strings.Index(text, "\n"); i > 0 {
			text = text[i+1:]
		}
		if j := strings.LastIndex(text, "```"); j > 0 {
			text = text[:j]
		}
	}
	// Locate the JSON object (the model sometimes adds prose around it).
	idx := strings.Index(text, `"action"`)
	if idx < 0 {
		return SmartSuggestion{}, false
	}
	start := strings.LastIndex(text[:idx], "{")
	if start < 0 {
		return SmartSuggestion{}, false
	}
	depth := 0
	for i := start; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				var s SmartSuggestion
				if err := json.Unmarshal([]byte(text[start:i+1]), &s); err != nil {
					return SmartSuggestion{}, false
				}
				if !isValidSuggestAction(s.Action) {
					return SmartSuggestion{}, false
				}
				return s, true
			}
		}
	}
	return SmartSuggestion{}, false
}

func isValidSuggestAction(a string) bool {
	switch a {
	case "allow-hint", "ask-hint", "allow-cmd", "deny-cmd", "ask-cmd", "skip":
		return true
	}
	return false
}

// suggestCache persists previous LLM judgments keyed by pattern. Most
// users invoke `yolonot suggest` repeatedly during a tuning session;
// without the cache, every re-run pays the full per-finding LLM
// roundtrip for findings the user already inspected.
type suggestCache struct {
	Patterns map[string]cachedSuggestion `json:"patterns"`
}

type cachedSuggestion struct {
	Action string `json:"action"`
	Text   string `json:"text"`
	Reason string `json:"reason"`
	TS     string `json:"ts"`
}

func suggestCachePath() string {
	return filepath.Join(YolonotDir(), "suggest-cache.json")
}

func loadSuggestCache() suggestCache {
	c := suggestCache{Patterns: map[string]cachedSuggestion{}}
	data, err := os.ReadFile(suggestCachePath())
	if err != nil {
		return c
	}
	_ = json.Unmarshal(data, &c)
	if c.Patterns == nil {
		c.Patterns = map[string]cachedSuggestion{}
	}
	return c
}

func saveSuggestCache(c suggestCache) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		Verbosef("suggest cache marshal: %v", err)
		return
	}
	_ = atomicWriteFile(suggestCachePath(), append(data, '\n'), 0600)
}

// cachedOrSmart returns the smart suggestion for f, consulting the
// on-disk cache before calling the LLM. Writes the cache eagerly on
// each new judgment so a Ctrl+C mid-session doesn't lose progress.
// The cache TTL is 30 days; older entries are ignored and refreshed.
func cachedOrSmart(f evolveFinding, cache *suggestCache) (SmartSuggestion, bool) {
	if entry, ok := cache.Patterns[f.Pattern]; ok {
		if isCacheFresh(entry.TS) {
			return SmartSuggestion{Action: entry.Action, Text: entry.Text, Reason: entry.Reason}, true
		}
	}
	s, ok := suggestSmart(f)
	if !ok {
		return s, false
	}
	cache.Patterns[f.Pattern] = cachedSuggestion{
		Action: s.Action,
		Text:   s.Text,
		Reason: s.Reason,
		TS:     time.Now().UTC().Format(time.RFC3339),
	}
	saveSuggestCache(*cache)
	return s, true
}

// truncateForDisplay trims a string for TUI labels so long prose or
// glob patterns don't wrap into terminal noise. Adds ... when cut.
func truncateForDisplay(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// smartActionToRule turns a SmartSuggestion into the literal text we
// append to .yolonot / ~/.yolonot/rules. Hint actions quote the prose
// text; cmd actions use the glob verbatim. "skip" returns "" so the
// caller drops it.
func smartActionToRule(s SmartSuggestion) string {
	switch s.Action {
	case "allow-hint", "ask-hint":
		if s.Text == "" {
			return ""
		}
		return fmt.Sprintf("%s %q", s.Action, s.Text)
	case "allow-cmd", "deny-cmd", "ask-cmd":
		if s.Text == "" {
			return ""
		}
		return fmt.Sprintf("%s %s", s.Action, s.Text)
	case "skip":
		return ""
	}
	return ""
}

// pickEvolveScopeWithDefault prompts the user for project vs global
// scope. Default leans global for deny/ask actions (which are usually
// company-wide policy) and project for allow actions (which are
// usually project-specific). Empty return = user cancelled.
func pickEvolveScopeWithDefault(action string) string {
	def := 0 // project
	switch action {
	case "deny-cmd", "ask-cmd", "ask-hint":
		def = 1 // global
	}
	idx := tuiSelect("Scope", []string{
		"project (.yolonot)",
		"global (~/.yolonot/rules)",
	}, def)
	if idx < 0 {
		return ""
	}
	if idx == 1 {
		return "g"
	}
	return "p"
}

// isCacheFresh returns true if the timestamp is within the cache TTL.
// 30 days is long enough that a tuning session doesn't pay repeated
// LLM costs, short enough that stale judgments don't pin behaviour
// against an updated meta-prompt or model.
func isCacheFresh(ts string) bool {
	if ts == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return false
	}
	return time.Since(t) < 30*24*time.Hour
}
