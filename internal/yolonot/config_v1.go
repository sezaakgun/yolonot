package yolonot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Config v1: a model catalog ("models") that judges and escalation refer to
// by name. This file holds the judge list encoding, the v0 → v1 fold and the
// catalog lookups. Nothing here touches disk.

// JudgeList is the "judges" array. Each entry is a bare string ("fast_allow",
// "exec:/path", "<model name>") or an object {"use": ..., "may": [...]}; it
// marshals back to the string form whenever May is empty.
type JudgeList []JudgeSpec

func (l *JudgeList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("judges: expected an array")
	}
	out := make(JudgeList, 0, len(raw))
	for _, r := range raw {
		r = bytes.TrimSpace(r)
		if len(r) > 0 && r[0] == '"' {
			var s string
			if err := json.Unmarshal(r, &s); err != nil {
				return err
			}
			out = append(out, JudgeSpec{Use: s})
			continue
		}
		var sp JudgeSpec
		if err := json.Unmarshal(r, &sp); err != nil {
			return fmt.Errorf("judges: each entry is a string or {\"use\":...}")
		}
		out = append(out, sp)
	}
	*l = out
	return nil
}

func (l JudgeList) MarshalJSON() ([]byte, error) {
	items := make([]interface{}, len(l))
	for i, sp := range l {
		if len(sp.May) == 0 {
			items[i] = sp.Use
		} else {
			items[i] = sp
		}
	}
	return json.Marshal(items)
}

// Judge kinds. "typed" and "chat" are catalog models told apart by URL.
const (
	judgeFastAllow = "fast_allow"
	judgeExec      = "exec"
	judgeTyped     = "typed"
	judgeChat      = "chat"
	judgeUnknown   = "unknown"
)

// reservedJudgeNames cannot be model names: they are judge keywords or
// layer names in decisions.jsonl.
var reservedJudgeNames = map[string]bool{
	"fast_allow": true, "exec": true, "rule": true, "session": true, "session_deny": true,
	"session_llm": true, "cache": true, "human": true, "oversize": true, "pause": true,
	"passthrough": true, "unknown": true, "pre_check": true, "llm": true, "decision": true, "escalation": true, "timeout": true,
}

var modelNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]*$`)

// ValidModelName reports whether s can be a catalog key.
func ValidModelName(s string) error {
	if !modelNameRe.MatchString(s) {
		return fmt.Errorf("model name %q: use lowercase letters, digits, . _ : -", s)
	}
	if reservedJudgeNames[s] || strings.HasPrefix(s, "exec:") {
		return fmt.Errorf("model name %q is reserved", s)
	}
	return nil
}

// modelKey derives a catalog key from a model entry: the last path segment
// of the id, lowercased, invalid characters dropped. "google/gemini-2.5-
// flash-lite" → "gemini-2.5-flash-lite". On OpenRouter a ":variant" suffix
// (":free", ":nitro", ":thinking") is a routing tag, not a model, so it is
// dropped; elsewhere (ollama "gemma4:e4b") the tag names the model and stays.
func modelKey(m ModelConfig) string {
	k := strings.ToLower(m.Model)
	if i := strings.LastIndex(k, "/"); i >= 0 {
		k = k[i+1:]
	}
	if strings.Contains(m.URL, "openrouter.ai") {
		if i := strings.Index(k, ":"); i >= 0 {
			k = k[:i]
		}
	}
	k = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == ':' || r == '-' {
			return r
		}
		return -1
	}, k)
	k = strings.TrimLeft(k, "._:-")
	if ValidModelName(k) != nil {
		k = "model"
	}
	return k
}

// kindOf classifies a judge entry against the catalog.
func (c Config) kindOf(sp JudgeSpec) string {
	switch {
	case sp.Use == judgeFastAllow:
		return judgeFastAllow
	case strings.HasPrefix(sp.Use, "exec:"):
		return judgeExec
	}
	m, ok := c.Models[sp.Use]
	if !ok {
		return judgeUnknown
	}
	if isTypedModel(m) {
		return judgeTyped
	}
	return judgeChat
}

// JudgeSpecs returns the chain with kinds resolved.
func (c Config) JudgeSpecs() []JudgeSpec {
	out := make([]JudgeSpec, len(c.Judges))
	for i, sp := range c.Judges {
		sp.kind = c.kindOf(sp)
		out[i] = sp
	}
	return out
}

// ModelLLM resolves a catalog entry to a call config (key from env or the
// in-memory entry). Zero when the name is unknown.
func (c Config) ModelLLM(name string) LLMConfig {
	m, ok := c.Models[name]
	if !ok {
		return LLMConfig{}
	}
	key := m.APIKey
	if m.EnvKey != "" {
		if v := os.Getenv(m.EnvKey); v != "" {
			key = v
		}
	}
	return LLMConfig{URL: m.URL, Model: m.Model, ModelName: name, APIKeyEnv: m.EnvKey, APIKey: key, Timeout: m.Timeout, Protocol: m.Protocol}
}

// ChatModelName is the first chat model in the chain: the one used for
// session similarity, suggest, prompt review and the status line.
func (c Config) ChatModelName() string {
	for _, sp := range c.Judges {
		if c.kindOf(sp) == judgeChat {
			return sp.Use
		}
	}
	return ""
}

// ModelNames lists the catalog in a stable order.
func (c Config) ModelNames() []string {
	names := make([]string, 0, len(c.Models))
	for k := range c.Models {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// putModel stores a catalog entry, creating the map on a fresh config.
func (c *Config) putModel(name string, m ModelConfig) {
	if c.Models == nil {
		c.Models = map[string]ModelConfig{}
	}
	c.Models[name] = m
}

// addModel inserts m under a derived key, suffixing on collision with
// different call settings. Reusing an endpoint/model must not discard a
// stage's explicit timeout or credentials during legacy migration.
func (c *Config) addModel(m ModelConfig) string {
	if c.Models == nil {
		c.Models = map[string]ModelConfig{}
	}
	base := modelKey(m)
	key := base
	for i := 2; ; i++ {
		existing, ok := c.Models[key]
		if !ok {
			c.Models[key] = m
			return key
		}
		if existing.URL == m.URL && existing.Model == m.Model &&
			existing.Timeout == m.Timeout && existing.EnvKey == m.EnvKey && existing.APIKey == m.APIKey && existing.Protocol == m.Protocol {
			return key
		}
		key = fmt.Sprintf("%s-%d", base, i)
	}
}

// normalize folds v0 keys into the v1 fields and clears them. Idempotent;
// a v1 config passes through untouched. Sets Legacy when anything moved.
func (c *Config) normalize() {
	moved := false
	chat, typed := "", ""
	// v0 blocks missing url or model never ran; dropping them keeps a partial
	// block from becoming an invalid catalog model that denies every command.
	if c.Provider.URL != "" || c.Provider.Model != "" {
		if c.Provider.URL != "" && c.Provider.Model != "" {
			chat = c.addModel(c.Provider)
		}
		c.Provider = ProviderConfig{}
		moved = true
	}
	if c.Decision.URL != "" || c.Decision.Model != "" {
		if c.Decision.URL != "" && c.Decision.Model != "" {
			typed = c.addModel(c.Decision)
		}
		c.Decision = ProviderConfig{}
		moved = true
	}
	if c.Escalation != nil && (c.Escalation.Provider.URL != "" || c.Escalation.Provider.Model != "") {
		p := c.Escalation.Provider
		if p.URL == "" && chat != "" && !isTypedModel(c.Models[chat]) {
			// v0 inheritance: model-only escalation ran on the primary's endpoint.
			prim := c.Models[chat]
			p.URL = prim.URL
			if p.Timeout == 0 {
				p.Timeout = prim.Timeout
			}
			if p.EnvKey == "" && p.APIKey == "" {
				p.EnvKey, p.APIKey = prim.EnvKey, prim.APIKey
			}
		}
		esc := *c.Escalation
		if p.URL != "" && p.Model != "" {
			esc.Model = c.addModel(p)
		}
		esc.Provider = ProviderConfig{}
		c.Escalation = &esc
		moved = true
	}
	if len(c.PreCheck) > 0 || c.LocalAllow || (len(c.Judges) == 0 && (chat != "" || typed != "")) {
		var judges JudgeList
		if len(c.Judges) > 0 {
			judges = c.Judges
		} else {
			if c.LocalAllow && !hasString([]string(c.PreCheck), FastAllowSentinel) {
				judges = append(judges, JudgeSpec{Use: judgeFastAllow})
			}
			for _, p := range c.PreCheck {
				switch p {
				case "":
				case FastAllowSentinel:
					judges = append(judges, JudgeSpec{Use: judgeFastAllow})
				default:
					judges = append(judges, JudgeSpec{Use: "exec:" + p})
				}
			}
			if typed != "" {
				judges = append(judges, JudgeSpec{Use: typed})
			}
			if chat != "" {
				judges = append(judges, JudgeSpec{Use: chat})
			}
		}
		c.Judges = judges
		c.PreCheck, c.LocalAllow = nil, false
		moved = true
	}
	// v0 explicit judges used kind keywords; map them onto the catalog.
	if chat != "" || typed != "" {
		var kept JudgeList
		for _, sp := range c.Judges {
			switch sp.Use {
			case "llm":
				sp.Use = chat
			case "decision", "jev":
				sp.Use = typed
			case "escalation":
				continue
			}
			if sp.Use != "" {
				kept = append(kept, sp)
			}
		}
		c.Judges = kept
	}
	if cl := c.Classifier; len(cl.Context)+len(cl.AllowHints)+len(cl.AskHints) > 0 || cl.SystemPrompt != "" || cl.Impl != "" {
		if len(c.Prompt.Context)+len(c.Prompt.AllowHints)+len(c.Prompt.AskHints) == 0 && c.Prompt.SystemPrompt == "" {
			c.Prompt = PromptConfig{Context: cl.Context, AllowHints: cl.AllowHints, AskHints: cl.AskHints, SystemPrompt: cl.SystemPrompt}
		}
		c.Classifier = ClassifierConfig{}
		moved = true
	}
	if c.Profile != "" {
		if c.Policy.Profile == "" {
			c.Policy.Profile = c.Profile
		}
		c.Profile = ""
		moved = true
	}
	if len(c.CustomProfiles) > 0 {
		if c.Policy.Profiles == nil {
			c.Policy.Profiles = map[string]map[string]string{}
		}
		for k, v := range c.CustomProfiles {
			if _, ok := c.Policy.Profiles[k]; !ok {
				c.Policy.Profiles[k] = v
			}
		}
		c.CustomProfiles = nil
		moved = true
	}
	if len(c.ProfileOverride) > 0 || len(c.RiskMaps) > 0 {
		if c.Policy.Harness == nil {
			c.Policy.Harness = map[string]HarnessPolicy{}
		}
		for h, p := range c.ProfileOverride {
			hp := c.Policy.Harness[h]
			if hp.Profile == "" {
				hp.Profile = p
			}
			c.Policy.Harness[h] = hp
		}
		for h, m := range c.RiskMaps {
			hp := c.Policy.Harness[h]
			if hp.RiskMap == nil {
				hp.RiskMap = map[string]string{}
			}
			for tier, action := range m {
				if _, ok := hp.RiskMap[tier]; !ok {
					hp.RiskMap[tier] = action
				}
			}
			c.Policy.Harness[h] = hp
		}
		c.ProfileOverride, c.RiskMaps = nil, nil
		moved = true
	}
	if moved {
		c.Legacy = true
	}
}

func hasString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// harnessPolicy returns the pin block for a harness (zero when none).
func (c Config) harnessPolicy(h string) HarnessPolicy {
	if c.Policy.Harness == nil {
		return HarnessPolicy{}
	}
	return c.Policy.Harness[h]
}

// setHarnessPolicy writes back a pin block, dropping it when empty.
func (c *Config) setHarnessPolicy(h string, hp HarnessPolicy) {
	if hp.Profile == "" && len(hp.RiskMap) == 0 {
		delete(c.Policy.Harness, h)
		if len(c.Policy.Harness) == 0 {
			c.Policy.Harness = nil
		}
		return
	}
	if c.Policy.Harness == nil {
		c.Policy.Harness = map[string]HarnessPolicy{}
	}
	c.Policy.Harness[h] = hp
}

// isModelLayer reports whether a decisions.jsonl layer names a model
// verdict (v1: the catalog name, v0: "llm"), as opposed to a fixed layer.
func isModelLayer(layer string) bool {
	layer = strings.TrimSuffix(layer, "+esc")
	if layer == "" || reservedJudgeNames[layer] && layer != "llm" && layer != "decision" {
		return false
	}
	return !strings.HasPrefix(layer, "exec:") && !strings.HasPrefix(layer, "pre_check")
}
