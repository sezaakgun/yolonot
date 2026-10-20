package yolonot

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// Cache entries are valid only for the configuration and resolved hints the
// deciding model saw. Credentials are never included in persisted metadata.
func classifierContextFingerprint(cfg Config, hints WalkupHints, command, cwd string) string {
	models := map[string]ModelConfig{}
	for name, m := range cfg.Models {
		m.APIKey = ""
		models[name] = m
	}
	data, _ := json.Marshal(struct {
		Revision   int
		Root       string
		Models     map[string]ModelConfig
		Judges     JudgeList
		Escalation *EscalationConfig
		Policy     PolicyConfig
		System     string
		TypedHints string
		Attach     bool
		Wrappers   []string
		Failure    FailurePolicy
		Sensitive  []string
		ProjectCtx string
		UserPrompt string
	}{4, projectRoot(cwd), models, cfg.Judges, cfg.Escalation, cfg.Policy, BuildSystemPrompt(cfg.Prompt, hints), DecisionHints(cfg.Prompt, hints), cfg.AttachOutsideRoot, cfg.Wrappers, cfg.Failure, LoadSensitivePatterns(cwd), detectProjectContext(command, cwd), formatUserSessionPrompt(extractTranscriptUserPrompt(currentTranscriptPath))})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func currentCacheContext(command, cwd string) string {
	cfg := LoadConfig()
	if cfg.LoadError != nil {
		return ""
	}
	hints := LoadHints(cwd)
	return classifierContextFingerprint(cfg, hints, command, cwd)
}

type cachedDecision struct {
	Decision
	Context string `json:"cache_context"`
}
