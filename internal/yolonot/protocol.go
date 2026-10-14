package yolonot

import "strings"

func validProtocol(p string) bool {
	switch p {
	case "", "chat", "anthropic", "claude-cli", "systemone", "decisions", "workers-ai":
		return true
	}
	return false
}

func inferProtocol(url string) string {
	switch {
	case url == "claude-cli":
		return "claude-cli"
	case strings.Contains(url, "anthropic"):
		return "anthropic"
	case isOpenAIDecisionsURL(url):
		return "decisions"
	case isWorkersAIClefURL(url):
		return "workers-ai"
	case isDecisionURL(url):
		return "systemone"
	default:
		return "chat"
	}
}

func modelProtocol(m ModelConfig) string {
	if m.Protocol != "" {
		return m.Protocol
	}
	return inferProtocol(m.URL)
}
func isTypedModel(m ModelConfig) bool { return typedProtocol(modelProtocol(m)) }
func typedProtocol(p string) bool     { return p == "systemone" || p == "decisions" || p == "workers-ai" }
func llmProtocol(c LLMConfig) string {
	if c.Protocol != "" {
		return c.Protocol
	}
	return inferProtocol(c.URL)
}
func isDecisionConfig(c LLMConfig) bool        { return typedProtocol(llmProtocol(c)) }
func isOpenAIDecisionsConfig(c LLMConfig) bool { return llmProtocol(c) == "decisions" }
