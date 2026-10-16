package yolonot

import "fmt"

func failureActionLabel(action string) string {
	switch action {
	case ActionPassthrough:
		return "PASS-THROUGH"
	case ActionAsk:
		return "ASK"
	default:
		return "DENY"
	}
}

func harnessSupportsAsk(h Harness) bool {
	if h == nil {
		return false
	}
	if capability, ok := h.(interface{ SupportsAsk() bool }); ok {
		return capability.SupportsAsk()
	}
	switch h.Name() {
	case "claude", "gemini", "antigravity":
		return true
	}
	return false
}

func failureAction(cfg Config, h Harness, kind string) string {
	var action string
	switch kind {
	case "invalid_config":
		action = cfg.Failure.InvalidConfig
		if action == "" {
			action = ActionDeny
		}
	case judgeErrParse:
		action = cfg.Failure.Parse
	case judgeErrUnavailable:
		action = cfg.Failure.Unavailable
	case judgeErrOversize:
		action = cfg.Failure.Oversize
		if action == "" {
			action = abstainAction(h)
		}
	case judgeErrBudget:
		action = cfg.Failure.Timeout
		if action == "" {
			action = budgetAbstainAction(h)
		}
	}
	if action == "" {
		action = ActionPassthrough
	}
	if action == ActionAsk && !harnessSupportsAsk(h) {
		return ActionDeny
	}
	if action != ActionAsk && action != ActionDeny && action != ActionPassthrough {
		return ActionDeny
	}
	return action
}

func emitFailure(cfg Config, p HookPayload, command, cwd, sessionID, project, kind, message string) {
	action := failureAction(cfg, ActiveHarness(), kind)
	layer := kind
	if kind == judgeErrBudget {
		layer = "timeout"
	}
	reason := fmt.Sprintf("%s; failure policy → %s", message, action)
	LogDecision(DecisionEntry{SessionID: sessionID, Command: command, Cwd: cwd, Layer: layer, Decision: action, Reasoning: reason})
	if action == ActionAsk && sessionID != "" {
		AppendLine(project, "asked", command)
	}
	if action == ActionPassthrough {
		r := HookResponse{}
		r.HookSpecificOutput.HookEventName = p.HookEventName
		r.SystemMessage = "yolonot: " + sanitizeBanner(reason)
		emitHook(activeHarnessFormat(r))
		return
	}
	emitHook(hookResponse(action, layer, reason, command))
}
