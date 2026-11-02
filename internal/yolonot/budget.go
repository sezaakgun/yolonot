package yolonot

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

// Installed harness hooks have a 60-second limit. Leave five seconds for
// process teardown, decision logging and writing a response to the host.
const hookDecisionBudget = 55 * time.Second

// hookBudgetContext uses an absolute deadline so a fallback judge cannot
// restart the budget spent by earlier judges or the similarity lookup.
func hookBudgetContext(parent context.Context, start time.Time) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if start.IsZero() {
		start = time.Now()
	}
	budget := hookDecisionBudget
	if seconds := LoadConfig().HookTimeout; seconds > 0 && seconds <= 55 {
		budget = time.Duration(seconds) * time.Second
	}
	return context.WithDeadline(parent, start.Add(budget))
}

func budgetJudgeError() *judgeError {
	return &judgeError{Kind: judgeErrBudget, Msg: "hook decision time budget exhausted"}
}

func budgetAbstainAction(h Harness) string {
	action := abstainAction(h)
	if action == ActionAsk && !harnessSupportsAsk(h) {
		// The other shipped adapters cannot create a native ask. Returning
		// ask there could become a permissive passthrough or allow.
		return ActionDeny
	}
	return action
}

func runPreCheckContext(parent context.Context, command string, input []byte) (*HookResponse, string, bool) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil, "", false
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	// A child's inherited output pipe must not hold the hook indefinitely
	// after the direct pre-check process is killed at its deadline.
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil, "", false
	}
	var response HookResponse
	if json.Unmarshal(bytes.TrimSpace(out), &response) != nil || response.HookSpecificOutput.PermissionDecision != ActionAllow {
		return nil, "", false
	}
	reason := response.HookSpecificOutput.PermissionDecisionReason
	if reason == "" {
		reason = "allowed by pre-check hook"
	}
	return &response, reason, true
}
