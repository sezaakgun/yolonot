package yolonot

import (
	"fmt"
	"strconv"
)

func editFailures(cfg *Config) {
	values := []string{"", ActionDeny, ActionAsk, ActionPassthrough}
	labels := []string{"Default", "Deny", "Ask (deny when unsupported)", "Defer to host permissions"}
	fields := []menuField{}
	current := []string{cfg.Failure.Unavailable, cfg.Failure.Parse, cfg.Failure.InvalidConfig, cfg.Failure.Oversize, cfg.Failure.Timeout}
	for i, name := range []string{"Provider unavailable", "Invalid model response", "Invalid configuration", "Oversized prompt", "Decision deadline"} {
		fields = append(fields, menuField{Title: name, Items: labels, Cur: indexOf(values, current[i])})
	}
	chosen, ok := runMenu("Failure behavior", "↑↓ choose  ⏎ next  esc cancel", fields)
	if !ok {
		return
	}
	cfg.Failure = FailurePolicy{Unavailable: values[chosen[0].Cur], Parse: values[chosen[1].Cur], InvalidConfig: values[chosen[2].Cur], Oversize: values[chosen[3].Cur], Timeout: values[chosen[4].Cur]}
}

func editPositiveSetting(title string, current, maximum int, set func(int)) {
	value := tuiInput(title, fmt.Sprint(current), fmt.Sprint(current))
	if value == "" {
		return
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 || (maximum > 0 && n > maximum) {
		tuiNote("Not changed", "enter a nonnegative number within the allowed range")
		return
	}
	set(n)
}

func editModelProtocol(cfg *Config, name string) {
	values := []string{"", "chat", "anthropic", "claude-cli", "systemone", "decisions", "workers-ai"}
	labels := []string{"Auto (legacy URL inference)", "OpenAI-compatible chat", "Anthropic Messages", "Claude CLI", "System One typed decisions", "OpenAI Decisions", "Workers AI typed decisions"}
	m := cfg.Models[name]
	i := tuiSelect("Protocol for "+name, labels, indexOf(values, m.Protocol))
	if i < 0 {
		return
	}
	m.Protocol = values[i]
	cfg.Models[name] = m
}
