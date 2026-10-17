package yolonot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type diagnosticCheck struct {
	Name    string `json:"name"`
	Harness string `json:"harness,omitempty"`
	Status  string `json:"status"`
	Detail  string `json:"detail"`
}

func diagnosticHarnesses(args []string) []Harness {
	if name := harnessArgument(args); name != "" {
		if h := GetHarness(name); h != nil {
			return []Harness{h}
		}
	}
	if sliceHas(args, "--all") {
		return Harnesses()
	}
	if os.Getenv("YOLONOT_HARNESS") != "" {
		return []Harness{ActiveHarness()}
	}
	var selected []Harness
	for _, h := range Harnesses() {
		if h.IsDetected() || sliceHas(args, "--all") {
			selected = append(selected, h)
		}
	}
	if len(selected) == 0 && ActiveHarness() != nil {
		selected = append(selected, ActiveHarness())
	}
	return selected
}

func harnessArgument(args []string) string {
	for i, a := range args {
		if a == "--harness" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "--harness=") {
			return strings.TrimPrefix(a, "--harness=")
		}
	}
	return ""
}

func sliceHas(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

func harnessBinary(name string) (string, error) {
	names := map[string][]string{"claude": {"claude"}, "codex": {"codex"}, "opencode": {"opencode"}, "gemini": {"gemini"}, "antigravity": {"agy"}, "cursor": {"cursor-agent", "agent", "cursor"}}
	for _, candidate := range names[name] {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	if name == "cursor" {
		for _, path := range []string{"/Applications/Cursor.app/Contents/Resources/app/bin/cursor"} {
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("CLI not found on PATH")
}

func harnessVersion(name, path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.WaitDelay = 100 * time.Millisecond
	// Some version commands initialise logs. Keep those outside real state.
	if name == "opencode" {
		if tmp, err := os.MkdirTemp("", "yolonot-doctor-"); err == nil {
			defer os.RemoveAll(tmp)
			cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+tmp, "XDG_STATE_HOME="+tmp, "XDG_CACHE_HOME="+tmp, "XDG_CONFIG_HOME="+tmp)
		}
	}
	out, err := cmd.Output()
	if err != nil {
		return "version unavailable"
	}
	return sanitizeBanner(strings.TrimSpace(string(out)))
}

func doctorChecks(cfg Config, targets []Harness, probe bool) []diagnosticCheck {
	var checks []diagnosticCheck
	status, detail := "ok", configPath()
	if cfg.LoadError != nil {
		status, detail = "error", cfg.LoadError.Error()
	}
	checks = append(checks, diagnosticCheck{Name: "config", Status: status, Detail: detail})
	for _, h := range targets {
		if h == nil {
			continue
		}
		status, detail = "ok", h.SettingsPath()
		if !h.IsInstalled() {
			status, detail = "error", "hook registration not found: "+detail
		}
		checks = append(checks, diagnosticCheck{Name: "registration", Harness: h.Name(), Status: status, Detail: detail})
		path, err := harnessBinary(h.Name())
		version := "CLI not found on PATH"
		status = "warning"
		if err == nil {
			status = "ok"
			version = harnessVersion(h.Name(), path)
		}
		checks = append(checks, diagnosticCheck{Name: "host_version", Harness: h.Name(), Status: status, Detail: version})
		defer prepareHarnessCapabilities(h, version)()
		checks = append(checks, diagnosticCheck{Name: "native_ask", Harness: h.Name(), Status: "info", Detail: fmt.Sprintf("%t (runtime capability; see docs/harnesses.md)", harnessSupportsAsk(h))})
		if h.Name() == "codex" {
			checks = append(checks, diagnosticCheck{Name: "hook_trust", Harness: h.Name(), Status: "warning", Detail: "Review and trust this exact hook in Codex /hooks; registration alone does not activate it."})
		}
		if h.Name() == "gemini" {
			checks = append(checks, diagnosticCheck{Name: "support_retired", Harness: h.Name(), Status: "warning", Detail: "yolonot no longer supports Gemini CLI. Use Antigravity (agy); uninstall old hooks with yolonot uninstall --harness gemini."})
		}
	}
	for _, name := range cfg.ModelNames() {
		m := cfg.Models[name]
		status, detail = "ok", modelProtocol(m)
		if m.EnvKey != "" && os.Getenv(m.EnvKey) == "" {
			status, detail = "warning", "missing environment variable "+m.EnvKey
		}
		if modelProtocol(m) == "claude-cli" {
			if _, err := exec.LookPath("claude"); err != nil {
				status, detail = "error", "claude CLI not found"
			}
		}
		if probe && status == "ok" {
			if probeModelConnection(m) == nil {
				detail += " connection probe passed"
			} else {
				status, detail = "error", "connection probe failed"
			}
		}
		checks = append(checks, diagnosticCheck{Name: "model:" + name, Status: status, Detail: detail})
	}
	for _, sp := range cfg.JudgeSpecs() {
		if sp.Kind() == judgeExec && !execPathFound(strings.TrimPrefix(sp.Use, "exec:")) {
			checks = append(checks, diagnosticCheck{Name: "exec_judge", Status: "error", Detail: sp.Use + " executable not found"})
		}
	}
	if len(cfg.Judges) == 0 {
		checks = append(checks, diagnosticCheck{Name: "judge_chain", Status: "warning", Detail: "Empty chain: rules/session policy still apply, otherwise host permissions decide."})
	}
	if esc := GetEscalationConfig(); esc.Model != "" {
		if c, ok := escalationLatencyCheck(ReadRecentDecisions(500), resolveTimeoutSeconds(esc, 10)); ok {
			checks = append(checks, c)
		}
	}
	checks = append(checks, ruleLintChecks(LoadRules())...)
	if paused := pausedSessions(); len(paused) > 0 {
		checks = append(checks, diagnosticCheck{Name: "paused_sessions", Status: "warning", Detail: fmt.Sprintf("%d paused session(s): %s (run: yolonot resume --session-id <id>)", len(paused), strings.Join(paused, ", "))})
	}
	checks = append(checks, diagnosticCheck{Name: "live_enforcement", Status: "info", Detail: "Registration and version checks do not prove host execution. Run the documented harmless host smoke test after restarting."})
	return checks
}

// escalationLatencyCheck reports how the second model's answer times
// compare with its timeout, both in milliseconds.
func escalationLatencyCheck(entries []DecisionEntry, timeoutSeconds int) (diagnosticCheck, bool) {
	es := collectEscalationStats(entries)
	if es.fired == 0 {
		return diagnosticCheck{}, false
	}
	detail := fmt.Sprintf("%d fired, %d timed out, p50 %dms, p90 %dms, timeout %ds",
		es.fired, es.timeouts, percentile(es.latencies, 50), percentile(es.latencies, 90), timeoutSeconds)
	c := diagnosticCheck{Name: "escalation_latency", Status: "ok", Detail: detail}
	if warn := escalationLatencyWarning(es, timeoutSeconds); warn != "" {
		c.Status, c.Detail = "warning", warn+"; "+detail+". Raise the model's timeout (yolonot models) or pick a faster one."
	}
	return c, true
}

// ruleLintChecks flags deny/ask command globs that match far more than
// they read as: a pattern ending in `/*` matches every absolute path.
func ruleLintChecks(rules []Rule) []diagnosticCheck {
	var checks []diagnosticCheck
	for _, r := range rules {
		if r.Type != "cmd" || (r.Action != "deny" && r.Action != "ask") {
			continue
		}
		if !strings.HasSuffix(r.Pattern, "/*") {
			continue
		}
		stem := strings.TrimSuffix(r.Pattern, "/*")
		probe := strings.TrimPrefix(stem, "*") + "/tmp/probe"
		fields := strings.Fields(probe)
		if len(fields) == 0 || !matchCmd(r.Pattern, probe, fields[0]) {
			continue
		}
		checks = append(checks, diagnosticCheck{Name: "rule_pattern", Status: "warning",
			Detail: fmt.Sprintf("%s-cmd %s also matches %q; for the literal `/` or `/*` argument alone use `%s-cmd %s/` and `%s-cmd %s/?`",
				r.Action, r.Pattern, probe, r.Action, stem, r.Action, stem)})
	}
	return checks
}

func cmdDoctor(args []string) {
	checks := doctorChecks(LoadConfig(), diagnosticHarnesses(args), sliceHas(args, "--probe-models"))
	if sliceHas(args, "--json") {
		data, _ := json.MarshalIndent(checks, "", "  ")
		fmt.Println(string(data))
	} else {
		for _, c := range checks {
			target := c.Name
			if c.Harness != "" {
				target = c.Harness + "/" + target
			}
			fmt.Printf("%-7s %-28s %s\n", strings.ToUpper(c.Status), target, c.Detail)
		}
	}
	for _, c := range checks {
		if c.Status == "error" {
			os.Exit(1)
		}
	}
}

type effectiveModel struct {
	Name     string `json:"name"`
	Model    string `json:"model"`
	Protocol string `json:"protocol"`
	EnvKey   string `json:"env_key,omitempty"`
	KeySet   bool   `json:"key_set"`
	Timeout  int    `json:"timeout"`
}
type effectiveState struct {
	Harness         string            `json:"harness"`
	ConfigPath      string            `json:"config_path"`
	HookPath        string            `json:"hook_path"`
	Registered      bool              `json:"registered"`
	NativeAsk       bool              `json:"native_ask"`
	Profile         string            `json:"profile"`
	RiskMap         map[string]string `json:"risk_map"`
	Judges          JudgeList         `json:"judges"`
	Models          []effectiveModel  `json:"models"`
	RuleSources     []string          `json:"rule_sources"`
	RuleCount       int               `json:"rule_count"`
	Session         string            `json:"session,omitempty"`
	Project         string            `json:"project"`
	Paused          bool              `json:"paused"`
	Failure         map[string]string `json:"failure"`
	HookTimeout     int               `json:"hook_timeout"`
	LearningEnabled bool              `json:"learning_enabled"`
	Learning        LearningConfig    `json:"learning"`
}

func resolvedState(cfg Config, h Harness, args []string) effectiveState {
	cwd, _ := os.Getwd()
	sid := resolveSessionID(args)
	state := effectiveState{Harness: h.Name(), ConfigPath: configPath(), HookPath: h.SettingsPath(), Registered: h.IsInstalled(), NativeAsk: harnessSupportsAsk(h), RiskMap: ResolveRiskMap(h), Judges: cfg.Judges, Session: sid, Project: projectRoot(cwd), Paused: isPaused(sid), RuleCount: len(LoadRules()), LearningEnabled: learningEnabled(cfg), Learning: cfg.Learning, HookTimeout: cfg.HookTimeout}
	if state.HookTimeout == 0 {
		state.HookTimeout = 55
	}
	if p := ResolveActiveProfile(cfg, h); p != nil {
		state.Profile = p.Name
	}
	for _, path := range yolonotConfigSearchPaths() {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			state.RuleSources = append(state.RuleSources, filepath.Clean(path))
		}
	}
	for _, name := range cfg.ModelNames() {
		m := cfg.Models[name]
		state.Models = append(state.Models, effectiveModel{Name: name, Model: m.Model, Protocol: modelProtocol(m), EnvKey: m.EnvKey, KeySet: cfg.ModelLLM(name).APIKey != "", Timeout: m.Timeout})
	}
	state.Failure = map[string]string{}
	for _, kind := range []string{judgeErrUnavailable, judgeErrParse, "invalid_config", judgeErrOversize, judgeErrBudget} {
		state.Failure[kind] = failureAction(cfg, h, kind)
	}
	return state
}

func cmdEffective(args []string) {
	h := ActiveHarness()
	if name := harnessArgument(args); name != "" {
		h = GetHarness(name)
	}
	if h == nil {
		fmt.Fprintln(os.Stderr, "Unknown harness")
		os.Exit(2)
	}
	defer prepareHarnessCapabilities(h)()
	state := resolvedState(LoadConfig(), h, args)
	if sliceHas(args, "--json") {
		data, _ := json.MarshalIndent(state, "", "  ")
		fmt.Println(string(data))
		return
	}
	fmt.Printf("Harness: %s (registered: %t, native ask: %t)\nProfile: %s\nConfig: %s\nHooks: %s\nProject: %s\nSession: %s (paused: %t)\nJudges: %s\nHook budget: %ds\nLearning: %t (retention %d days, cap %d)\n", state.Harness, state.Registered, state.NativeAsk, state.Profile, state.ConfigPath, state.HookPath, state.Project, state.Session, state.Paused, judgeNames(state.Judges), state.HookTimeout, state.LearningEnabled, state.Learning.RetentionDays, state.Learning.MaxEntries)
	for _, tier := range allRiskTiers {
		fmt.Printf("  %-10s %s\n", tier, state.RiskMap[tier])
	}
	for _, kind := range []string{judgeErrUnavailable, judgeErrParse, "invalid_config", judgeErrOversize, judgeErrBudget} {
		fmt.Printf("Failure %-15s %s\n", kind, state.Failure[kind])
	}
	fmt.Printf("Rules: %d from %s\n", state.RuleCount, strings.Join(state.RuleSources, ", "))
	for _, m := range state.Models {
		fmt.Printf("Model %s: %s / %s (key set: %t)\n", m.Name, m.Protocol, m.Model, m.KeySet)
	}
}

func probeModelConnection(m ModelConfig) error {
	cfg := LLMConfig{URL: m.URL, Model: m.Model, Protocol: m.Protocol, Timeout: m.Timeout, APIKey: m.APIKey}
	if m.EnvKey != "" && os.Getenv(m.EnvKey) != "" {
		cfg.APIKey = os.Getenv(m.EnvKey)
	}
	if isDecisionConfig(cfg) {
		_, err := callDecision(cfg, "Command: echo connection-probe")
		return err
	}
	_, err := CallLLM(cfg, "Reply with OK only.", "Connection probe.", 32)
	return err
}

// Outside an OpenCode invocation, derive V2's runtime marker from the local
// CLI so check/effective display the policy the installed plugin will use.
// A caller-supplied marker always wins; restore it after read-only commands.
func prepareHarnessCapabilities(h Harness, knownVersion ...string) func() {
	noop := func() {}
	if h == nil || h.Name() != "opencode" || os.Getenv("YOLONOT_OPENCODE_API") != "" {
		return noop
	}
	version := ""
	if len(knownVersion) > 0 {
		version = knownVersion[0]
	} else if path, err := harnessBinary("opencode"); err == nil {
		version = harnessVersion("opencode", path)
	}
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if !strings.HasPrefix(version, "2.") {
		return noop
	}
	old, existed := os.LookupEnv("YOLONOT_OPENCODE_API")
	os.Setenv("YOLONOT_OPENCODE_API", "2")
	return func() {
		if existed {
			os.Setenv("YOLONOT_OPENCODE_API", old)
		} else {
			os.Unsetenv("YOLONOT_OPENCODE_API")
		}
	}
}
