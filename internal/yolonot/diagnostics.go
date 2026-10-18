package yolonot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

func healthChecks(cfg Config, targets []Harness, probe bool) []diagnosticCheck {
	var checks []diagnosticCheck
	status := "ok"
	var detail string
	if cfg.LoadError != nil {
		status, detail = "error", cfg.LoadError.Error()
	} else {
		detail = fmt.Sprintf("%s (%d model(s), %d judge(s))", configPath(), len(cfg.Models), len(cfg.Judges))
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
	checks = append(checks, diagnosticCheck{Name: "live_enforcement", Status: "info", Detail: "Registration and version checks do not prove host execution. Run the documented harmless host smoke test after restarting."})
	return checks
}

func auditChecks(cfg Config, targets []Harness, cwd string) []diagnosticCheck {
	var checks []diagnosticCheck
	checks = append(checks, ruleLintChecks(LoadRules(cwd))...)
	checks = append(checks, policyRiskChecks(cfg, targets)...)
	checks = append(checks, hostPermissionChecks(targets, cwd)...)
	if paused := pausedSessions(); len(paused) > 0 {
		hint := "yolonot resume --session-id <id>"
		if isGloballyPaused() {
			hint = "yolonot resume --global"
		}
		checks = append(checks, diagnosticCheck{Name: "paused_sessions", Status: "warning", Detail: fmt.Sprintf("%d paused session(s): %s (run: %s)", len(paused), strings.Join(paused, ", "), hint)})
	}
	return checks
}

func doctorChecks(cfg Config, targets []Harness, probe bool) []diagnosticCheck {
	cwd, _ := os.Getwd()
	checks := healthChecks(cfg, targets, probe)
	// Insert audit checks before the trailing live_enforcement info check.
	if len(checks) > 0 && checks[len(checks)-1].Name == "live_enforcement" {
		last := checks[len(checks)-1]
		checks = append(checks[:len(checks)-1], auditChecks(cfg, targets, cwd)...)
		checks = append(checks, last)
		return checks
	}
	return append(checks, auditChecks(cfg, targets, cwd)...)
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

var broadAllowHeads = map[string]string{
	"git": "git push --force / git reset --hard", "npm": "npm publish / npm run", "pnpm": "pnpm publish / pnpm run",
	"yarn": "yarn publish / yarn run", "bun": "bun run", "uv": "uv run", "pip": "pip install", "pip3": "pip3 install",
	"cargo": "cargo run / cargo publish", "go": "go run", "make": "arbitrary Makefile targets",
	"docker": "docker rm -f / docker run --privileged", "podman": "podman rm -f", "kubectl": "kubectl delete",
	"helm": "helm uninstall", "terraform": "terraform destroy", "aws": "aws s3 rb / destructive APIs",
	"gcloud": "destructive cloud APIs", "az": "destructive cloud APIs", "gh": "gh repo delete / gh api",
	"bash": "arbitrary shell scripts", "sh": "arbitrary shell scripts", "zsh": "arbitrary shell scripts",
	"python": "arbitrary code execution", "python3": "arbitrary code execution", "node": "arbitrary code execution",
	"ruby": "arbitrary code execution", "perl": "arbitrary code execution", "rm": "file deletion",
	"sudo": "privileged execution", "curl": "network requests / uploads", "wget": "network downloads",
}

func broadAllowCmdWarning(pattern string) string {
	p := strings.TrimSpace(pattern)
	if p == "*" {
		return "allow-cmd * auto-approves every command before the judge or session_deny runs"
	}
	if !strings.HasSuffix(p, "*") {
		return ""
	}
	stem := strings.TrimSpace(strings.TrimSuffix(p, "*"))
	fields := strings.Fields(stem)
	if len(fields) == 0 {
		return ""
	}
	head := filepath.Base(fields[0])
	if len(fields) == 1 {
		if riskExample, bad := broadAllowHeads[head]; bad {
			return fmt.Sprintf("allow-cmd %s runs before the judge and also auto-approves %s; prefer allow-hint or a narrower subcommand pattern", pattern, riskExample)
		}
	}
	if len(fields) >= 2 {
		pair := head + " " + fields[1]
		if pair == "uv run" || pair == "npm run" || pair == "pnpm run" || pair == "bun run" || pair == "go run" || pair == "git push" {
			return fmt.Sprintf("allow-cmd %s auto-approves arbitrary or remote-mutating %s invocations before the judge", pattern, pair)
		}
		if (head == "git") && (fields[1] == "-C" || fields[1] == "-c") {
			return fmt.Sprintf("allow-cmd %s matches every git subcommand invoked with %s; narrow to specific subcommands", pattern, fields[1])
		}
		if riskExample, bad := broadAllowHeads[head]; bad && strings.HasPrefix(fields[1], "-") {
			return fmt.Sprintf("allow-cmd %s runs before the judge and also auto-approves %s (%s %s); prefer allow-hint or a script path rule", pattern, riskExample, head, fields[1])
		}
	}
	return ""
}

// ruleLintChecks flags deny/ask command globs that match far more than
// they read as: a pattern ending in `/*` matches every absolute path, and
// flags overly broad allow-cmd globs that bypass the judge for multiplex tools
// or interpreters.
func ruleLintChecks(rules []Rule) []diagnosticCheck {
	var checks []diagnosticCheck
	for _, r := range rules {
		if r.Type == "cmd" && r.Action == "allow" {
			if warn := broadAllowCmdWarning(r.Pattern); warn != "" {
				checks = append(checks, diagnosticCheck{Name: "rule_risk", Status: "warning", Detail: warn})
			}
			continue
		}
		if r.Type != "cmd" || (r.Action != "deny" && r.Action != "ask") {
			continue
		}
		if !strings.HasSuffix(r.Pattern, "/*") {
			continue
		}
		stem := strings.TrimSuffix(r.Pattern, "/*")
		probe := strings.TrimPrefix(stem, "*") + "/tmp/probe"
		fields := strings.Fields(probe)
		if len(fields) == 0 || !matchCmd(r.Pattern, probe) {
			continue
		}
		checks = append(checks, diagnosticCheck{Name: "rule_pattern", Status: "warning",
			Detail: fmt.Sprintf("%s-cmd %s also matches %q; for the literal `/` or `/*` argument alone use `%s-cmd %s/` and `%s-cmd %s/?`",
				r.Action, r.Pattern, probe, r.Action, stem, r.Action, stem)})
	}
	return checks
}

func riskyTiersFromMap(rm map[string]string) []string {
	var risky []string
	for _, tier := range []string{RiskModerate, RiskHigh, RiskCritical} {
		act := rm[tier]
		if act == ActionForceAllow || ((tier == RiskHigh || tier == RiskCritical) && act == ActionAllow) {
			risky = append(risky, tier+"="+act)
		}
	}
	return risky
}

func hasHarnessRiskOverride(cfg Config, harnessName string) bool {
	hp := cfg.harnessPolicy(harnessName)
	if hp.Profile != "" || len(hp.RiskMap) > 0 {
		return true
	}
	upper := strings.ToUpper(harnessName)
	if os.Getenv("YOLONOT_"+upper+"_PROFILE") != "" {
		return true
	}
	for _, tier := range allRiskTiers {
		if os.Getenv("YOLONOT_"+upper+"_RISK_"+strings.ToUpper(tier)) != "" {
			return true
		}
	}
	return false
}

func policyRiskChecks(cfg Config, targets []Harness) []diagnosticCheck {
	var checks []diagnosticCheck
	if cfg.AttachOutsideRoot {
		checks = append(checks, diagnosticCheck{
			Name:   "attach_boundary",
			Status: "warning",
			Detail: "attach_outside_root is true: scripts outside the git repository root can be attached to model prompts",
		})
	}
	var globalRisky []string
	if len(targets) != 1 {
		profName := cfg.Policy.Profile
		if v := os.Getenv("YOLONOT_PROFILE"); v != "" {
			profName = v
		}
		if profName == "" {
			profName = DefaultProfileName
		}
		if p := LookupProfile(cfg, profName); p != nil {
			if globalRisky = riskyTiersFromMap(p.Map); len(globalRisky) > 0 {
				checks = append(checks, diagnosticCheck{
					Name:   "risk_policy",
					Status: "warning",
					Detail: fmt.Sprintf("profile %q sets %s (relaxes or overrides classifier caution on higher-risk tiers)", p.Name, strings.Join(globalRisky, ", ")),
				})
			}
		}
	}
	for _, h := range targets {
		if h == nil || h.Name() == "gemini" {
			continue
		}
		if len(targets) != 1 && !hasHarnessRiskOverride(cfg, h.Name()) {
			continue
		}
		risky := riskyTiersFromMap(ResolveRiskMap(h))
		if len(targets) != 1 && len(globalRisky) > 0 {
			var extra []string
			for _, item := range risky {
				if !slices.Contains(globalRisky, item) {
					extra = append(extra, item)
				}
			}
			risky = extra
		}
		if len(risky) > 0 {
			checks = append(checks, diagnosticCheck{
				Name:    "risk_policy",
				Harness: h.Name(),
				Status:  "warning",
				Detail:  fmt.Sprintf("%s (relaxes or overrides classifier caution on higher-risk tiers)", strings.Join(risky, ", ")),
			})
		}
	}
	return checks
}

func isBroadHostAllowRule(rule string) bool {
	r := strings.TrimSpace(rule)
	if r == "*" || r == "Bash(*)" || r == "Bash" || r == "Shell(*)" || r == "Shell" || r == "command(*)" || strings.HasPrefix(r, "unsandboxed(") {
		return true
	}
	for _, prefix := range []string{"Bash(", "Shell(", "command("} {
		if strings.HasPrefix(r, prefix) && strings.HasSuffix(r, ")") {
			inner := strings.TrimSuffix(strings.TrimPrefix(r, prefix), ")")
			inner = strings.TrimSuffix(inner, ":*")
			inner = strings.TrimSuffix(inner, " *")
			inner = strings.TrimSuffix(inner, "*")
			inner = strings.TrimSpace(inner)
			if inner == "" {
				return true
			}
			fields := strings.Fields(inner)
			if len(fields) == 1 {
				if _, bad := broadAllowHeads[fields[0]]; bad {
					return true
				}
			}
			if len(fields) == 2 {
				pair := fields[0] + " " + fields[1]
				if pair == "uv run" || pair == "npm run" || pair == "pnpm run" || pair == "bun run" || pair == "go run" || pair == "git push" {
					return true
				}
			}
		}
	}
	return false
}

func hostPermissionChecks(targets []Harness, cwd string) []diagnosticCheck {
	summary := DiscoverHostPermissions(cwd, targets...)
	var checks []diagnosticCheck
	for _, f := range summary.HostFiles {
		for _, alert := range f.PolicyAlerts {
			checks = append(checks, diagnosticCheck{
				Name:    alert.Category,
				Harness: f.Harness,
				Status:  "warning",
				Detail:  sanitizeBanner(alert.Detail),
			})
		}
		var broad []string
		for _, r := range f.Rules {
			if r.Action == "allow" && (r.BroadWarning != "" || isBroadHostAllowRule(r.Raw)) {
				broad = append(broad, sanitizeBanner(r.Raw))
			}
		}
		if len(broad) > 0 {
			checks = append(checks, diagnosticCheck{
				Name:    "host_permissions",
				Harness: f.Harness,
				Status:  "warning",
				Detail:  fmt.Sprintf("broad host allow rule(s) in %s: %s (auto-runs when yolonot passes through or is paused)", sanitizeBanner(f.Path), strings.Join(broad, ", ")),
			})
		}
	}
	return checks
}

func cmdDoctor(args []string) {
	cfg := LoadConfig()
	targets := diagnosticHarnesses(args)
	checks := healthChecks(cfg, targets, sliceHas(args, "--probe-models"))
	if sliceHas(args, "--json") {
		data, _ := json.MarshalIndent(checks, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Println("yolonot doctor")
		fmt.Println()
		for _, c := range checks {
			target := c.Name
			if c.Harness != "" {
				target = c.Harness + "/" + target
			}
			fmt.Printf("  %-7s %-28s %s\n", strings.ToUpper(c.Status), target, c.Detail)
		}
		cwd, _ := os.Getwd()
		if audits := auditChecks(cfg, targets, cwd); len(audits) > 0 {
			fmt.Printf("\n  ⚠ %d security/policy warning(s) found — run: yolonot audit\n", len(audits))
		}
	}
	for _, c := range checks {
		if c.Status == "error" {
			os.Exit(1)
		}
	}
}

func cmdAudit(args []string) {
	cfg := LoadConfig()
	targets := diagnosticHarnesses(args)
	cwd, _ := os.Getwd()
	checks := auditChecks(cfg, targets, cwd)
	if sliceHas(args, "--json") {
		if checks == nil {
			checks = []diagnosticCheck{}
		}
		data, _ := json.MarshalIndent(checks, "", "  ")
		fmt.Println(string(data))
		return
	}
	if len(checks) == 0 {
		fmt.Println("yolonot audit — no security or permission warnings found.")
		return
	}
	fmt.Printf("yolonot audit — %d warning(s) found\n\n", len(checks))
	for _, c := range checks {
		target := c.Name
		if c.Harness != "" {
			target = c.Harness + "/" + target
		}
		fmt.Printf("  %-7s %-28s %s\n", strings.ToUpper(c.Status), target, c.Detail)
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
	Harness     string            `json:"harness"`
	ConfigPath  string            `json:"config_path"`
	HookPath    string            `json:"hook_path"`
	Registered  bool              `json:"registered"`
	NativeAsk   bool              `json:"native_ask"`
	Profile     string            `json:"profile"`
	RiskMap     map[string]string `json:"risk_map"`
	Judges      JudgeList         `json:"judges"`
	Models      []effectiveModel  `json:"models"`
	RuleSources []string          `json:"rule_sources"`
	RuleCount   int               `json:"rule_count"`
	Session     string            `json:"session,omitempty"`
	Project     string            `json:"project"`
	Paused      bool              `json:"paused"`
	Approved    []string          `json:"approved,omitempty"`
	Asked       []string          `json:"asked,omitempty"`
	Denied      []string          `json:"denied,omitempty"`
	Failure     map[string]string `json:"failure"`
	HookTimeout int               `json:"hook_timeout"`
	Warnings    []string          `json:"warnings,omitempty"`
}

func resolvedState(cfg Config, h Harness, args []string) effectiveState {
	cwd, _ := os.Getwd()
	sid := resolveSessionID(args)
	if sid == "" {
		sid = FindSessionID()
	}
	rules := LoadRules(cwd)
	state := effectiveState{Harness: h.Name(), ConfigPath: configPath(), HookPath: h.SettingsPath(), Registered: h.IsInstalled(), NativeAsk: harnessSupportsAsk(h), RiskMap: ResolveRiskMap(h), Judges: cfg.Judges, Session: sid, Project: projectRoot(cwd), Paused: isPaused(sid), RuleCount: len(rules), HookTimeout: cfg.HookTimeout}
	if sid != "" {
		projSid := ProjectSessionID(sid, cwd)
		state.Approved = ReadLines(projSid, "approved")
		for _, cmd := range ReadLines(projSid, "approved_unsandboxed") {
			state.Approved = append(state.Approved, cmd+"  [unsandboxed]")
		}
		state.Asked = ReadLines(projSid, "asked")
		state.Denied = ReadLines(projSid, "denied")
	}
	if state.HookTimeout == 0 {
		state.HookTimeout = 55
	}
	if p := ResolveActiveProfile(cfg, h); p != nil {
		state.Profile = p.Name
	}
	for _, path := range yolonotConfigSearchPaths(cwd) {
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
	for _, c := range append(append(ruleLintChecks(rules), policyRiskChecks(cfg, []Harness{h})...), hostPermissionChecks([]Harness{h}, cwd)...) {
		state.Warnings = append(state.Warnings, c.Name+": "+c.Detail)
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
	fmt.Printf("Harness: %s (registered: %t, native ask: %t)\nProfile: %s\nConfig: %s\nHooks: %s\nProject: %s\nSession: %s (paused: %t)\nJudges: %s\nHook budget: %ds\n", state.Harness, state.Registered, state.NativeAsk, state.Profile, state.ConfigPath, state.HookPath, state.Project, state.Session, state.Paused, judgeNames(state.Judges), state.HookTimeout)
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
	if len(state.Warnings) > 0 {
		fmt.Println("Warnings:")
		for _, w := range state.Warnings {
			fmt.Printf("  ⚠ %s\n", w)
		}
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
