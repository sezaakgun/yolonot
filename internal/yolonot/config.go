package yolonot

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ProviderConfig struct {
	Name     string `json:"name,omitempty"`
	URL      string `json:"url,omitempty"`
	Model    string `json:"model,omitempty"`
	EnvKey   string `json:"env_key,omitempty"`
	APIKey   string `json:"api_key,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`  // LLM call timeout in seconds
	Protocol string `json:"protocol,omitempty"` // chat | anthropic | claude-cli | systemone | decisions | workers-ai; empty = legacy URL inference
}

type Config struct {
	Schema string `json:"$schema,omitempty"`
	// ConfigVersion is 1 for the models/judges/prompt/policy shape written
	// by yolonot 1.x. Absent on v0 files; LoadConfig folds v0 keys into the
	// v1 fields in memory and SaveConfig writes v1 only.
	ConfigVersion int `json:"config_version,omitempty"`

	// Models is the catalog every other section refers to by name: judges
	// name entries, escalation names one. A model is typed (System One or
	// OpenAI Decisions endpoint) or chat, decided by its URL.
	Models map[string]ModelConfig `json:"models,omitempty"`
	// Judges is the ordered chain: fast_allow, exec:<path>, or a model name.
	Judges JudgeList `json:"judges,omitempty"`
	// Escalation is the optional second opinion run after the chain.
	Escalation *EscalationConfig `json:"escalation,omitempty"`
	// Prompt tunes the chat-model system prompt (context / hints / override).
	Prompt PromptConfig `json:"prompt,omitzero"`
	// Policy maps risk tiers to actions: profile, custom profiles, per-harness pins.
	Policy PolicyConfig `json:"policy,omitzero"`

	QuietOnAllow bool     `json:"quiet_on_allow,omitempty"` // when true, allow decisions emit no systemMessage — only ask/deny show a banner
	Wrappers     []string `json:"wrappers,omitempty"`       // user-defined transparent command wrappers (e.g. ["mycli","corp-shim"]). Extend the built-in set (time/timeout/nice/nohup/strace/ltrace/command/builtin/rtk) — never replace it. Applied to both fast_allow unwrapping and session-approval cross-form lookup.

	// AttachOutsideRoot lets script attachment cross the attach root (git
	// repo root of the session cwd, else the cwd). Sensitive home dirs stay
	// floored regardless. Config-file only by design: no CLI verb and no
	// .yolonot directive, so an untrusted clone can never widen the boundary.
	AttachOutsideRoot bool          `json:"attach_outside_root,omitempty"`
	HookTimeout       int           `json:"hook_timeout,omitempty"` // overall model/exec budget, 1..55 seconds; default 55
	Failure           FailurePolicy `json:"failure,omitzero"`
	LoadError         error         `json:"-"`

	// v0 keys (yolonot ≤ 0.23). Read only: normalize() folds them into the
	// fields above and clears them, so they never reach disk again.
	Provider        ProviderConfig               `json:"provider,omitzero"`
	Decision        ProviderConfig               `json:"decision,omitzero"`
	Classifier      ClassifierConfig             `json:"classifier,omitzero"`
	PreCheck        PreCheckList                 `json:"pre_check,omitempty"`
	LocalAllow      bool                         `json:"local_allow,omitempty"`
	RiskMaps        map[string]map[string]string `json:"risk_maps,omitempty"`
	Profile         string                       `json:"profile,omitempty"`
	ProfileOverride map[string]string            `json:"profile_override,omitempty"`
	CustomProfiles  map[string]map[string]string `json:"custom_profiles,omitempty"`

	// Legacy is set by LoadConfig when the file on disk still uses v0 keys.
	Legacy bool `json:"-"`
}

// ModelConfig is one catalog entry. Same shape as the v0 provider block.
type ModelConfig = ProviderConfig

// PromptConfig is the chat-model prompt tuning (v0: classifier.*).
type PromptConfig struct {
	Context    []string `json:"context,omitempty"`     // prose describing trusted infra (repos, buckets, domains)
	AllowHints []string `json:"allow_hints,omitempty"` // prose nudging the model toward allow on routine patterns
	AskHints   []string `json:"ask_hints,omitempty"`   // prose nudging the model toward ask on environment-specific risks
	// SystemPrompt fully replaces the built-in base prompt when non-empty.
	// Context/AllowHints/AskHints still append after it. A per-project
	// .yolonot `system-prompt` directive overrides this. An override that
	// omits the JSON verdict contract is used anyway with a Verbosef warning
	// (BuildSystemPrompt); unparseable output then passes through to the
	// host's permission layer. Empty = built-in prompt, byte-for-byte.
	SystemPrompt string `json:"system_prompt,omitempty"`
}

// PolicyConfig is the risk-tier policy (v0: profile, custom_profiles,
// profile_override, risk_maps).
type PolicyConfig struct {
	// Profile names the global profile: a built-in (fast/balanced/strict/
	// paranoid) or a Profiles entry. Empty → DefaultProfileName.
	Profile string `json:"profile,omitempty"`
	// Profiles are user-defined tier→action maps (canonical: allow|ask|deny),
	// validated via ValidateCustomProfile. Names must not collide with built-ins.
	Profiles map[string]map[string]string `json:"profiles,omitempty"`
	// Harness pins a profile and/or overrides single tier cells for one harness.
	Harness map[string]HarnessPolicy `json:"harness,omitempty"`
}

type HarnessPolicy struct {
	Profile string            `json:"profile,omitempty"`
	RiskMap map[string]string `json:"risk_map,omitempty"` // tier → allow|ask|deny|passthrough, merged on top of the profile
}

// ClassifierConfig holds the classifier backend choice plus prose tuning that
// gets injected into the LLM system prompt. JSON parses two shapes for
// backward compatibility:
//
//	"classifier": "llm"                                 // legacy string form
//	"classifier": {"impl": "llm", "context": [...] }    // new object form
//
// The legacy form maps to {Impl: "llm"} with empty hint slices, so older
// configs and older tests keep working byte-for-byte.
//
// Hint slices accept the literal string "$defaults" as a sentinel that is
// spliced in place of yolonot's built-in lists when the system prompt is
// assembled (today the built-in lists are empty; the sentinel is reserved for
// forward-compat parity with Claude Code's autoMode contract). Omitting the
// sentinel takes full ownership of the list.
type ClassifierConfig struct {
	Impl       string   `json:"impl,omitempty"`        // "llm" (default), "heuristic", "knn", ...
	Context    []string `json:"context,omitempty"`     // prose describing trusted infra (repos, buckets, domains)
	AllowHints []string `json:"allow_hints,omitempty"` // prose nudging classifier toward allow on routine patterns
	AskHints   []string `json:"ask_hints,omitempty"`   // prose nudging classifier toward ask on environment-specific risks
	// SystemPrompt fully replaces the built-in classifier base prompt when
	// non-empty. Unlike the hint slices (which append), this owns the whole
	// base — but Context/AllowHints/AskHints still append after it, so the
	// $defaults + walk-up machinery keeps working on top of a custom base.
	// A per-project .yolonot `system-prompt` directive overrides this. An
	// override that omits the JSON verdict contract is used anyway with a
	// Verbosef warning (BuildSystemPrompt); if the model then emits
	// unparseable output the hook passes through to the host's native
	// permission layer. Empty = built-in prompt, byte-for-byte.
	SystemPrompt string `json:"system_prompt,omitempty"`
}

// UnmarshalJSON accepts either a JSON string ("llm") or a JSON object,
// preserving compatibility with configs written by every prior yolonot
// version that shipped `classifier: <string>`.
func (c *ClassifierConfig) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("classifier: %w", err)
		}
		c.Impl = s
		return nil
	}
	// Use a type alias so the recursive call doesn't re-enter this method.
	type raw ClassifierConfig
	var r raw
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("classifier: expected string or object")
	}
	*c = ClassifierConfig(r)
	return nil
}

// MarshalJSON keeps the legacy string form on disk when only Impl is set
// (i.e. no prose tuning). This means an existing config that loaded as
// "classifier": "llm" round-trips unchanged through Save — important so we
// don't silently rewrite every user's config the first time they upgrade.
func (c ClassifierConfig) MarshalJSON() ([]byte, error) {
	if len(c.Context) == 0 && len(c.AllowHints) == 0 && len(c.AskHints) == 0 && c.SystemPrompt == "" {
		if c.Impl == "" {
			return []byte(`""`), nil
		}
		return json.Marshal(c.Impl)
	}
	type raw ClassifierConfig
	return json.Marshal(raw(c))
}

// EscalationConfig configures the optional second, bigger model consulted
// when the primary classifier is uncertain (see hook.go escalation block).
// A nil Config.Escalation means the feature was never configured and the
// config file round-trips byte-identical. Note the feature can also be
// armed purely via LLM_ESCALATION_URL/LLM_ESCALATION_MODEL env vars with
// no config block at all, mirroring the primary's LLM_URL/LLM_MODEL.
type EscalationConfig struct {
	// Model names a Models entry (a chat model). Empty = not configured.
	Model string `json:"model,omitempty"`
	// Disabled is the config-side kill switch: `yolonot escalation off`
	// sets it instead of deleting Model, so re-enabling needs no re-setup.
	Disabled bool `json:"disabled,omitempty"`
	// Unresolved controls what happens when escalation FIRED and the final
	// action still resolves to ask (including escalation errors):
	// "" / "ask" keeps the ask; "deny" degrades it to a deny that carries
	// both verdicts — for unattended runs where an ask is a stall.
	Unresolved string `json:"unresolved,omitempty"`
	// Provider is the v0 inline endpoint; normalize() moves it into Models.
	Provider ProviderConfig `json:"provider,omitzero"`
}

// FastAllowSentinel is the reserved entry in Config.PreCheck that dispatches
// to the built-in Go bash parser (IsLocallySafeWith) instead of fork+exec.
// Treated as just another pre-checker so users can reorder it alongside
// external binaries (e.g. Dippy) without learning a second concept.
const FastAllowSentinel = "fast-allow"

// PreCheckList is a list of external hook commands. It accepts either a
// single string or an array of strings in JSON so older single-hook configs
// keep working (and so users can write the simple case with less ceremony).
type PreCheckList []string

func (p *PreCheckList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '[' {
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*p = PreCheckList(arr)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("pre_check: expected string or array of strings")
	}
	if s != "" {
		*p = PreCheckList{s}
	}
	return nil
}

func YolonotDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".yolonot")
}

func configPath() string {
	return filepath.Join(YolonotDir(), "config.json")
}

func LoadConfig() Config {
	c, err := readConfig(configPath())
	c.LoadError = err
	return c
}

func SaveConfig(c Config) error {
	if err := saveConfig(c); err != nil {
		fmt.Fprintf(os.Stderr, "yolonot: save config failed: %v\n", err)
		return err
	}
	return nil
}

// saveConfig reports write failures to interactive callers, which must keep
// their draft open when persistence did not succeed.
func saveConfig(c Config) error {
	c.normalize()
	c.ConfigVersion = 1
	// Never persist APIKey to disk. If a user entered a key via the TUI,
	// it lives in memory for this process and is expected to come from
	// the env var on the next run. Plaintext on-disk storage is a weak
	// default — a same-user process (backup agent, cloud sync, snooper)
	// could read it. Scrub on a copy: Models is a shared map and the
	// caller may still need the key for a connection test.
	c.Models = withoutAPIKeys(c.Models)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// atomicWriteFile does symlink rejection + rename-from-tempfile so
	// an attacker can't redirect the write via a TOCTOU symlink.
	if err := atomicWriteFile(configPath(), append(data, '\n'), 0600); err != nil {
		return err
	}
	Verbosef("wrote %s (%d bytes)", configPath(), len(data)+1)
	return nil
}

func withoutAPIKeys(models map[string]ModelConfig) map[string]ModelConfig {
	if len(models) == 0 {
		return models
	}
	scrubbed := make(map[string]ModelConfig, len(models))
	for k, m := range models {
		m.APIKey = ""
		scrubbed[k] = m
	}
	return scrubbed
}

// parseHarnessFlag scans os.Args[2:] for "--harness <name>", "--harness=<name>",
// or "--all". Returns (harnessName, all). harnessName is empty when unset.
func parseHarnessFlag() (string, bool) {
	args := os.Args
	if len(args) < 3 {
		return "", false
	}
	for i := 2; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--all":
			return "", true
		case a == "--harness" && i+1 < len(args):
			return args[i+1], false
		case strings.HasPrefix(a, "--harness="):
			return strings.TrimPrefix(a, "--harness="), false
		}
	}
	return "", false
}

// hasFlag reports whether a bare flag (e.g. "--skill-only") appears anywhere
// in os.Args[2:]. Used by install/uninstall for boolean modifiers.
func hasFlag(name string) bool {
	args := os.Args
	if len(args) < 3 {
		return false
	}
	for i := 2; i < len(args); i++ {
		if args[i] == name {
			return true
		}
	}
	return false
}

func hasHarnessTarget(targets []Harness, name string) bool {
	for _, h := range targets {
		if h.Name() == name {
			return true
		}
	}
	return false
}

// resolveInstallTargets picks which harnesses to install/uninstall into.
//   - --harness <name> → that single adapter (errors if unknown)
//   - --all            → every registered adapter
//   - default          → every already-installed adapter, or if none, every
//     detected adapter (historically "claude only" on a clean box).
func resolveInstallTargets(purpose string) []Harness {
	name, all := parseHarnessFlag()
	if name != "" {
		h := GetHarness(name)
		if h == nil {
			fmt.Fprintf(os.Stderr, "unknown harness: %s\nknown:", name)
			for _, h := range Harnesses() {
				fmt.Fprintf(os.Stderr, " %s", h.Name())
			}
			fmt.Fprintln(os.Stderr)
			os.Exit(2)
		}
		if purpose != "uninstall" && h.Name() == "gemini" {
			fmt.Fprintln(os.Stderr, "Gemini CLI support has been retired. Use --harness antigravity (agy). To remove old hooks: yolonot uninstall --harness gemini")
			os.Exit(2)
		}
		return []Harness{h}
	}
	if all {
		if purpose == "uninstall" {
			return Harnesses()
		}
		return supportedHarnesses()
	}
	if purpose == "uninstall" {
		var installed []Harness
		_, modErr := os.Stat(modDir())
		for _, h := range Harnesses() {
			if h.IsInstalled() || (h.Name() == "claude" && modErr == nil) {
				installed = append(installed, h)
			}
		}
		return installed
	}
	// Install default: any detected harness; falls back to the full registry
	// so a first-time user still gets the historical Claude-only install.
	var detected []Harness
	for _, h := range supportedHarnesses() {
		if h.IsDetected() {
			detected = append(detected, h)
		}
	}
	if len(detected) == 0 {
		return supportedHarnesses()
	}
	return detected
}

func cmdInstall() {
	targets := resolveInstallTargets("install")
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no harnesses registered")
		os.Exit(2)
	}

	skillOnly := hasFlag("--skill-only")
	if skillOnly {
		cmdInstallSkillOnly(targets)
		return
	}

	updating := false
	for _, h := range targets {
		if h.IsInstalled() {
			updating = true
			break
		}
	}
	if updating {
		fmt.Println("Updating yolonot hooks...")
	}

	bp := binaryPath()
	for _, h := range targets {
		if err := h.Install(bp); err != nil {
			fmt.Fprintf(os.Stderr, "install failed for %s: %v\n", h.Name(), err)
			os.Exit(1)
		}
	}

	os.MkdirAll(filepath.Join(YolonotDir(), "sessions"), 0755)
	os.MkdirAll(filepath.Join(YolonotDir(), "cache"), 0755)
	Verbosef("ensured %s and %s",
		filepath.Join(YolonotDir(), "sessions"),
		filepath.Join(YolonotDir(), "cache"))

	var skillPaths []string
	for _, h := range targets {
		path, err := h.InstallSkill()
		if err != nil {
			Verbosef("skill install for %s failed: %v", h.Name(), err)
			continue
		}
		if path != "" {
			skillPaths = append(skillPaths, path)
		}
	}

	// --mod opts in; installs targeting Claude refresh an existing mod so
	// upgrades do not leave an old register.tsx behind.
	modPath := ""
	if _, err := os.Stat(modDir()); hasHarnessTarget(targets, "claude") && (hasFlag("--mod") || err == nil) {
		p, err := modInstall(bp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mod install failed: %v\n", err)
			os.Exit(1)
		}
		modPath = p
	}

	fmt.Println("yolonot installed.")
	fmt.Printf("  Hook command → %s hook\n", bp)
	fmt.Printf("  Data dir     → %s\n", YolonotDir())
	for _, h := range targets {
		fmt.Printf("  Harness      → %s (%s)\n", h.Name(), h.SettingsPath())
	}
	for _, p := range skillPaths {
		fmt.Printf("  Skill        → %s\n", p)
	}
	if modPath != "" {
		fmt.Printf("  Mod          → %s (Claude Code function hooks)\n", modPath)
	}

	// Per-harness caveats: Gemini needs --yolo, Codex/OpenCode don't have
	// an "ask" primitive, etc. Each adapter owns what it surfaces here.
	for _, h := range targets {
		notes := h.PostInstallNotes()
		if len(notes) == 0 {
			continue
		}
		fmt.Println()
		fmt.Printf("Note (%s):\n", h.Name())
		for _, n := range notes {
			fmt.Printf("  • %s\n", n)
		}
	}

	fmt.Println()
	if isFirstRun() {
		fmt.Println("First-time setup? Run 'yolonot setup' to seed rules + pick models.")
		fmt.Println("Already wired up? Restart your AI coding CLI to activate.")
	} else {
		fmt.Println("Restart your AI coding CLI to activate.")
	}
}

// isFirstRun returns true when the user looks like they've never finished
// onboarding: no global rules file and no LLM provider configured. Used to
// decide whether `install` should nudge toward `setup`.
func isFirstRun() bool {
	if _, err := os.Stat(filepath.Join(YolonotDir(), "rules")); err == nil {
		return false
	}
	if cfg := LoadConfig(); cfg.Provider.Model != "" {
		return false
	}
	return true
}

// cmdInstallSkillOnly refreshes just the harness skill bundles (e.g. Claude's
// SKILL.md) without touching hooks, settings, or data dirs. Useful after a
// yolonot upgrade when the binary already has fresh hooks but the embedded
// SKILL.md changed.
func cmdInstallSkillOnly(targets []Harness) {
	var written []string
	for _, h := range targets {
		path, err := h.InstallSkill()
		if err != nil {
			fmt.Fprintf(os.Stderr, "skill install failed for %s: %v\n", h.Name(), err)
			os.Exit(1)
		}
		if path != "" {
			written = append(written, fmt.Sprintf("%s → %s", h.Name(), path))
		}
	}
	if len(written) == 0 {
		fmt.Println("No harness in scope ships a skill bundle. Nothing to do.")
		return
	}
	fmt.Println("Skill bundle refreshed.")
	for _, w := range written {
		fmt.Printf("  %s\n", w)
	}
}

func cmdUninstall() {
	targets := resolveInstallTargets("uninstall")
	if len(targets) == 0 {
		fmt.Println("yolonot is not installed.")
		return
	}

	for _, h := range targets {
		if err := h.Uninstall(); err != nil {
			fmt.Fprintf(os.Stderr, "uninstall failed for %s: %v\n", h.Name(), err)
		}
		if err := h.UninstallSkill(); err != nil {
			Verbosef("skill uninstall for %s failed: %v", h.Name(), err)
		}
	}
	if hasHarnessTarget(targets, "claude") {
		modUninstall()
	}

	fmt.Println("yolonot uninstalled. Restart your AI coding CLI to deactivate.")
	fmt.Printf("Data preserved at %s — delete manually if wanted.\n", YolonotDir())
}

func cmdInit() {
	os.MkdirAll(filepath.Join(YolonotDir(), "sessions"), 0755)
	os.MkdirAll(filepath.Join(YolonotDir(), "cache"), 0755)

	// Global rules
	globalRules := filepath.Join(YolonotDir(), "rules")
	if _, err := os.Stat(globalRules); os.IsNotExist(err) {
		os.WriteFile(globalRules, []byte(`# ~/.yolonot/rules — global rules, every project
# Format: <allow|ask|deny>-<cmd|path> <glob>
#
# Nothing is enabled here on purpose. Read-only commands are cleared by the
# fast_allow judge; everything else is judged by your models (yolonot judges).
# Rules are for the things you already know the answer to:
#
#   deny-cmd  *rm -rf /*        # never. not even if asked nicely.
#   deny-cmd  *sudo *
#   ask-cmd   *curl *           # always ask, whatever the model thinks
#   allow-cmd npm test*         # never ask again
#
# Sensitive paths skip allow rules and fast_allow so a model always sees them:
#
#   sensitive .ssh/
#   sensitive .aws/
#   sensitive .env
#   sensitive id_rsa
#
# yolonot rules --trace shows where every active rule came from.
`), 0644)
		fmt.Printf("  Created %s (examples only, nothing enabled)\n", globalRules)
	} else {
		rules := LoadRules()
		fmt.Printf("  Exists  %s (%d rules)\n", globalRules, len(rules))
	}

	// Project rules
	cwd, _ := os.Getwd()
	projectName := filepath.Base(cwd)
	projectRules := filepath.Join(cwd, ".yolonot")

	if _, err := os.Stat(projectRules); os.IsNotExist(err) {
		lines := []string{
			fmt.Sprintf("# .yolonot — project rules for %s", projectName),
			"# Format: <allow|ask|deny>-<cmd|path> <glob>",
			"# Nothing is enabled; uncomment what this project already knows.",
			"",
			"# --- Project scripts ---",
			"# allow-path scripts/*",
			"# allow-path tests/*",
		}

		// Detect tech stack
		if exists(filepath.Join(cwd, "pyproject.toml")) || exists(filepath.Join(cwd, "setup.py")) {
			lines = append(lines, "", "# --- Python ---")
			lines = append(lines, `# allow-cmd uv run python -c "print*`)
			lines = append(lines, `# allow-cmd python3 -c "print*`)
		}
		if exists(filepath.Join(cwd, "package.json")) {
			lines = append(lines, "", "# --- Node.js ---")
			lines = append(lines, "# allow-cmd npm test*", "# allow-cmd npm run build*")
		}
		if exists(filepath.Join(cwd, "go.mod")) {
			lines = append(lines, "", "# --- Go ---")
			lines = append(lines, "# allow-cmd go test*", "# allow-cmd go build*")
		}
		if exists(filepath.Join(cwd, "Cargo.toml")) {
			lines = append(lines, "", "# --- Rust ---")
			lines = append(lines, "# allow-cmd cargo test*", "# allow-cmd cargo build*")
		}
		if exists(filepath.Join(cwd, "Dockerfile")) || exists(filepath.Join(cwd, "docker-compose.yml")) {
			lines = append(lines, "", "# --- Docker ---")
			lines = append(lines, "# allow-cmd docker build*", "# allow-cmd docker compose*")
		}
		if isDir(filepath.Join(cwd, "deploy")) || isDir(filepath.Join(cwd, "infra")) {
			lines = append(lines, "", "# --- Deploy/Infra ---")
			lines = append(lines, "# ask-path deploy/*", "# ask-path infra/*")
		}
		if isDir(filepath.Join(cwd, "k8s")) || isDir(filepath.Join(cwd, "helm")) {
			lines = append(lines, "# ask-path k8s/*", "# ask-path helm/*")
		}

		content := strings.Join(lines, "\n") + "\n"
		os.WriteFile(projectRules, []byte(content), 0644)
		fmt.Printf("  Created %s (examples only, nothing enabled)\n", projectRules)
	} else {
		rules := loadRulesFromFile(projectRules)
		fmt.Printf("  Exists  %s (%d rules)\n", projectRules, len(rules))
	}

	fmt.Println()
	fmt.Println("yolonot initialized.")
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// pickProvider runs the interactive provider/model picker. escalation=true
// biases the model suggestions toward bigger models (that's the point of a
// second opinion) and skips primary-only advice like the claude-cli speed
// warning — escalation latency only sits in front of would-be asks.
// Returns ok=false on any cancel.
func pickProvider(config Config, escalation bool) (ProviderConfig, bool) {
	type providerInfo struct {
		Name      string
		URL       string
		Models    []string // primary suggestions (small/fast)
		EscModels []string // escalation suggestions (big); empty = same as Models
		EnvKey    string
	}
	providers := []providerInfo{
		{"Claude Code (subscription)", "claude-cli", []string{
			"claude-haiku-5-5", "claude-sonnet-5-5",
		}, []string{
			// Opus first: the escalation slot is the judgment slot, it only
			// fires on would-be asks, and via the subscription it costs
			// nothing extra — only latency, which sits in front of an
			// interruption anyway.
			"claude-opus-5-5", "claude-sonnet-5-5",
		}, ""},
		{"OpenAI", "https://api.openai.com/v1/chat/completions", []string{
			"gpt-6-luna", "gpt-5.6-luna", "gpt-5.4-mini",
		}, []string{
			"gpt-6.1-sol", "gpt-6-sol",
		}, "OPENAI_API_KEY"},
		{"Anthropic (API)", "https://api.anthropic.com/v1/messages", []string{
			"claude-haiku-5-5", "claude-sonnet-5-5",
		}, []string{
			"claude-opus-5-5", "claude-sonnet-5-5",
		}, "ANTHROPIC_API_KEY"},
		{"xAI", "https://api.x.ai/v1/chat/completions", []string{
			"grok-4.3", "grok-4.20-0309-non-reasoning",
		}, []string{
			"grok-4.7", "grok-4.6",
		}, "XAI_API_KEY"},
		{"Ollama (local)", "http://localhost:11434/v1/chat/completions", nil, nil, ""},
		{"OpenRouter", "https://openrouter.ai/api/v1/chat/completions", nil, nil, "OPENROUTER_API_KEY"},
	}
	suggestedModels := func(p providerInfo) []string {
		if escalation && len(p.EscModels) > 0 {
			return p.EscModels
		}
		return p.Models
	}

	// Build menu items with status indicators
	var items []string
	for _, p := range providers {
		status := "ready"
		if p.URL == "claude-cli" {
			if _, err := exec.LookPath("claude"); err != nil {
				status = "not found"
			} else if escalation {
				// For escalation, claude-cli is the zero-extra-cost pick and
				// its latency only sits in front of would-be interruptions.
				status = "subscription-covered"
			} else {
				status = "slow"
			}
		} else if p.EnvKey != "" && os.Getenv(p.EnvKey) == "" && config.Provider.APIKey == "" {
			status = "key missing"
		} else if strings.Contains(p.URL, "localhost") {
			if checkOllama() {
				status = "running"
			} else {
				status = "not running"
			}
		}
		modelHint := "(select model)"
		if models := suggestedModels(p); len(models) > 0 {
			modelHint = models[0]
		}
		items = append(items, fmt.Sprintf("%-30s %-26s %s", p.Name, modelHint, status))
	}
	items = append(items, "Custom endpoint")

	title := "Model"
	if escalation {
		title = "Escalation model"
	}

	idx := tuiSelect(title, items, 0)
	if idx < 0 {
		noteCancelled()
		return ProviderConfig{}, false
	}

	var selected ProviderConfig

	switch {
	case idx < len(providers):
		p := providers[idx]
		var model string
		var apiKey string

		if p.URL == "claude-cli" && !escalation {
			fmt.Println()
			fmt.Println("  Warning: Claude Code subscription is slow (~2-5s per command).")
			fmt.Println("  Every command spawns a separate claude process.")
			fmt.Println("  Recommended alternatives:")
			fmt.Println("    - Ollama with gemma4:e4b (free, local, fast)")
			fmt.Println("    - OpenAI gpt-6-luna (cheap, fast)")
			fmt.Println()
			if !tuiConfirm("Continue with Claude Code subscription?") {
				noteCancelled()
				return ProviderConfig{}, false
			}
		}

		// Get API key first
		if p.EnvKey != "" {
			apiKey = os.Getenv(p.EnvKey)
			if apiKey == "" {
				apiKey = tuiPassword(p.EnvKey)
			}
		}

		if strings.Contains(p.URL, "localhost") {
			// Ollama: list installed models
			if !checkOllama() {
				tuiNote("Ollama not running", "Start it with: ollama serve")
				return ProviderConfig{}, false
			}
			if escalation {
				fmt.Println("  Note: a local model escalating to another local model adds latency more than judgment.")
			}
			models := listOllamaModels()
			if len(models) > 0 {
				models = append(models, "Other (type name)")
				modelIdx := tuiSelect("Select Ollama model", models, 0)
				if modelIdx < 0 {
					noteCancelled()
					return ProviderConfig{}, false
				}
				if modelIdx == len(models)-1 {
					model = tuiInput("Model name", "e.g. llama3:8b", "")
				} else {
					model = models[modelIdx]
				}
			} else {
				fmt.Println("  No models installed. Recommended: gemma4:e4b")
				fmt.Println("  Install with: ollama pull gemma4:e4b")
				model = tuiInput("Model name", "gemma4:e4b", "gemma4:e4b")
			}
		} else {
			models := suggestedModels(p)

			// OpenRouter: fetch free models live for the primary. For
			// escalation the free list is the wrong pool — big models are
			// the point — so fall through to typed input.
			if strings.Contains(p.URL, "openrouter") && len(models) == 0 && !escalation {
				if !tuiInPage {
					fmt.Print("Fetching free models... ")
				}
				models = fetchOpenRouterFreeModels()
				if !tuiInPage && len(models) > 0 {
					fmt.Printf("found %d\n", len(models))
				} else if !tuiInPage {
					fmt.Println("failed")
				}
			}

			if len(models) > 0 {
				choices := append([]string{}, models...)
				choices = append(choices, "Other (type name)")
				modelIdx := tuiSelect(fmt.Sprintf("Select %s model", p.Name), choices, 0)
				if modelIdx < 0 {
					noteCancelled()
					return ProviderConfig{}, false
				}
				if modelIdx == len(choices)-1 {
					model = tuiInput("Model name", "", "")
				} else {
					model = choices[modelIdx]
				}
			} else {
				model = tuiInput("Model name", "", "")
			}
		}

		if model == "" {
			noteCancelled()
			return ProviderConfig{}, false
		}

		timeout := 10
		if strings.Contains(p.URL, "localhost") || p.URL == "claude-cli" || (escalation && strings.Contains(p.URL, "openrouter")) {
			timeout = 30
		} else if strings.Contains(p.URL, "openrouter") {
			timeout = 15
		}

		selected = ProviderConfig{Name: p.Name, URL: p.URL, Model: model, EnvKey: p.EnvKey, Timeout: timeout}
		if apiKey != "" && os.Getenv(p.EnvKey) == "" {
			selected.APIKey = apiKey
			fmt.Printf("\nThe entered key will be used for this run's connection test but NOT written to disk.\n")
			fmt.Printf("For persistent use, export %s in your shell rc:\n", p.EnvKey)
			fmt.Printf("  export %s=<your-key>\n\n", p.EnvKey)
		}

	case idx == len(providers):
		url := tuiInput("API URL", "https://api.example.com/v1/chat/completions", "")
		if url == "" {
			noteCancelled()
			return ProviderConfig{}, false
		}
		model := tuiInput("Model name", "e.g. my-model", "")
		if model == "" {
			noteCancelled()
			return ProviderConfig{}, false
		}
		envKey := tuiInput("API key env var", "leave empty if none", "")
		selected = ProviderConfig{
			Name:   "Custom",
			URL:    url,
			Model:  model,
			EnvKey: envKey,
		}
	default:
		noteCancelled()
		return ProviderConfig{}, false
	}

	return selected, true
}

// testProviderConnection runs the cheap "Say ok" round-trip against a
// picked provider and prints the result. Returns true on success.
func testProviderConnection(selected ProviderConfig) bool {
	if tuiInPage {
		// The settings page reports the result as a notice.
		cfg := LLMConfig{URL: selected.URL, Model: selected.Model, APIKey: selected.APIKey, Timeout: selected.Timeout, Protocol: selected.Protocol}
		if cfg.APIKey == "" && selected.EnvKey != "" {
			cfg.APIKey = os.Getenv(selected.EnvKey)
		}
		text, err := CallLLM(cfg, "Say ok", "ok", 256)
		return err == nil && text != ""
	}
	fmt.Print("Testing connection... ")
	cfg := LLMConfig{URL: selected.URL, Model: selected.Model, APIKey: selected.APIKey, Timeout: selected.Timeout, Protocol: selected.Protocol}
	if cfg.APIKey == "" && selected.EnvKey != "" {
		cfg.APIKey = os.Getenv(selected.EnvKey)
	}
	// max_tokens must leave room for reasoning/diffusion models (e.g.
	// inception/mercury-2) which consume budget internally before emitting any
	// visible content — at max_tokens=5 they return empty content
	// (finish_reason "length"), failing the test even though the model works
	// fine at real classifier token counts. 256 is cheap and universal.
	text, err := CallLLM(cfg, "Say ok", "ok", 256)
	switch {
	case err != nil:
		fmt.Printf("error: %v\n", err)
		return false
	case text != "":
		fmt.Println("ok")
		return true
	default:
		fmt.Println("unexpected response")
		return false
	}
}

// fetchOpenRouterFreeModels fetches the list of free models from OpenRouter.
func fetchOpenRouterFreeModels() []string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://openrouter.ai/api/v1/models")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}

	var models []string
	for _, m := range result.Data {
		if strings.HasSuffix(m.ID, ":free") {
			models = append(models, m.ID)
		}
	}
	return models
}

func checkOllama() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:11434/api/tags")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

func listOllamaModels() []string {
	out, err := exec.Command("ollama", "list").Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var models []string
	for _, line := range lines[1:] { // skip header
		parts := strings.Fields(line)
		if len(parts) > 0 {
			models = append(models, parts[0])
		}
	}
	return models
}

func cmdRules() {
	if len(os.Args) > 2 {
		switch os.Args[2] {
		case "defaults", "config", "review", "verify", "help", "-h", "--help":
			cmdClassifier(os.Args[2:])
			return
		}
	}

	// --trace prints every `.yolonot` yolonot actually loads (walk-up order),
	// shows each rule's source path + line, and marks shadowed entries —
	// answers "which ancestor .yolonot did this rule come from?".
	trace := false
	for _, a := range os.Args[2:] {
		if a == "--trace" || a == "-t" {
			trace = true
		}
	}

	if trace {
		cmdRulesTrace()
		return
	}

	// Default view: every loaded source, rules and hints listed per-source.
	paths := yolonotConfigSearchPaths()
	anyPrinted := false
	for _, path := range paths {
		rules := loadRulesFromFile(path)
		hints := loadHintsFromFile(path)
		if len(rules) == 0 && len(hints) == 0 {
			continue
		}
		anyPrinted = true
		fmt.Printf("%s:\n", path)
		for _, r := range rules {
			if r.Message != "" {
				fmt.Printf("  %s-%s %s  \"%s\"\n", r.Action, r.Type, r.Pattern, r.Message)
			} else {
				fmt.Printf("  %s-%s %s\n", r.Action, r.Type, r.Pattern)
			}
		}
		for _, h := range hints {
			fmt.Printf("  %s %q\n", h.Type, h.Text)
		}
		fmt.Println()
	}

	cfg := LoadConfig()
	if len(cfg.Prompt.Context) > 0 || len(cfg.Prompt.AllowHints) > 0 || len(cfg.Prompt.AskHints) > 0 || cfg.Prompt.SystemPrompt != "" {
		anyPrinted = true
		fmt.Printf("%s (prompt):\n", configPath())
		for _, c := range cfg.Prompt.Context {
			fmt.Printf("  context %q\n", c)
		}
		for _, h := range cfg.Prompt.AllowHints {
			fmt.Printf("  allow-hint %q\n", h)
		}
		for _, h := range cfg.Prompt.AskHints {
			fmt.Printf("  ask-hint %q\n", h)
		}
		if cfg.Prompt.SystemPrompt != "" {
			fmt.Printf("  system-prompt %q\n", truncateStr(cfg.Prompt.SystemPrompt, 80))
		}
		fmt.Println()
	}

	if !anyPrinted {
		fmt.Println("Rules: (none)")
		fmt.Println("Drop a .yolonot in this project or run `yolonot init`.")
	}

	patterns := LoadSensitivePatterns()
	if len(patterns) == 0 {
		fmt.Println("Sensitive file checks: disabled (opt-in)")
		fmt.Println("  Uncomment patterns in ~/.yolonot/rules, or add to any .yolonot file:")
		fmt.Println("    sensitive .env")
		fmt.Println("    sensitive .pem")
		fmt.Println("    sensitive .ssh/")
	} else {
		fmt.Printf("Sensitive file checks: enabled (%d patterns)\n", len(patterns))
		for _, pat := range patterns {
			fmt.Printf("  %s\n", pat)
		}
		fmt.Println()
		fmt.Println("  Disable with 'not-sensitive *' or remove individual patterns with 'not-sensitive <pattern>'.")
	}
}

// cmdRulesTrace shows every loaded rule with its source path + line number,
// and marks rules that are shadowed by earlier ones (same action+type+pattern,
// first-match-wins). Helps users answer "why is this rule in effect?" /
// "where did this rule come from?" after a walk-up load.
func cmdRulesTrace() {
	type entry struct {
		source     string
		line       int
		rule       Rule
		hint       *Hint
		shadowed   bool
		shadowedBy string
	}
	var all []entry
	seen := map[string]string{} // key -> first source:line

	paths := yolonotConfigSearchPaths()
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				continue
			}
			actionType := parts[0]
			switch actionType {
			case "context", "allow-hint", "ask-hint", "system-prompt":
				text := unquoteHintBody(parts[1])
				if text != "" {
					h := Hint{Type: actionType, Text: text}
					all = append(all, entry{source: path, line: lineNum, hint: &h})
				}
				continue
			}
			idx := strings.Index(actionType, "-")
			if idx < 0 {
				continue
			}
			action := actionType[:idx]
			ruleType := actionType[idx+1:]
			if (action != "allow" && action != "deny" && action != "ask") ||
				(ruleType != "cmd" && ruleType != "path" && ruleType != "redirect") {
				continue
			}
			pattern, message := splitTrailingMessage(parts[1])
			r := Rule{Action: action, Type: ruleType, Pattern: pattern, Message: message}
			key := r.Action + "-" + r.Type + " " + r.Pattern
			e := entry{source: path, line: lineNum, rule: r}
			if prev, ok := seen[key]; ok {
				e.shadowed = true
				e.shadowedBy = prev
			} else {
				seen[key] = fmt.Sprintf("%s:%d", path, lineNum)
			}
			all = append(all, e)
		}
		f.Close()
	}

	if len(all) == 0 {
		fmt.Println("No rules loaded.")
		return
	}

	repoRoot := ""
	if cwd, err := os.Getwd(); err == nil {
		abs, _ := filepath.Abs(cwd)
		repoRoot = findRepoRoot(abs)
	}
	if repoRoot == "" {
		fmt.Println("(cwd not in a git repo — walk-up disabled; only global rules loaded)")
	} else {
		fmt.Printf("(walk-up trust boundary: %s)\n", repoRoot)
	}
	fmt.Println()

	for _, e := range all {
		if e.hint != nil {
			fmt.Printf("  [hint   ] %s %q\n", e.hint.Type, e.hint.Text)
			fmt.Printf("            %s:%d\n", e.source, e.line)
			continue
		}
		tag := "active "
		if e.shadowed {
			tag = "shadow "
		}
		trailer := ""
		if e.rule.Message != "" {
			trailer = fmt.Sprintf("  \"%s\"", e.rule.Message)
		}
		fmt.Printf("  [%s] %s-%s %s%s\n", tag, e.rule.Action, e.rule.Type, e.rule.Pattern, trailer)
		fmt.Printf("            %s:%d", e.source, e.line)
		if e.shadowed {
			fmt.Printf(" (shadowed by %s)", e.shadowedBy)
		}
		fmt.Println()
	}
}

func cmdStatus() {
	args := os.Args[2:]
	if sliceHas(args, "--json") {
		cmdEffective(args)
		return
	}
	showAll := Verbose || sliceHas(args, "--all") || sliceHas(args, "--effective")
	explicitHarness := sliceHas(args, "--harness")
	sessionID := GetSessionIDFromEnv()
	if sessionID == "" {
		sessionID = FindSessionID()
	}
	if sessionID == "" {
		if isGloballyPaused() {
			fmt.Println("  ⚠ Globally PAUSED across all sessions (all commands bypass yolonot; run: yolonot resume --global)")
		} else {
			fmt.Println("No active session found.")
		}
		if showAll || explicitHarness {
			fmt.Println()
			cmdEffective(args)
		}
		return
	}

	cwd, _ := os.Getwd()
	projSessionID := ProjectSessionID(sessionID, cwd)

	approved := ReadLines(projSessionID, "approved")
	for _, cmd := range ReadLines(projSessionID, "approved_unsandboxed") {
		approved = append(approved, cmd+"  [unsandboxed]")
	}
	asked := ReadLines(projSessionID, "asked")
	denied := ReadLines(projSessionID, "denied")

	projName := filepath.Base(projectRoot(cwd))
	if projName == "" || projName == "." {
		projName = filepath.Base(cwd)
	}
	fmt.Printf("yolonot session: %s (project: %s)\n", sessionID, projName)
	if isGloballyPaused() {
		fmt.Printf("  ⚠ Globally PAUSED across all sessions (all commands bypass yolonot; run: yolonot resume --global)\n")
	} else if isPaused(sessionID) {
		fmt.Printf("  ⚠ Session %s is PAUSED (all commands bypass yolonot; run: yolonot resume)\n", sessionID)
	}
	fmt.Printf("  %d approved · %d asked · %d denied\n\n", len(approved), len(asked), len(denied))

	if len(approved) > 0 {
		fmt.Printf("APPROVED (%d):\n", len(approved))
		shown := approved
		const maxShown = 15
		if !showAll && len(shown) > maxShown {
			shown = shown[len(shown)-maxShown:]
		}
		for _, cmd := range shown {
			fmt.Printf("  ✓ %s\n", truncateStr(cmd, 80))
		}
		if !showAll && len(approved) > maxShown {
			fmt.Printf("  … and %d earlier approved commands (run `yolonot status --all` to see all)\n", len(approved)-maxShown)
		}
		fmt.Println()
	}
	if len(asked) > 0 {
		fmt.Printf("ASKED (%d):\n", len(asked))
		for _, cmd := range asked {
			fmt.Printf("  ? %s\n", truncateStr(cmd, 80))
		}
		fmt.Println()
	}
	if len(denied) > 0 {
		fmt.Printf("DENIED (%d):\n", len(denied))
		for _, cmd := range denied {
			fmt.Printf("  ✗ %s\n", truncateStr(cmd, 80))
		}
		fmt.Println()
	}
	if len(approved) == 0 && len(asked) == 0 && len(denied) == 0 {
		fmt.Println("No decisions recorded for this session yet.")
	}
	if showAll || explicitHarness {
		fmt.Println()
		cmdEffective(args)
	}
}

// normalizeCommand strips variable parts from a command for grouping.
// It takes the first 3 tokens, removes tokens that look like UUIDs,
// hex hashes, or long numeric IDs so that commands differing only in
// such variable parts get grouped together.
var idTokenRe = regexp.MustCompile(`^[0-9a-f]{8,}$|^\d{10,}$`)

// multiplexTools are commands where the subcommand verb (get/delete/apply/...)
// is the actual risk signal, not the head command. For these, normalize to
// "<tool> <verb>" by skipping flags and their values between the head and
// the first positional token. Without this, suggest buckets `kubectl get`
// and `kubectl delete` together under "kubectl --context X" and any
// allow/deny rule becomes catastrophic.
var multiplexTools = map[string]bool{
	"kubectl": true, "k": true,
	"docker": true, "podman": true,
	"helm": true,
	"aws":  true, "gcloud": true, "az": true,
	"git": true,
	"npm": true, "pnpm": true, "yarn": true, "bun": true,
	"pip": true, "pip3": true, "uv": true,
	"cargo": true, "go": true,
	"brew":      true,
	"terraform": true, "tf": true, "pulumi": true,
	"ansible": true, "ansible-playbook": true,
	"gh":        true,
	"systemctl": true, "service": true,
}

func normalizeCommand(cmd string) string {
	tokens := strings.Fields(cmd)
	if len(tokens) == 0 {
		return ""
	}
	head := tokens[0]
	// Strip a leading process-wrapper if present (sudo, rtk, time, nohup,
	// nice, ENV=value). These aren't the real head command — the next
	// non-wrapper token is.
	for len(tokens) > 1 && isProcessWrapper(head) {
		tokens = tokens[1:]
		head = tokens[0]
	}

	// Multiplex tools: walk past flags + flag values until the first
	// positional token, which is the subcommand verb. Bucket by
	// "<tool> <verb>" regardless of intervening --context, -n, --profile,
	// etc. Result: "kubectl get" and "kubectl delete" never share a bucket.
	if multiplexTools[head] && len(tokens) > 1 {
		if verb := extractSubcommandVerb(tokens[1:]); verb != "" {
			return head + " " + verb
		}
		return head
	}

	// Non-multiplex tools: preserve the existing 3-token fallback with
	// ID-token stripping. Catches simple cases like `rm /tmp/foo`,
	// `cat /etc/hosts`, where the entire command shape is the signal.
	if len(tokens) > 3 {
		tokens = tokens[:3]
	}
	var cleaned []string
	for _, tok := range tokens {
		if idTokenRe.MatchString(tok) {
			continue
		}
		cleaned = append(cleaned, tok)
	}
	if len(cleaned) == 0 {
		return tokens[0]
	}
	return strings.Join(cleaned, " ")
}

// isProcessWrapper reports whether tok is a transparent wrapper command
// that doesn't change the risk profile of what follows. Mirrors (a subset
// of) the fast-allow wrappers list; only the ones likely to appear in
// suggest history.
func isProcessWrapper(tok string) bool {
	if strings.Contains(tok, "=") {
		return true // ENV=value sh script.sh — assignment prefix
	}
	switch tok {
	case "sudo", "rtk", "time", "nohup", "nice", "command", "builtin":
		return true
	}
	return false
}

// extractSubcommandVerb returns up to two positional tokens after a
// multiplex tool, joined by space, skipping flags and their values.
// Returns "" if no positional token exists. Logic:
//
//   - "-X=value" or "--X=value" → skip (inline value, single token)
//   - "-X" or "--X" → skip; if next token doesn't start with "-" assume
//     it's the flag's value and skip that too
//   - first positional → start of verb; second positional if present is
//     joined ("docker compose down", "kubectl get pods", "aws s3 ls")
//
// Two positionals is the sweet spot: enough granularity to split
// `kubectl delete pod` from `kubectl delete deployment` (very different
// blast radius), without dragging in IDs and resource names that vary
// per invocation and would fragment buckets.
//
// Imperfect for boolean flags like `--all` or `-f` that genuinely take
// no value — we may consume an extra positional. Acceptable: rare in
// multiplex-tool usage and the failure mode is "verb is one token
// shorter than ideal", not wrong-bucket.
func extractSubcommandVerb(args []string) string {
	var verbs []string
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if !strings.HasPrefix(tok, "-") {
			verbs = append(verbs, tok)
			if len(verbs) >= 2 {
				break
			}
			continue
		}
		if strings.Contains(tok, "=") {
			continue // inline value, single token
		}
		// Long or short flag without inline value: consume next token
		// as its value if it doesn't look like another flag.
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			i++
		}
	}
	return strings.Join(verbs, " ")
}

// evolveContextLine summarises one logged decision for the suggest
// prompt: what the judges said and what they could not see.
func evolveContextLine(e DecisionEntry) string {
	parts := []string{"decision=" + e.Decision}
	if e.Risk != "" {
		parts = append(parts, "risk="+e.Risk)
	}
	if e.Escalated {
		switch {
		case e.EscalationError != "":
			parts = append(parts, "escalation="+e.EscalationError)
		case e.EscalationDecision != "":
			parts = append(parts, "escalation="+e.EscalationDecision+"/"+e.EscalationRisk+" ("+e.EscalationOutcome+")")
		}
	}
	if len(e.Withheld) > 0 {
		parts = append(parts, "not shown: "+strings.Join(e.Withheld, "; "))
	}
	if isAgentEntry(e) {
		parts = append(parts, "from a subagent")
	}
	if e.Reasoning != "" {
		parts = append(parts, "reason: "+truncateStr(e.Reasoning, 120))
	}
	return strings.Join(parts, ", ")
}

// timeWeight returns a weight for a decision based on how recent it is.
// Today's entries count full (1.0), last week 0.75, last month 0.5,
// older entries 0.25.
func timeWeight(ts string) float64 {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return 0.5
	}
	days := time.Since(t).Hours() / 24
	switch {
	case days < 1:
		return 1.0
	case days < 7:
		return 0.75
	case days < 30:
		return 0.5
	default:
		return 0.25
	}
}

// evolveFinding holds an aggregated pattern discovered by cmdEvolve.
type evolveFinding struct {
	Category string   `json:"category"`
	Pattern  string   `json:"pattern"`
	Count    int      `json:"count"`
	Weighted float64  `json:"weighted"`
	Approved int      `json:"approved,omitempty"`
	Once     int      `json:"once,omitempty"`
	Rejected int      `json:"rejected,omitempty"`
	Desc     string   `json:"desc"`
	Examples []string `json:"examples"`
	Context  []string `json:"context,omitempty"` // one line per example: verdicts, risk, escalation, withheld scripts
}

// evolveChange holds a rule chosen by the user during cmdEvolve.
type evolveChange struct {
	Rule  string
	Scope string // "p" or "g"
}

// collectEvolveFindings analyses decision entries and returns findings
// worth promoting to rules. Exported-style for testability but unexported.
func collectEvolveFindings(entries []DecisionEntry, existingRules []Rule) []evolveFinding {
	const weightThreshold = 2.0
	const maxExamples = 3

	type bucket struct {
		weighted float64
		count    int
		examples []string
		context  []string
	}
	type humanTally struct {
		approved int
		once     int
		rejected int
	}

	askBuckets := map[string]*bucket{}
	allowBuckets := map[string]*bucket{}
	timeoutBuckets := map[string]*bucket{}
	withheldBuckets := map[string]*bucket{}
	humanByPat := map[string]*humanTally{}
	add := func(buckets map[string]*bucket, pat string, e DecisionEntry, w float64) {
		b, ok := buckets[pat]
		if !ok {
			b = &bucket{}
			buckets[pat] = b
		}
		b.weighted += w
		b.count++
		if len(b.examples) < maxExamples {
			b.examples = append(b.examples, e.Command)
			b.context = append(b.context, evolveContextLine(e))
		}
	}

	for _, e := range entries {
		if e.Command == "" || e.BypassSandbox {
			continue
		}
		if e.Layer == "human" {
			pat := askShape(e.Command)
			if pat == "" {
				continue
			}
			ht := humanByPat[pat]
			if ht == nil {
				ht = &humanTally{}
				humanByPat[pat] = ht
			}
			switch {
			case e.Source == "allow_once":
				ht.once++
			case e.Source == "ask_rejected" || e.Decision == "deny":
				ht.rejected++
			case e.Source == "ask_approved" || e.Decision == "allow":
				ht.approved++
			}
			continue
		}
		isAsk := e.Decision == "ask" || e.OrigDecision == "ask"
		isJudgeOrCache := isModelLayer(e.Layer) || e.Layer == "cache"
		isLowConfAllow := e.Decision == "allow" && isJudgeOrCache && e.Confidence > 0 && e.Confidence < 0.8
		if !((isAsk && isJudgeOrCache) || isLowConfAllow) {
			continue
		}
		pat := askShape(e.Command)
		if pat == "" {
			continue
		}
		w := timeWeight(e.Timestamp)

		switch {
		case isAsk && isJudgeOrCache && len(e.Withheld) > 0:
			// Keyed by the script the judge could not see: the fix is a hint
			// about that script, whatever command shape invoked it.
			path := e.Withheld[0]
			if i := strings.Index(path, ": "); i > 0 {
				path = path[:i]
			}
			add(withheldBuckets, path, e, w)
		case isAsk && isJudgeOrCache && e.EscalationError == "timeout":
			add(timeoutBuckets, pat, e, w)
		case isAsk && isJudgeOrCache:
			add(askBuckets, pat, e, w)
		case isLowConfAllow:
			add(allowBuckets, pat, e, w)
		}
	}

	var findings []evolveFinding

	addFindings := func(buckets map[string]*bucket, category, descFmt string) {
		for pat, b := range buckets {
			if b.weighted < weightThreshold {
				continue
			}
			// Skip patterns already covered by existing rules
			sample := pat + " test"
			if category == "SCRIPT NOT SHOWN" {
				sample = "bash " + pat
			}
			if MatchRuleWith(sample, existingRules, nil) != nil {
				continue
			}
			f := evolveFinding{
				Category: category,
				Pattern:  pat,
				Count:    b.count,
				Weighted: b.weighted,
				Desc:     fmt.Sprintf(descFmt, b.count, b.weighted),
				Examples: b.examples,
				Context:  b.context,
			}
			if ht := humanByPat[pat]; ht != nil {
				f.Approved = ht.approved
				f.Once = ht.once
				f.Rejected = ht.rejected
				var parts []string
				if ht.approved > 0 {
					parts = append(parts, fmt.Sprintf("%d approved", ht.approved))
				}
				if ht.once > 0 {
					parts = append(parts, fmt.Sprintf("%d once", ht.once))
				}
				if ht.rejected > 0 {
					parts = append(parts, fmt.Sprintf("%d rejected", ht.rejected))
				}
				if len(parts) > 0 {
					f.Desc += " · human: " + strings.Join(parts, ", ")
				}
			}
			findings = append(findings, f)
		}
	}

	addFindings(withheldBuckets, "SCRIPT NOT SHOWN", "asked %dx with this script unseen by the judge (weighted: %.1f)")
	addFindings(timeoutBuckets, "ESCALATION TIMEOUT", "asked %dx because the second model timed out (weighted: %.1f)")
	addFindings(askBuckets, "REPEATED ASK", "asked %dx (weighted: %.1f)")
	addFindings(allowBuckets, "RISKY ALLOW", "allowed %dx at low confidence (weighted: %.1f)")

	// Sort by weighted score descending for consistent presentation
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Weighted > findings[j].Weighted
	})

	return findings
}

func cmdEvolve(args []string) {
	// --basic disables LLM-driven suggestions and falls back to the
	// statistics-only flow. --list / -l prints non-interactive findings
	// and candidate rules (also auto-selected when stdin is not a terminal
	// so skills and pipes never hang on /dev/tty). --json emits structured JSON.
	basic := false
	listMode := false
	jsonMode := false
	for _, a := range args {
		switch a {
		case "--basic":
			basic = true
		case "--list", "-l":
			listMode = true
		case "--json":
			jsonMode = true
		case "--help", "-h":
			fmt.Println("Usage: yolonot suggest [--list | --json] [--basic]")
			fmt.Println()
			fmt.Println("  --list, -l  Print findings and candidate rules without interactive TUI")
			fmt.Println("  --json      Emit findings and candidate rules as JSON")
			fmt.Println("  --basic     Skip LLM-driven action recommendation; show only the")
			fmt.Println("              statistics-derived hint/rule templates.")
			return
		}
	}
	if !listMode && !jsonMode && !stdinIsTerminal() {
		listMode = true
	}

	entries := ReadRecentDecisions(10000) // read all
	if len(entries) == 0 {
		if jsonMode {
			fmt.Println(`{"analyzed":0,"findings":[],"candidates":[]}`)
			return
		}
		fmt.Println("No decision log found. Use yolonot for a while first.")
		return
	}

	cwd, _ := os.Getwd()
	existingRules := LoadRules()
	findings := collectEvolveFindings(entries, existingRules)
	candidates := collectLearningCandidates(cwd, entries, existingRules)

	if len(findings) == 0 && len(candidates) == 0 {
		if jsonMode {
			fmt.Printf(`{"analyzed":%d,"findings":[],"candidates":[]}`+"\n", len(entries))
			return
		}
		fmt.Println("No patterns found worth promoting. Use yolonot more to build history.")
		return
	}

	// Smart-suggest cache: persisted across runs so a tuning session
	// doesn't re-pay LLM cost for already-judged patterns. Loaded
	// once, written eagerly per new judgment in cachedOrSmart.
	cache := loadSuggestCache()
	smartEnabled := !basic && GetLLMConfig().URL != "" && GetLLMConfig().Model != ""

	if jsonMode {
		type jsonFinding struct {
			evolveFinding
			Recommended *SmartSuggestion `json:"recommended,omitempty"`
		}
		outFindings := make([]jsonFinding, 0, len(findings))
		for _, f := range findings {
			jf := jsonFinding{evolveFinding: f}
			if smartEnabled {
				if s, ok := cachedOrSmart(f, &cache); ok && s.Action != "skip" {
					jf.Recommended = &s
				}
			}
			outFindings = append(outFindings, jf)
		}
		payload := struct {
			Analyzed   int                 `json:"analyzed"`
			Findings   []jsonFinding       `json:"findings"`
			Candidates []learningCandidate `json:"candidates"`
		}{
			Analyzed:   len(entries),
			Findings:   outFindings,
			Candidates: candidates,
		}
		if payload.Candidates == nil {
			payload.Candidates = []learningCandidate{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(payload)
		return
	}

	fmt.Printf("SUGGEST: Analyzed %d decisions\n\n", len(entries))

	if listMode {
		for i, f := range findings {
			fmt.Printf("[%d/%d] %s  %q — %s\n", i+1, len(findings), f.Category, f.Pattern, f.Desc)
			if len(f.Examples) > 0 {
				fmt.Println("  Examples:")
				for _, ex := range f.Examples {
					fmt.Printf("    %s\n", truncateStr(strings.ReplaceAll(ex, "\n", " ⏎ "), 80))
				}
			}
			if smartEnabled {
				if smart, ok := cachedOrSmart(f, &cache); ok && smart.Action != "skip" {
					fmt.Printf("  ✦ Recommended: %s\n", smartActionToRule(smart))
					if smart.Reason != "" {
						fmt.Printf("    Reason: %s\n", smart.Reason)
					}
				}
			}
			if f.Category == "SCRIPT NOT SHOWN" {
				fmt.Printf("  Rule options: allow-path %s  |  ask-path %s\n", f.Pattern, f.Pattern)
			} else {
				fmt.Printf("  Hint option:  allow-hint \"%s is read-only routine\"\n", f.Pattern)
				fmt.Printf("  Rule option:  allow-cmd %s*\n", f.Pattern)
			}
			fmt.Println()
		}
		if len(candidates) > 0 {
			printLearningCandidateList(candidates)
		}
		return
	}

	if len(findings) == 0 {
		printLearningCandidateList(candidates)
		return
	}

	var changes []evolveChange

	// Labeled loop so `break suggestLoop` inside the nested action switch
	// reliably aborts the session. Without the label, `break` only exits
	// the switch, leaving the for-loop to silently advance to the next
	// finding when the user cancels a scope picker. Cancellation is the
	// session-end signal here, never a "skip just this one".
suggestLoop:
	for i, f := range findings {
		// Print finding with examples
		fmt.Printf("[%d/%d] \"%s\" -- %s\n", i+1, len(findings), f.Pattern, f.Desc)
		if len(f.Examples) > 0 {
			fmt.Println("  Examples:")
			for _, ex := range f.Examples {
				cmd := truncateStr(strings.ReplaceAll(ex, "\n", " ⏎ "), 80)
				fmt.Printf("    %s\n", cmd)
			}
		}
		fmt.Println()

		// Smart-suggest: ask the LLM to read the examples and propose a
		// specific recommendation. Inserts at position 0 with prefilled
		// prose so user just hits Enter to accept. Falls through
		// silently if --basic or no provider.
		var smart SmartSuggestion
		hasSmart := false
		if smartEnabled {
			smart, hasSmart = cachedOrSmart(f, &cache)
		}

		// TUI action selection. Hint options come first because vague
		// buckets (kubectl/aws/git, where the same prefix covers both
		// destructive and read-only ops) are common and a glob rule is
		// usually the wrong fix — auto-allow would catch the
		// destructive sibling on next match. Hints are prose that the
		// LLM reads, so they can describe risk-class boundaries that a
		// glob can't.
		isScriptNotShown := f.Category == "SCRIPT NOT SHOWN"
		ruleAllowItem := fmt.Sprintf("rule allow → allow-cmd %s*  (risk: matches destructive siblings)", f.Pattern)
		ruleDenyItem := fmt.Sprintf("rule deny  → deny-cmd *%s*  (risk: blocks legit siblings)", f.Pattern)
		ruleAskItem := fmt.Sprintf("rule ask   → ask-cmd *%s*", f.Pattern)
		if isScriptNotShown {
			ruleAllowItem = fmt.Sprintf("rule allow → allow-path %s", f.Pattern)
			ruleDenyItem = fmt.Sprintf("rule deny  → deny-path %s", f.Pattern)
			ruleAskItem = fmt.Sprintf("rule ask   → ask-path %s", f.Pattern)
		}
		baseItems := []string{
			fmt.Sprintf("hint allow → allow-hint \"%s on <add scope> is routine\"", f.Pattern),
			fmt.Sprintf("hint ask   → ask-hint \"%s mutating ops always confirm\"", f.Pattern),
			ruleAllowItem,
			ruleDenyItem,
			ruleAskItem,
			"skip",
		}
		var items []string
		smartOffset := 0
		if hasSmart && smart.Action != "skip" {
			label := fmt.Sprintf("✦ recommended: %s → %s", smart.Action, truncateForDisplay(smart.Text, 60))
			if smart.Reason != "" {
				label += fmt.Sprintf("  (%s)", truncateForDisplay(smart.Reason, 50))
			}
			items = append(items, label)
			smartOffset = 1
		}
		items = append(items, baseItems...)

		defaultIdx := len(items) - 1 // skip
		if hasSmart && smart.Action != "skip" {
			defaultIdx = 0 // prefer recommendation
		}
		idx := tuiSelect(
			fmt.Sprintf("\"%s\" (%s)", f.Pattern, f.Desc),
			items, defaultIdx)

		if idx < 0 {
			break suggestLoop // cancelled
		}

		// Map the chosen index back through the smart-offset. If user
		// picked option 0 with smart enabled, treat as "apply
		// recommendation"; otherwise subtract offset and route to the
		// existing baseItems handlers.
		if smartOffset == 1 && idx == 0 {
			scope := pickEvolveScopeWithDefault(smart.Action)
			if scope == "" {
				break suggestLoop
			}
			rule := smartActionToRule(smart)
			if rule == "" {
				continue
			}
			changes = append(changes, evolveChange{Rule: rule, Scope: scope})
			continue
		}
		idx -= smartOffset

		// Branch: hint vs glob rule. Both end up as text appended to a
		// file at the chosen scope; the difference is which file
		// section / format the user picks.
		switch idx {
		case 0: // hint allow
			defText := fmt.Sprintf("%s is read-only routine", f.Pattern)
			text := tuiInput("allow-hint prose", defText, defText)
			if text == "" {
				continue
			}
			scopeIdx := tuiSelect("Scope (where to save the hint)", []string{
				"project (.yolonot)",
				"global (~/.yolonot/rules)",
			}, 0)
			if scopeIdx < 0 {
				break suggestLoop
			}
			scope := "p"
			if scopeIdx == 1 {
				scope = "g"
			}
			changes = append(changes, evolveChange{
				Rule:  fmt.Sprintf("allow-hint %q", text),
				Scope: scope,
			})
		case 1: // hint ask
			defText := fmt.Sprintf("%s mutating operations always require confirmation", f.Pattern)
			text := tuiInput("ask-hint prose", defText, defText)
			if text == "" {
				continue
			}
			scopeIdx := tuiSelect("Scope (where to save the hint)", []string{
				"project (.yolonot)",
				"global (~/.yolonot/rules)",
			}, 0)
			if scopeIdx < 0 {
				break suggestLoop
			}
			scope := "p"
			if scopeIdx == 1 {
				scope = "g"
			}
			changes = append(changes, evolveChange{
				Rule:  fmt.Sprintf("ask-hint %q", text),
				Scope: scope,
			})
		case 2, 3, 4: // glob rules (existing behavior)
			var rule string
			defScopeIdx := 0
			switch idx {
			case 2:
				if isScriptNotShown {
					rule = fmt.Sprintf("allow-path %s", f.Pattern)
				} else {
					rule = fmt.Sprintf("allow-cmd %s*", f.Pattern)
				}
			case 3:
				if isScriptNotShown {
					rule = fmt.Sprintf("deny-path %s", f.Pattern)
				} else {
					rule = fmt.Sprintf("deny-cmd *%s*", f.Pattern)
				}
				defScopeIdx = 1
			case 4:
				if isScriptNotShown {
					rule = fmt.Sprintf("ask-path %s", f.Pattern)
				} else {
					rule = fmt.Sprintf("ask-cmd *%s*", f.Pattern)
				}
				defScopeIdx = 1
			}
			scopeIdx := tuiSelect("Scope", []string{
				"project (.yolonot)",
				"global (~/.yolonot/rules)",
			}, defScopeIdx)
			if scopeIdx < 0 {
				break suggestLoop
			}
			scope := "p"
			if scopeIdx == 1 {
				scope = "g"
			}
			changes = append(changes, evolveChange{rule, scope})
		default:
			continue // skip
		}
	}

	if len(candidates) > 0 {
		printLearningCandidateList(candidates)
	}

	if len(changes) == 0 {
		fmt.Println("No changes to apply.")
		return
	}

	fmt.Println("\nChanges to apply:")
	for _, c := range changes {
		target := ".yolonot (project)"
		if c.Scope == "g" {
			target = "~/.yolonot/rules (global)"
		}
		fmt.Printf("  + %s -> %s\n", c.Rule, target)
	}

	if !tuiConfirm("Apply these changes?") {
		noteCancelled()
		return
	}

	header := fmt.Sprintf("\n# Suggested by yolonot (%s)\n", time.Now().Format("2006-01-02"))

	for _, c := range changes {
		var path string
		if c.Scope == "g" {
			path = filepath.Join(YolonotDir(), "rules")
		} else {
			path = filepath.Join(cwd, ".yolonot")
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("  Error writing %s: %v\n", path, err)
			continue
		}
		f.WriteString(header)
		f.WriteString(c.Rule + "\n")
		f.Close()
		header = "" // only write header once per file
		fmt.Printf("  Updated %s\n", path)
	}
	fmt.Println("Done.")

}

func cmdQuiet(args []string) {
	cfg := LoadConfig()

	if len(args) == 0 {
		if cfg.QuietOnAllow {
			fmt.Println("Quiet on approve: ON")
			fmt.Println("  Banners shown only for ask/deny. Allow decisions are silent.")
		} else {
			fmt.Println("Quiet on approve: OFF")
			fmt.Println("  Banners shown for every decision (allow / ask / deny).")
		}
		fmt.Println()
		fmt.Println("Usage: yolonot config quiet [on|off]")
		return
	}

	switch strings.ToLower(args[0]) {
	case "on", "true", "1", "yes", "y":
		cfg.QuietOnAllow = true
	case "off", "false", "0", "no", "n":
		cfg.QuietOnAllow = false
	default:
		fmt.Fprintf(os.Stderr, "Unknown value: %s (expected on|off)\n", args[0])
		return
	}
	if !requireV1(&cfg) {
		return
	}
	mustSaveConfig(cfg)
	if cfg.QuietOnAllow {
		fmt.Println("Quiet on approve: ON — allow decisions will be silent.")
	} else {
		fmt.Println("Quiet on approve: OFF — banners shown for every decision.")
	}
}

// cmdRisk shows or updates the per-harness risk→action map via `yolonot profile`.
func cmdRisk(args []string) {
	if len(args) == 0 {
		h := ActiveHarness()
		if h == nil {
			fmt.Fprintln(os.Stderr, "No active harness detected.")
			return
		}
		printRiskMap(h)
		return
	}

	harnessName := args[0]
	h := GetHarness(harnessName)
	if h == nil {
		fmt.Fprintf(os.Stderr, "Unknown harness %q. Known: ", harnessName)
		names := []string{}
		for _, hh := range Harnesses() {
			names = append(names, hh.Name())
		}
		fmt.Fprintln(os.Stderr, strings.Join(names, ", "))
		return
	}

	if len(args) == 1 {
		printRiskMap(h)
		return
	}

	if args[1] == "reset" || (len(args) == 3 && args[2] == "reset") {
		cfg := LoadConfig()
		if !requireV1(&cfg) {
			return
		}
		if len(args) == 2 {
			hp := cfg.harnessPolicy(h.Name())
			hp.RiskMap = nil
			cfg.setHarnessPolicy(h.Name(), hp)
			mustSaveConfig(cfg)
			fmt.Printf("Reset all risk overrides for %s.\n", h.Name())
			return
		}
		tier := args[2]
		if args[2] == "reset" {
			tier = args[1]
		}
		if !isValidRisk(tier) {
			fmt.Fprintf(os.Stderr, "Invalid tier %q. Valid: %s\n", tier, strings.Join(allRiskTiers, ", "))
			return
		}
		hp := cfg.harnessPolicy(h.Name())
		delete(hp.RiskMap, tier)
		if len(hp.RiskMap) == 0 {
			hp.RiskMap = nil
		}
		cfg.setHarnessPolicy(h.Name(), hp)
		mustSaveConfig(cfg)
		fmt.Printf("Reset %s/%s to default.\n", h.Name(), tier)
		return
	}

	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: yolonot profile <harness> <tier> <action>")
		return
	}
	tier, action := args[1], normalizeRiskAction(args[2])
	if !isValidRisk(tier) {
		fmt.Fprintf(os.Stderr, "Invalid tier %q. Valid: %s\n", tier, strings.Join(allRiskTiers, ", "))
		return
	}
	if action == ActionForceAllow && tier == RiskCritical {
		fmt.Fprintln(os.Stderr, "Invalid action: force_allow cannot be used on the critical tier.")
		return
	}
	if !isValidActionForTier(tier, action) {
		fmt.Fprintf(os.Stderr, "Invalid action %q. Valid: allow, force_allow, ask, deny, passthrough\n", args[2])
		return
	}
	cfg := LoadConfig()
	if !requireV1(&cfg) {
		return
	}
	hp := cfg.harnessPolicy(h.Name())
	if hp.RiskMap == nil {
		hp.RiskMap = map[string]string{}
	}
	hp.RiskMap[tier] = action
	cfg.setHarnessPolicy(h.Name(), hp)
	mustSaveConfig(cfg)
	fmt.Printf("%s/%s → %s\n", h.Name(), tier, action)
}

func printRiskMap(h Harness) {
	defer prepareHarnessCapabilities(h)()
	defaults := h.RiskMap()
	effective := ResolveRiskMap(h)
	cfg := LoadConfig()
	overrides := cfg.harnessPolicy(h.Name()).RiskMap
	fmt.Printf("Risk map for harness %q:\n", h.Name())

	// Header: which profile is active for this harness, including env / session pins.
	active := ResolveActiveProfile(cfg, h)
	if active != nil {
		envHarnessKey := "YOLONOT_" + strings.ToUpper(h.Name()) + "_PROFILE"
		sid := currentSessionID(h)
		switch {
		case sid != "" && readSessionProfile(sid) != "":
			fmt.Printf("  Profile: %s (mid-session pin, %s)\n\n", active.Name, shortSession(sid))
		case os.Getenv(envHarnessKey) != "":
			fmt.Printf("  Profile: %s (env %s, this session only)\n\n", active.Name, envHarnessKey)
		case os.Getenv("YOLONOT_PROFILE") != "":
			fmt.Printf("  Profile: %s (env YOLONOT_PROFILE, this session only)\n\n", active.Name)
		default:
			globalName := cfg.Policy.Profile
			if globalName == "" {
				globalName = DefaultProfileName
			}
			if v := cfg.harnessPolicy(h.Name()).Profile; v != "" && v != globalName {
				fmt.Printf("  Profile: %s (global) → %s (override)\n\n", globalName, v)
			} else {
				fmt.Printf("  Profile: %s\n\n", active.Name)
			}
		}
	}

	// Pre-compute the profile-translated layer to label provenance accurately.
	var profileLayer map[string]string
	if active != nil {
		profileLayer = TranslateProfile(active.Map, h)
	}

	fmt.Printf("  %-9s  %-12s  %s\n", "tier", "action", "source")
	for _, tier := range allRiskTiers {
		source := "default"
		shippedDefault := defaults[tier]
		if profileLayer != nil {
			if v, ok := profileLayer[tier]; ok && v != shippedDefault {
				source = "profile=" + active.Name
			}
		}
		if _, ok := overrides[tier]; ok {
			source = "config"
		}
		envKey := "YOLONOT_" + strings.ToUpper(h.Name()) + "_RISK_" + strings.ToUpper(tier)
		if os.Getenv(envKey) != "" {
			source = "env " + envKey
		}
		fmt.Printf("  %-9s  %-12s  %s\n", tier, effective[tier], source)
	}
}

var typesafeDecision = ProviderConfig{Name: "TypeSafe Jev", URL: decisionDefaultURL, Model: "jev-latest", EnvKey: "TYPESAFE_API_KEY", Timeout: 10}

// decisionPresets are the decision endpoints verified live to answer the
// yolonot question set. OpenRouter serves several models on one URL.
var decisionPresets = []struct {
	Name   string
	URL    string
	Models []string
	EnvKey string
}{
	{"TypeSafe Jev", decisionDefaultURL, []string{"jev-latest"}, "TYPESAFE_API_KEY"},
	{"OpenRouter", openRouterSystemOneURL, []string{"typesafe/jev-1.13", "microsoft/microsoft-decision-1"}, "OPENROUTER_API_KEY"},
	{"OpenAI Decisions", openAIDecisionsURL, []string{"gpt-6-luna"}, "OPENAI_API_KEY"},
	{"Cloudflare Workers AI", workersAIClefURL, []string{"clef-flash", "clef"}, "CLOUDFLARE_API_TOKEN"},
}

// pickDecisionProvider chooses the typed decision model. "Custom" takes
// any System One URL. ok=false on cancel.
func pickDecisionProvider() (ProviderConfig, bool) {
	var items []string
	for _, p := range decisionPresets {
		status := "ready"
		if os.Getenv(p.EnvKey) == "" {
			status = "key missing"
		}
		items = append(items, fmt.Sprintf("%-30s %-26s %s", p.Name, p.Models[0], status))
	}
	items = append(items, "Custom System One endpoint")
	idx := tuiSelect("Decision model", items, 0)
	switch {
	case idx < 0:
		return ProviderConfig{}, false
	case idx == len(decisionPresets):
		url := tuiInput("API URL", "https://api.example.com/v1/systemone", "")
		if url == "" {
			return ProviderConfig{}, false
		}
		model := tuiInput("Model name", "e.g. jev-latest", "")
		if model == "" {
			return ProviderConfig{}, false
		}
		envKey := tuiInput("API key env var", "leave empty if none", "")
		return ProviderConfig{Name: "custom", URL: url, Model: model, EnvKey: envKey, Timeout: 10}, true
	}
	p := decisionPresets[idx]
	model := p.Models[0]
	if len(p.Models) > 1 {
		choices := append(append([]string{}, p.Models...), "Other (type name)")
		m := tuiSelect("Select "+p.Name+" model", choices, 0)
		if m < 0 {
			return ProviderConfig{}, false
		}
		if m == len(choices)-1 {
			model = tuiInput("Model name", "", "")
		} else {
			model = choices[m]
		}
		if model == "" {
			return ProviderConfig{}, false
		}
	}
	url := p.URL
	if strings.Contains(url, "{account_id}") {
		account := tuiInput("Cloudflare account id", "32 hex characters", os.Getenv("CLOUDFLARE_ACCOUNT_ID"))
		if account == "" {
			return ProviderConfig{}, false
		}
		// Workers AI addresses the model in the path; the body's "model" is the short name.
		url = strings.Replace(url, "{account_id}", account, 1) + model
	}
	return ProviderConfig{Name: p.Name, URL: url, Model: model, EnvKey: p.EnvKey, Timeout: 10}, true
}
