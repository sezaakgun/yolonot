package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ProviderConfig struct {
	Name    string `json:"name,omitempty"`
	URL     string `json:"url,omitempty"`
	Model   string `json:"model,omitempty"`
	EnvKey  string `json:"env_key,omitempty"`
	APIKey  string `json:"api_key,omitempty"`
	Timeout int    `json:"timeout,omitempty"` // LLM call timeout in seconds
}

type Config struct {
	Provider            ProviderConfig `json:"provider"`
	ConfidenceThreshold float64        `json:"confidence_threshold,omitempty"` // 0 = disabled (default)
	PreCheck            PreCheckList   `json:"pre_check,omitempty"`            // optional external hooks (e.g. dippy-hook) run before yolonot's pipeline; first "allow" wins
	QuietOnAllow        bool           `json:"quiet_on_allow,omitempty"`       // when true, allow decisions emit no systemMessage — only ask/deny show a banner
}

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

func settingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "settings.json")
}

func LoadConfig() Config {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return Config{}
	}
	var c Config
	json.Unmarshal(data, &c)
	return c
}

func SaveConfig(c Config) {
	os.MkdirAll(YolonotDir(), 0755)
	data, _ := json.MarshalIndent(c, "", "  ")
	os.WriteFile(configPath(), append(data, '\n'), 0600)
	Verbosef("wrote %s (%d bytes)", configPath(), len(data)+1)
}

func loadSettings() map[string]interface{} {
	data, err := os.ReadFile(settingsPath())
	if err != nil {
		return map[string]interface{}{}
	}
	var s map[string]interface{}
	json.Unmarshal(data, &s)
	return s
}

func saveSettings(s map[string]interface{}) {
	data, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile(settingsPath(), append(data, '\n'), 0644)
}

func binaryPath() string {
	exe, _ := os.Executable()
	return exe
}

func IsInstalled() bool {
	s := loadSettings()
	hooks, _ := s["hooks"].(map[string]interface{})
	pre, _ := hooks["PreToolUse"].([]interface{})
	for _, entry := range pre {
		if e, ok := entry.(map[string]interface{}); ok {
			if hs, ok := e["hooks"].([]interface{}); ok {
				for _, h := range hs {
					if hm, ok := h.(map[string]interface{}); ok {
						if cmd, ok := hm["command"].(string); ok && strings.Contains(cmd, "yolonot") {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func cmdInstall() {
	if IsInstalled() {
		// Update: remove old hooks, reinstall with current settings
		Verbosef("existing install detected — removing old hooks from %s", settingsPath())
		removeHooks()
		fmt.Println("Updating yolonot hooks...")
	}

	s := loadSettings()
	hooks, _ := s["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = map[string]interface{}{}
		s["hooks"] = hooks
	}

	bp := binaryPath() + " hook"

	preHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 60.0}
	postHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 60.0}

	// PreToolUse: add to existing Bash entry or create before catch-all
	addHookToEvent(hooks, "PreToolUse", "Bash", preHook)
	// PostToolUse: add to existing Bash entry or create at start
	addHookToEvent(hooks, "PostToolUse", "Bash", postHook)

	saveSettings(s)
	Verbosef("wrote %s (Bash matcher for PreToolUse + PostToolUse, timeout 60s)", settingsPath())

	// Create data directories
	os.MkdirAll(filepath.Join(YolonotDir(), "sessions"), 0755)
	os.MkdirAll(filepath.Join(YolonotDir(), "cache"), 0755)
	Verbosef("ensured %s and %s",
		filepath.Join(YolonotDir(), "sessions"),
		filepath.Join(YolonotDir(), "cache"))

	// Install skill
	installSkill()

	fmt.Println("yolonot installed.")
	fmt.Printf("  Hook command → %s\n", bp)
	fmt.Printf("  Data dir     → %s\n", YolonotDir())
	fmt.Println()
	fmt.Println("Run 'yolonot init' to create rule files.")
	fmt.Println("Run 'yolonot provider' to configure LLM.")
	fmt.Println("Restart Claude Code to activate.")
}

func installSkill() {
	home, _ := os.UserHomeDir()
	skillDir := filepath.Join(home, ".claude", "skills", "yolonot")
	skillDst := filepath.Join(skillDir, "SKILL.md")

	os.MkdirAll(skillDir, 0755)
	os.WriteFile(skillDst, embeddedSkillMD, 0644)
	Verbosef("wrote SKILL.md to %s (%d bytes)", skillDst, len(embeddedSkillMD))
	fmt.Printf("  Skill      → %s\n", skillDir)
}

func addHookToEvent(hooks map[string]interface{}, event, matcher string, hook map[string]interface{}) {
	entries, _ := hooks[event].([]interface{})

	// Try to add to existing entry with same matcher
	for _, entry := range entries {
		if e, ok := entry.(map[string]interface{}); ok {
			if m, _ := e["matcher"].(string); m == matcher {
				hs, _ := e["hooks"].([]interface{})
				e["hooks"] = append(hs, hook)
				return
			}
		}
	}

	// Insert before catch-all (.*) or append
	newEntry := map[string]interface{}{
		"matcher": matcher,
		"hooks":   []interface{}{hook},
	}
	insertIdx := len(entries)
	for i, entry := range entries {
		if e, ok := entry.(map[string]interface{}); ok {
			if m, _ := e["matcher"].(string); m == ".*" {
				insertIdx = i
				break
			}
		}
	}
	// Insert at position
	entries = append(entries, nil)
	copy(entries[insertIdx+1:], entries[insertIdx:])
	entries[insertIdx] = newEntry
	hooks[event] = entries
}

// removeHooks strips all yolonot hooks from settings.json, preserving other hooks.
func removeHooks() {
	s := loadSettings()
	hooks, _ := s["hooks"].(map[string]interface{})

	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		entries, _ := hooks[event].([]interface{})
		var newEntries []interface{}
		for _, entry := range entries {
			if e, ok := entry.(map[string]interface{}); ok {
				hs, _ := e["hooks"].([]interface{})
				var remaining []interface{}
				for _, h := range hs {
					if hm, ok := h.(map[string]interface{}); ok {
						if cmd, _ := hm["command"].(string); strings.Contains(cmd, "yolonot") {
							continue
						}
					}
					remaining = append(remaining, h)
				}
				if len(remaining) > 0 {
					e["hooks"] = remaining
					newEntries = append(newEntries, e)
				}
			}
		}
		hooks[event] = newEntries
	}

	saveSettings(s)
}

func cmdUninstall() {
	if !IsInstalled() {
		fmt.Println("yolonot is not installed.")
		return
	}

	Verbosef("stripping yolonot hooks from %s", settingsPath())
	removeHooks()

	// Remove skill
	home, _ := os.UserHomeDir()
	skillDir := filepath.Join(home, ".claude", "skills", "yolonot")
	Verbosef("removing skill dir %s", skillDir)
	os.RemoveAll(skillDir)

	fmt.Println("yolonot uninstalled. Restart Claude Code to deactivate.")
	fmt.Printf("Data preserved at %s — delete manually if wanted.\n", YolonotDir())
}

func cmdInit() {
	os.MkdirAll(filepath.Join(YolonotDir(), "sessions"), 0755)
	os.MkdirAll(filepath.Join(YolonotDir(), "cache"), 0755)

	// Global rules
	globalRules := filepath.Join(YolonotDir(), "rules")
	if _, err := os.Stat(globalRules); os.IsNotExist(err) {
		os.WriteFile(globalRules, []byte(`# ~/.yolonot/rules — global rules (apply to all projects)
# Format: <action>-<type> <pattern>

# --- Yolonot self-operations (always allow) ---
allow-cmd echo $CLAUDE_SESSION_ID*
allow-cmd *yolonot *
allow-cmd cat */.yolonot/*
allow-cmd ls */.yolonot/*
allow-cmd wc */.yolonot/*
allow-cmd tail */.yolonot/*
allow-cmd head */.yolonot/*
allow-cmd grep */.yolonot/*

# --- Read-only commands (chained commands bypass these → LLM) ---
allow-cmd cat *
allow-cmd ls *
allow-cmd head *
allow-cmd tail *
allow-cmd grep *
allow-cmd rg *
allow-cmd find *
allow-cmd wc *
allow-cmd tree *
allow-cmd echo *
allow-cmd pwd*
allow-cmd which *
allow-cmd file *
allow-cmd stat *
allow-cmd du *
allow-cmd df *
allow-cmd env*
allow-cmd printenv*
allow-cmd id*
allow-cmd whoami*
allow-cmd uname*
allow-cmd date*
allow-cmd hostname*

# --- Safe file/dir creation (non-destructive) ---
allow-cmd mkdir *
allow-cmd touch *

# --- Safe network (local only) ---
allow-cmd curl localhost*
allow-cmd curl 127.0.0.1*
allow-cmd curl 0.0.0.0*
allow-cmd curl http://localhost*
allow-cmd curl http://127.0.0.1*
allow-cmd curl http://0.0.0.0*
allow-cmd curl -s localhost*
allow-cmd curl -s http://localhost*

# --- Dangerous patterns ---
deny-cmd *rm -rf /*
deny-cmd *sudo *
deny-cmd *chmod 777*
deny-cmd *> /dev/sd*
deny-cmd *mkfs*
deny-cmd *dd if=*

# --- Uncertain ---
ask-cmd *curl *
ask-cmd *wget *

# --- Sensitive file patterns ---
# Commands touching these skip allow rules so the LLM evaluates the risk.
# Disabled by default. Uncomment patterns you want to protect.
# sensitive .env
# sensitive .pem
# sensitive .key
# sensitive .crt
# sensitive .p12
# sensitive .pfx
# sensitive .jks
# sensitive .ssh/
# sensitive .aws/
# sensitive .gnupg/
# sensitive .kube/config
# sensitive credentials
# sensitive secrets
# sensitive password
# sensitive token
# sensitive /etc/shadow
# sensitive /etc/passwd
# sensitive /etc/sudoers
# sensitive id_rsa
# sensitive id_ed25519
# sensitive id_ecdsa
# sensitive .netrc
# sensitive .pgpass
# sensitive .my.cnf
`), 0644)
		fmt.Printf("  Created %s\n", globalRules)
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
			"# Format: <action>-<type> <pattern>",
			"",
			"# --- Project scripts ---",
			"allow-path scripts/*",
			"allow-path tests/*",
			"allow-path test_*",
		}

		// Detect tech stack
		if exists(filepath.Join(cwd, "pyproject.toml")) || exists(filepath.Join(cwd, "setup.py")) {
			lines = append(lines, "", "# --- Python ---")
			lines = append(lines, `allow-cmd uv run python -c "print*`)
			lines = append(lines, `allow-cmd python3 -c "print*`)
		}
		if exists(filepath.Join(cwd, "package.json")) {
			lines = append(lines, "", "# --- Node.js ---")
			lines = append(lines, "allow-cmd npm test*", "allow-cmd npm run build*")
		}
		if exists(filepath.Join(cwd, "go.mod")) {
			lines = append(lines, "", "# --- Go ---")
			lines = append(lines, "allow-cmd go test*", "allow-cmd go build*")
		}
		if exists(filepath.Join(cwd, "Cargo.toml")) {
			lines = append(lines, "", "# --- Rust ---")
			lines = append(lines, "allow-cmd cargo test*", "allow-cmd cargo build*")
		}
		if exists(filepath.Join(cwd, "Dockerfile")) || exists(filepath.Join(cwd, "docker-compose.yml")) {
			lines = append(lines, "", "# --- Docker ---")
			lines = append(lines, "allow-cmd docker build*", "allow-cmd docker compose*")
		}
		if isDir(filepath.Join(cwd, "deploy")) || isDir(filepath.Join(cwd, "infra")) {
			lines = append(lines, "", "# --- Deploy/Infra ---")
			lines = append(lines, "ask-path deploy/*", "ask-path infra/*")
		}
		if isDir(filepath.Join(cwd, "k8s")) || isDir(filepath.Join(cwd, "helm")) {
			lines = append(lines, "ask-path k8s/*", "ask-path helm/*")
		}

		content := strings.Join(lines, "\n") + "\n"
		os.WriteFile(projectRules, []byte(content), 0644)
		ruleCount := 0
		for _, l := range lines {
			if l != "" && !strings.HasPrefix(l, "#") {
				ruleCount++
			}
		}
		fmt.Printf("  Created %s (%d rules)\n", projectRules, ruleCount)
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

func cmdProvider() {
	config := LoadConfig()

	type providerInfo struct {
		Name   string
		URL    string
		Models []string
		EnvKey string
	}
	providers := []providerInfo{
		{"Claude Code (subscription)", "claude-cli", []string{
			"claude-haiku-4-5-20251001", "claude-sonnet-4-6-20250514",
		}, ""},
		{"OpenAI", "https://api.openai.com/v1/chat/completions", []string{
			"gpt-5.4-mini", "gpt-5.4-nano", "gpt-4o-mini",
		}, "OPENAI_API_KEY"},
		{"Anthropic (API)", "https://api.anthropic.com/v1/messages", []string{
			"claude-haiku", "claude-sonnet",
		}, "ANTHROPIC_API_KEY"},
		{"xAI", "https://api.x.ai/v1/chat/completions", []string{
			"grok-4-1-fast-reasoning", "grok-4-1-fast-non-reasoning",
		}, "XAI_API_KEY"},
		{"Ollama (local)", "http://localhost:11434/v1/chat/completions", nil, ""},
		{"OpenRouter", "https://openrouter.ai/api/v1/chat/completions", nil, "OPENROUTER_API_KEY"},
	}

	// Build menu items with status indicators
	var items []string
	for _, p := range providers {
		icon := "✓"
		status := "ready"
		if p.URL == "claude-cli" {
			if _, err := exec.LookPath("claude"); err != nil {
				icon = "✗"
				status = "claude not found"
			} else {
				icon = "⚠"
				status = "slow — not recommended"
			}
		} else if p.EnvKey != "" && os.Getenv(p.EnvKey) == "" && config.Provider.APIKey == "" {
			icon = "✗"
			status = "key missing"
		} else if strings.Contains(p.URL, "localhost") {
			if checkOllama() {
				status = "running"
			} else {
				icon = "✗"
				status = "not running"
			}
		}
		modelHint := ""
		if len(p.Models) > 0 {
			modelHint = p.Models[0]
		} else {
			modelHint = "(select model)"
		}
		items = append(items, fmt.Sprintf("%s %s — %s [%s]", icon, p.Name, modelHint, status))
	}
	items = append(items, "Custom endpoint")

	title := "Select LLM provider"
	curModel := envOr("LLM_MODEL", config.Provider.Model)
	if curModel != "" {
		title = fmt.Sprintf("Select LLM provider (current: %s)", curModel)
	}

	idx := tuiSelect(title, items, 0)
	if idx < 0 {
		fmt.Println("Cancelled.")
		return
	}

	var selected ProviderConfig

	switch {
	case idx < len(providers):
		p := providers[idx]
		var model string
		var apiKey string

		if p.URL == "claude-cli" {
			fmt.Println()
			fmt.Println("  Warning: Claude Code subscription is slow (~2-5s per command).")
			fmt.Println("  Every command spawns a separate claude process.")
			fmt.Println("  Recommended alternatives:")
			fmt.Println("    - Ollama with gemma4:e4b (free, local, fast)")
			fmt.Println("    - OpenAI gpt-5.4-nano (cheap, fast)")
			fmt.Println()
			if !tuiConfirm("Continue with Claude Code subscription?") {
				fmt.Println("Cancelled.")
				return
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
				return
			}
			models := listOllamaModels()
			if len(models) > 0 {
				models = append(models, "Other (type name)")
				modelIdx := tuiSelect("Select Ollama model", models, 0)
				if modelIdx < 0 {
					fmt.Println("Cancelled.")
					return
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
			models := p.Models

			// OpenRouter: fetch free models live
			if strings.Contains(p.URL, "openrouter") && len(models) == 0 {
				fmt.Print("Fetching free models... ")
				models = fetchOpenRouterFreeModels()
				if len(models) > 0 {
					fmt.Printf("found %d\n", len(models))
				} else {
					fmt.Println("failed")
				}
			}

			if len(models) > 0 {
				choices := append([]string{}, models...)
				choices = append(choices, "Other (type name)")
				modelIdx := tuiSelect(fmt.Sprintf("Select %s model", p.Name), choices, 0)
				if modelIdx < 0 {
					fmt.Println("Cancelled.")
					return
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
			fmt.Println("Cancelled.")
			return
		}

		timeout := 10
		if strings.Contains(p.URL, "localhost") || strings.Contains(p.URL, "openrouter") || p.URL == "claude-cli" {
			timeout = 30
		}

		selected = ProviderConfig{Name: p.Name, URL: p.URL, Model: model, EnvKey: p.EnvKey, Timeout: timeout}
		if apiKey != "" && os.Getenv(p.EnvKey) == "" {
			selected.APIKey = apiKey
		}

	case idx == len(providers):
		url := tuiInput("API URL", "https://api.example.com/v1/chat/completions", "")
		model := tuiInput("Model name", "e.g. my-model", "")
		envKey := tuiInput("API key env var", "leave empty if none", "")
		if url == "" || model == "" {
			fmt.Println("Cancelled.")
			return
		}
		selected = ProviderConfig{
			Name:   "Custom",
			URL:    url,
			Model:  model,
			EnvKey: envKey,
		}
	default:
		fmt.Println("Cancelled.")
		return
	}

	config.Provider = selected
	SaveConfig(config)
	fmt.Printf("\nProvider set: %s via %s\n", selected.Model, selected.URL)

	// Connection test
	fmt.Print("Testing connection... ")
	cfg := LLMConfig{URL: selected.URL, Model: selected.Model, APIKey: selected.APIKey}
	if cfg.APIKey == "" && selected.EnvKey != "" {
		cfg.APIKey = os.Getenv(selected.EnvKey)
	}
	text, err := CallLLM(cfg, "Say ok", "ok", 5)
	if err != nil {
		fmt.Printf("error: %v\n", err)
	} else if text != "" {
		fmt.Println("ok")
	} else {
		fmt.Println("unexpected response")
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
	cwd, _ := os.Getwd()
	projectRules := filepath.Join(cwd, ".yolonot")
	fmt.Printf("Project rules (%s):\n", projectRules)
	rules := loadRulesFromFile(projectRules)
	if len(rules) > 0 {
		for _, r := range rules {
			fmt.Printf("  %s-%s %s\n", r.Action, r.Type, r.Pattern)
		}
	} else {
		fmt.Println("  (none)")
	}

	globalRules := filepath.Join(YolonotDir(), "rules")
	fmt.Printf("\nGlobal rules (%s):\n", globalRules)
	rules = loadRulesFromFile(globalRules)
	if len(rules) > 0 {
		for _, r := range rules {
			fmt.Printf("  %s-%s %s\n", r.Action, r.Type, r.Pattern)
		}
	} else {
		fmt.Println("  (none)")
	}

	patterns := LoadSensitivePatterns()
	if len(patterns) == 0 {
		fmt.Println("\nSensitive file checks: disabled (opt-in)")
		fmt.Println("  Uncomment patterns in ~/.yolonot/rules, or add to any .yolonot file:")
		fmt.Println("    sensitive .env")
		fmt.Println("    sensitive .pem")
		fmt.Println("    sensitive .ssh/")
	} else {
		fmt.Printf("\nSensitive file checks: enabled (%d patterns)\n", len(patterns))
		for _, pat := range patterns {
			fmt.Printf("  %s\n", pat)
		}
		fmt.Println()
		fmt.Println("  Disable with 'not-sensitive *' or remove individual patterns with 'not-sensitive <pattern>'.")
	}
}

func cmdStatus() {
	sessionID := os.Getenv("CLAUDE_SESSION_ID")
	if sessionID == "" {
		sessionID = FindSessionID()
	}
	if sessionID == "" {
		fmt.Println("No active session found.")
		return
	}

	cwd, _ := os.Getwd()
	projSessionID := ProjectSessionID(sessionID, cwd)

	approved := ReadLines(projSessionID, "approved")
	asked := ReadLines(projSessionID, "asked")
	denied := ReadLines(projSessionID, "denied")

	fmt.Printf("yolonot session: %s (project: %s)\n", sessionID, filepath.Base(cwd))
	fmt.Printf("  %d approved · %d asked · %d denied\n\n", len(approved), len(asked), len(denied))

	if len(approved) > 0 {
		fmt.Printf("APPROVED (%d):\n", len(approved))
		for _, cmd := range approved {
			if len(cmd) > 80 {
				cmd = cmd[:77] + "..."
			}
			fmt.Printf("  ✓ %s\n", cmd)
		}
		fmt.Println()
	}
	if len(asked) > 0 {
		fmt.Printf("ASKED (%d):\n", len(asked))
		for _, cmd := range asked {
			if len(cmd) > 80 {
				cmd = cmd[:77] + "..."
			}
			fmt.Printf("  ? %s\n", cmd)
		}
		fmt.Println()
	}
	if len(denied) > 0 {
		fmt.Printf("DENIED (%d):\n", len(denied))
		for _, cmd := range denied {
			if len(cmd) > 80 {
				cmd = cmd[:77] + "..."
			}
			fmt.Printf("  ✗ %s\n", cmd)
		}
		fmt.Println()
	}
	if len(approved) == 0 && len(asked) == 0 && len(denied) == 0 {
		fmt.Println("No decisions recorded for this session yet.")
	}
}

// normalizeCommand strips variable parts from a command for grouping.
// It takes the first 3 tokens, removes tokens that look like UUIDs,
// hex hashes, or long numeric IDs so that commands differing only in
// such variable parts get grouped together.
var idTokenRe = regexp.MustCompile(`^[0-9a-f]{8,}$|^\d{10,}$`)

func normalizeCommand(cmd string) string {
	tokens := strings.Fields(cmd)
	if len(tokens) == 0 {
		return ""
	}
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
	Category string
	Pattern  string
	Count    int
	Weighted float64
	Desc     string
	Examples []string
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
	}

	askBuckets := map[string]*bucket{}
	allowBuckets := map[string]*bucket{}

	for _, e := range entries {
		if e.Command == "" {
			continue
		}
		pat := normalizeCommand(e.Command)
		if pat == "" {
			continue
		}
		w := timeWeight(e.Timestamp)

		if e.Decision == "ask" && e.Layer == "llm" {
			b, ok := askBuckets[pat]
			if !ok {
				b = &bucket{}
				askBuckets[pat] = b
			}
			b.weighted += w
			b.count++
			if len(b.examples) < maxExamples {
				b.examples = append(b.examples, e.Command)
			}
		} else if e.Decision == "allow" && e.Layer == "llm" && e.Confidence > 0 && e.Confidence < 0.8 {
			b, ok := allowBuckets[pat]
			if !ok {
				b = &bucket{}
				allowBuckets[pat] = b
			}
			b.weighted += w
			b.count++
			if len(b.examples) < maxExamples {
				b.examples = append(b.examples, e.Command)
			}
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
			if MatchRuleWith(sample, existingRules, nil) != nil {
				continue
			}
			findings = append(findings, evolveFinding{
				Category: category,
				Pattern:  pat,
				Count:    b.count,
				Weighted: b.weighted,
				Desc:     fmt.Sprintf(descFmt, b.count, b.weighted),
				Examples: b.examples,
			})
		}
	}

	addFindings(askBuckets, "REPEATED ASK", "asked %dx (weighted: %.1f)")
	addFindings(allowBuckets, "RISKY ALLOW", "allowed %dx at low confidence (weighted: %.1f)")

	// Sort by weighted score descending for consistent presentation
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Weighted > findings[j].Weighted
	})

	return findings
}

func cmdEvolve() {
	entries := ReadRecentDecisions(10000) // read all
	if len(entries) == 0 {
		fmt.Println("No decision log found. Use yolonot for a while first.")
		return
	}

	existingRules := LoadRules()
	findings := collectEvolveFindings(entries, existingRules)

	if len(findings) == 0 {
		fmt.Println("No patterns found worth promoting. Use yolonot more to build history.")
		return
	}

	fmt.Printf("SUGGEST: Analyzed %d decisions\n\n", len(entries))

	var changes []evolveChange

	for i, f := range findings {
		// Print finding with examples
		fmt.Printf("[%d/%d] \"%s\" -- %s\n", i+1, len(findings), f.Pattern, f.Desc)
		if len(f.Examples) > 0 {
			fmt.Println("  Examples:")
			for _, ex := range f.Examples {
				cmd := ex
				if len(cmd) > 80 {
					cmd = cmd[:77] + "..."
				}
				fmt.Printf("    %s\n", cmd)
			}
		}
		fmt.Println()

		// TUI action selection
		items := []string{
			fmt.Sprintf("allow -- allow-cmd %s*", f.Pattern),
			fmt.Sprintf("deny  -- deny-cmd *%s*", f.Pattern),
			fmt.Sprintf("ask   -- ask-cmd *%s*", f.Pattern),
			"skip",
		}
		idx := tuiSelect(
			fmt.Sprintf("\"%s\" (%s)", f.Pattern, f.Desc),
			items, 3) // default to skip

		if idx < 0 {
			break // cancelled
		}

		var rule string
		defScopeIdx := 0 // project
		switch idx {
		case 0:
			rule = fmt.Sprintf("allow-cmd %s*", f.Pattern)
		case 1:
			rule = fmt.Sprintf("deny-cmd *%s*", f.Pattern)
			defScopeIdx = 1 // global
		case 2:
			rule = fmt.Sprintf("ask-cmd *%s*", f.Pattern)
			defScopeIdx = 1 // global
		default:
			continue // skip
		}

		scopeIdx := tuiSelect("Scope", []string{
			"project (.yolonot)",
			"global (~/.yolonot/rules)",
		}, defScopeIdx)

		if scopeIdx < 0 {
			break // cancelled
		}

		scope := "p"
		if scopeIdx == 1 {
			scope = "g"
		}
		changes = append(changes, evolveChange{rule, scope})
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
		fmt.Println("Cancelled.")
		return
	}

	header := fmt.Sprintf("\n# Suggested by yolonot (%s)\n", time.Now().Format("2006-01-02"))
	cwd, _ := os.Getwd()

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

func cmdPreCheck(args []string) {
	cfg := LoadConfig()

	printHelp := func() {
		fmt.Println("Usage:")
		fmt.Println("  yolonot pre-check                  List configured hooks")
		fmt.Println("  yolonot pre-check add <cmd>        Append a hook")
		fmt.Println("  yolonot pre-check remove <n|path>  Remove by index (1-based) or exact path")
		fmt.Println("  yolonot pre-check clear            Remove all hooks")
		fmt.Println()
		fmt.Println("Pre-check hooks run after deny rules, before yolonot's own pipeline,")
		fmt.Println("in the order listed. Each receives the standard Claude Code PreToolUse")
		fmt.Println("hook JSON on stdin. The first hook that returns permissionDecision=\"allow\"")
		fmt.Println("wins. Any other outcome (ask/deny/empty/error/timeout) falls through to")
		fmt.Println("the next hook and eventually to yolonot's own rules + LLM.")
		fmt.Println()
		fmt.Println("⚠ Security: pre-check commands run with YOUR user privileges on every")
		fmt.Println("  Bash tool invocation. Only add commands you trust — a malicious or")
		fmt.Println("  compromised hook can bypass yolonot by returning \"allow\" for anything.")
	}

	if len(args) == 0 {
		if len(cfg.PreCheck) == 0 {
			fmt.Println("Pre-check hooks: none configured")
		} else {
			fmt.Println("Pre-check hooks (run in order; first allow wins):")
			for i, p := range cfg.PreCheck {
				fmt.Printf("  [%d] %s\n", i+1, p)
			}
		}
		fmt.Println()
		printHelp()
		return
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: yolonot pre-check add <cmd>")
			return
		}
		entry := strings.Join(args[1:], " ")
		for _, existing := range cfg.PreCheck {
			if existing == entry {
				fmt.Printf("Already configured: %s\n", entry)
				return
			}
		}
		cfg.PreCheck = append(cfg.PreCheck, entry)
		SaveConfig(cfg)
		fmt.Printf("Added pre-check hook: %s\n", entry)
		fmt.Printf("  (now %d hook(s) configured)\n", len(cfg.PreCheck))

	case "remove", "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: yolonot pre-check remove <n|path>")
			return
		}
		target := strings.Join(args[1:], " ")
		if n, err := strconv.Atoi(target); err == nil && n >= 1 && n <= len(cfg.PreCheck) {
			removed := cfg.PreCheck[n-1]
			cfg.PreCheck = append(cfg.PreCheck[:n-1], cfg.PreCheck[n:]...)
			SaveConfig(cfg)
			fmt.Printf("Removed [%d]: %s\n", n, removed)
			return
		}
		for i, p := range cfg.PreCheck {
			if p == target {
				cfg.PreCheck = append(cfg.PreCheck[:i], cfg.PreCheck[i+1:]...)
				SaveConfig(cfg)
				fmt.Printf("Removed: %s\n", p)
				return
			}
		}
		fmt.Fprintf(os.Stderr, "Not found: %s\n", target)

	case "clear", "off", "none":
		if len(cfg.PreCheck) == 0 {
			fmt.Println("Pre-check hooks: already empty")
			return
		}
		cfg.PreCheck = nil
		SaveConfig(cfg)
		fmt.Println("Pre-check hooks cleared.")

	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n\n", args[0])
		printHelp()
	}
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
		fmt.Println("Usage: yolonot quiet [on|off]")
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
	SaveConfig(cfg)
	if cfg.QuietOnAllow {
		fmt.Println("Quiet on approve: ON — allow decisions will be silent.")
	} else {
		fmt.Println("Quiet on approve: OFF — banners shown for every decision.")
	}
}

func cmdThreshold(args []string) {
	cfg := LoadConfig()

	if len(args) == 0 {
		// Show current
		if cfg.ConfidenceThreshold == 0 {
			fmt.Println("Confidence threshold: disabled (all LLM allows pass through)")
		} else {
			fmt.Printf("Confidence threshold: %.0f%%\n", cfg.ConfidenceThreshold*100)
			fmt.Println("Commands allowed below this confidence will be asked instead.")
		}
		fmt.Println("\nUsage: yolonot threshold <0-100>")
		fmt.Println("  0   = disabled (default)")
		fmt.Println("  90  = only auto-allow when LLM is 90%+ confident")
		fmt.Println("  95  = strict — auto-allow only very confident decisions")
		return
	}

	// Parse value
	var val float64
	n, _ := fmt.Sscanf(args[0], "%f", &val)
	if n != 1 {
		fmt.Fprintln(os.Stderr, "Invalid value. Usage: yolonot threshold <0-100>")
		return
	}
	if val < 0 || val > 100 {
		fmt.Fprintln(os.Stderr, "Threshold must be between 0 and 100")
		return
	}

	cfg.ConfidenceThreshold = val / 100.0
	SaveConfig(cfg)

	if val == 0 {
		fmt.Println("Confidence threshold disabled.")
	} else {
		fmt.Printf("Confidence threshold set to %.0f%%.\n", val)
	}
}
