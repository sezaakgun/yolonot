package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ProviderConfig struct {
	Name   string `json:"name,omitempty"`
	URL    string `json:"url,omitempty"`
	Model  string `json:"model,omitempty"`
	EnvKey string `json:"env_key,omitempty"`
	APIKey string `json:"api_key,omitempty"`
}

type Config struct {
	Provider ProviderConfig `json:"provider"`
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
	os.WriteFile(configPath(), append(data, '\n'), 0644)
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
		fmt.Println("yolonot is already installed.")
		return
	}

	s := loadSettings()
	hooks, _ := s["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = map[string]interface{}{}
		s["hooks"] = hooks
	}

	bp := binaryPath() + " hook"

	preHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 120.0}
	postHook := map[string]interface{}{"type": "command", "command": bp, "timeout": 5.0}

	// PreToolUse: add to existing Bash entry or create before catch-all
	addHookToEvent(hooks, "PreToolUse", "Bash", preHook)
	// PostToolUse: add to existing Bash entry or create at start
	addHookToEvent(hooks, "PostToolUse", "Bash", postHook)

	saveSettings(s)

	// Create data directories
	os.MkdirAll(filepath.Join(YolonotDir(), "sessions"), 0755)
	os.MkdirAll(filepath.Join(YolonotDir(), "cache"), 0755)

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

	// Find SKILL.md relative to the binary
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(exeDir, ".claude", "skills", "yolonot", "SKILL.md"),
		filepath.Join(exeDir, "skills", "yolonot", "SKILL.md"),
	}

	var skillSrc string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			skillSrc = c
			break
		}
	}

	if skillSrc == "" {
		fmt.Println("  Skill: SKILL.md not found (install manually from repo)")
		return
	}

	os.MkdirAll(skillDir, 0755)
	data, err := os.ReadFile(skillSrc)
	if err != nil {
		fmt.Printf("  Skill: error reading %s: %v\n", skillSrc, err)
		return
	}
	os.WriteFile(skillDst, data, 0644)
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

func cmdUninstall() {
	if !IsInstalled() {
		fmt.Println("yolonot is not installed.")
		return
	}

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

	// Remove skill
	home, _ := os.UserHomeDir()
	skillDir := filepath.Join(home, ".claude", "skills", "yolonot")
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
		Model  string
		EnvKey string
	}
	providers := []providerInfo{
		{"OpenAI", "https://api.openai.com/v1/chat/completions", "gpt-4o-mini", "OPENAI_API_KEY"},
		{"Anthropic", "https://api.anthropic.com/v1/messages", "claude-haiku", "ANTHROPIC_API_KEY"},
		{"Ollama (local)", "http://localhost:11434/v1/chat/completions", "", ""},
		{"OpenRouter", "https://openrouter.ai/api/v1/chat/completions", "", "OPENROUTER_API_KEY"},
	}

	// Build menu items with status indicators
	var items []string
	for _, p := range providers {
		icon := "✓"
		status := "ready"
		if p.EnvKey != "" && os.Getenv(p.EnvKey) == "" && config.Provider.APIKey == "" {
			icon = "✗"
			status = "key missing"
		}
		if strings.Contains(p.URL, "localhost") {
			if checkOllama() {
				status = "running"
			} else {
				icon = "✗"
				status = "not running"
			}
		}
		modelStr := p.Model
		if modelStr == "" {
			modelStr = "(select model)"
		}
		items = append(items, fmt.Sprintf("%s %s — %s [%s]", icon, p.Name, modelStr, status))
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
		model := p.Model

		if strings.Contains(p.URL, "localhost") {
			// Ollama: list installed models with TUI
			if !checkOllama() {
				tuiNote("Ollama not running", "Start it with: ollama serve")
				return
			}
			models := listOllamaModels()
			if len(models) > 0 {
				modelIdx := tuiSelect("Select Ollama model", models, 0)
				if modelIdx < 0 {
					fmt.Println("Cancelled.")
					return
				}
				model = models[modelIdx]
			} else {
				model = tuiInput("Model name", "e.g. llama3:8b", "")
			}
			if model == "" {
				fmt.Println("Cancelled.")
				return
			}
		} else if model != "" {
			custom := tuiInput("Model", "press enter for default", model)
			if custom != "" {
				model = custom
			}
		} else {
			model = tuiInput("Model name", "e.g. gpt-4o-mini", "")
			if model == "" {
				fmt.Println("Cancelled.")
				return
			}
		}

		selected = ProviderConfig{Name: p.Name, URL: p.URL, Model: model, EnvKey: p.EnvKey}

		if p.EnvKey != "" && os.Getenv(p.EnvKey) == "" {
			key := tuiPassword(p.EnvKey)
			if key != "" {
				selected.APIKey = key
			}
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

	approved := ReadLines(sessionID, "approved")
	asked := ReadLines(sessionID, "asked")
	denied := ReadLines(sessionID, "denied")

	fmt.Printf("yolonot session: %s\n", sessionID)
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

func cmdEvolve() {
	entries := ReadRecentDecisions(10000) // read all
	if len(entries) == 0 {
		fmt.Println("No decision log found. Use yolonot for a while first.")
		return
	}

	// Group by command pattern (first 3 tokens)
	type finding struct {
		Category string
		Pattern  string
		Count    int
		Desc     string
	}

	askCounts := map[string]int{}
	allowCounts := map[string]int{}

	for _, e := range entries {
		if e.Command == "" {
			continue
		}
		parts := strings.Fields(e.Command)
		if len(parts) > 3 {
			parts = parts[:3]
		}
		pat := strings.Join(parts, " ")

		if e.Decision == "ask" && e.Layer == "llm" {
			askCounts[pat]++
		} else if e.Decision == "allow" && e.Layer == "llm" && e.Confidence > 0 && e.Confidence < 0.8 {
			allowCounts[pat]++
		}
	}

	var findings []finding
	for pat, count := range askCounts {
		if count >= 3 {
			findings = append(findings, finding{"REPEATED ASK", pat, count, fmt.Sprintf("asked %dx", count)})
		}
	}
	for pat, count := range allowCounts {
		if count >= 3 {
			findings = append(findings, finding{"RISKY ALLOW", pat, count, fmt.Sprintf("allowed %dx at low confidence", count)})
		}
	}

	if len(findings) == 0 {
		fmt.Println("No patterns found worth promoting. Use yolonot more to build history.")
		return
	}

	fmt.Printf("EVOLVE: Analyzed %d decisions\n\n", len(entries))
	reader := bufio.NewReader(os.Stdin)

	type change struct {
		Rule  string
		Scope string
	}
	var changes []change

	for i, f := range findings {
		fmt.Printf("[%d/%d] %s: \"%s\" (%s)\n", i+1, len(findings), f.Category, f.Pattern, f.Desc)
		fmt.Printf("  a) allow  — add allow-cmd %s*\n", f.Pattern)
		fmt.Printf("  b) deny   — add deny-cmd *%s*\n", f.Pattern)
		fmt.Printf("  c) ask    — add ask-cmd *%s*\n", f.Pattern)
		fmt.Println("  d) skip")
		fmt.Println("  q) quit and apply")
		fmt.Println()
		fmt.Print("  Choice: ")
		ch, _ := reader.ReadString('\n')
		ch = strings.TrimSpace(strings.ToLower(ch))

		if ch == "q" {
			break
		}
		var rule string
		defScope := "p"
		switch ch {
		case "a":
			rule = fmt.Sprintf("allow-cmd %s*", f.Pattern)
		case "b":
			rule = fmt.Sprintf("deny-cmd *%s*", f.Pattern)
			defScope = "g"
		case "c":
			rule = fmt.Sprintf("ask-cmd *%s*", f.Pattern)
			defScope = "g"
		default:
			fmt.Println()
			continue
		}
		fmt.Printf("  Scope — (p)roject or (g)lobal? [%s]: ", defScope)
		scope, _ := reader.ReadString('\n')
		scope = strings.TrimSpace(strings.ToLower(scope))
		if scope == "" {
			scope = defScope
		}
		changes = append(changes, change{rule, scope})
		fmt.Println()
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
		fmt.Printf("  + %s → %s\n", c.Rule, target)
	}
	fmt.Print("\nApply? [y/N]: ")
	confirm, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
		fmt.Println("Cancelled.")
		return
	}

	header := fmt.Sprintf("\n# Evolved by yolonot (%s)\n", time.Now().Format("2006-01-02"))
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
