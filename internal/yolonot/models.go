package yolonot

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// `yolonot models`: the catalog. `yolonot migrate`: the one-way v0 → v1
// rewrite, offered (never forced) by interactive verbs.

func cmdModels(args []string) {
	cfg := LoadConfig()
	if len(args) == 0 {
		printModels(cfg)
		return
	}
	switch args[0] {
	case "add":
		if !requireV1(&cfg) {
			return
		}
		name, m, ok := pickModel(cfg, len(args) > 1 && args[1] == "typed")
		if !ok {
			return
		}
		cfg.putModel(name, m)
		SaveConfig(cfg)
		fmt.Printf("Added %s: %s via %s\n", name, m.Model, m.URL)
		if !testProviderConnection(m) {
			return
		}
		if len(cfg.Judges) == 0 || tuiConfirm("Add "+name+" to the judge chain?") {
			cfg.Judges = append(cfg.Judges, JudgeSpec{Use: name})
			SaveConfig(cfg)
			printJudges(cfg)
		}
	case "remove", "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: yolonot models remove <name>")
			return
		}
		if !requireV1(&cfg) {
			return
		}
		name := args[1]
		if _, ok := cfg.Models[name]; !ok {
			fmt.Fprintf(os.Stderr, "No model named %q.\n", name)
			os.Exit(2)
		}
		for _, sp := range cfg.Judges {
			if sp.Use == name {
				fmt.Fprintf(os.Stderr, "%s is in the judge chain. Remove it first: yolonot judges remove %s\n", name, name)
				os.Exit(2)
			}
		}
		if cfg.Escalation != nil && cfg.Escalation.Model == name {
			fmt.Fprintf(os.Stderr, "%s is the escalation model. Change it first: yolonot escalation setup\n", name)
			os.Exit(2)
		}
		delete(cfg.Models, name)
		SaveConfig(cfg)
		fmt.Printf("Removed %s.\n", name)
	case "test":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: yolonot models test <name>")
			return
		}
		m, ok := cfg.Models[args[1]]
		if !ok {
			fmt.Fprintf(os.Stderr, "No model named %q.\n", args[1])
			os.Exit(2)
		}
		if !testProviderConnection(m) {
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "Usage: yolonot models [add [typed]|remove <name>|test <name>]")
		os.Exit(2)
	}
}

func printModels(cfg Config) {
	if len(cfg.Models) == 0 {
		fmt.Println("Models: none. Add one with: yolonot models add")
		return
	}
	fmt.Println("Models (referenced by name in judges and escalation):")
	w := 16
	for _, name := range cfg.ModelNames() {
		w = max(w, len(name))
	}
	for _, name := range cfg.ModelNames() {
		m := cfg.Models[name]
		kind := "chat"
		if isDecisionURL(m.URL) {
			kind = "typed"
		}
		role := ""
		for i, sp := range cfg.Judges {
			if sp.Use == name {
				role = fmt.Sprintf("judge #%d", i+1)
			}
		}
		if cfg.Escalation != nil && cfg.Escalation.Model == name {
			role = strings.TrimSpace(role + " escalation")
		}
		fmt.Printf("  %-*s %-6s %-36s %-10s %s\n", w, name, kind, m.Model, keyHint(m.EnvKey), role)
	}
}

// pickModel runs the provider picker and asks for a catalog name.
func pickModel(cfg Config, typed bool) (string, ModelConfig, bool) {
	var m ProviderConfig
	var ok bool
	if typed {
		m, ok = pickDecisionProvider()
	} else {
		m, ok = pickProvider(cfg, false)
	}
	if !ok {
		return "", m, false
	}
	def := modelKey(m)
	for {
		name := tuiInput("Name for this model (used in judges and banners)", def, def)
		if name == "" {
			return "", m, false
		}
		if err := ValidModelName(name); err != nil {
			tuiNote(err.Error(), "")
			continue
		}
		if _, exists := cfg.Models[name]; exists && !tuiConfirm("Replace existing model "+name+"?") {
			continue
		}
		return name, m, true
	}
}

// --- migration ---

func migrateDeclinedPath() string { return YolonotDir() + "/migrate-declined" }

// requireV1 gates a mutating verb: on a v0 file it asks once to migrate;
// a decline leaves the file untouched and the verb does nothing.
func requireV1(cfg *Config) bool {
	if !cfg.Legacy {
		return true
	}
	fmt.Println("config.json is in the v0 format. This change is written in the v1 format (models / judges / prompt / policy).")
	if !stdinIsTerminal() {
		fmt.Println("Not changed. Run `yolonot migrate` first.")
		os.Exit(2)
	}
	if !tuiConfirm("Migrate config.json to v1 now? A backup is kept at config.json.bak") {
		fmt.Println("Not changed. Run `yolonot migrate` when ready.")
		return false
	}
	migrateConfig(*cfg)
	cfg.Legacy = false
	return true
}

// offerMigration is called by read-only interactive verbs: asks once,
// remembers a decline.
func offerMigration(cfg Config) {
	if !cfg.Legacy || !stdinIsTerminal() {
		return
	}
	if _, err := os.Stat(migrateDeclinedPath()); err == nil {
		return
	}
	fmt.Println("config.json is in the v0 format. yolonot 1.x reads it as is; v2 will not.")
	if tuiConfirm("Migrate config.json to v1 now? A backup is kept at config.json.bak") {
		migrateConfig(cfg)
		return
	}
	os.WriteFile(migrateDeclinedPath(), []byte("declined\n"), 0600)
	fmt.Println("Kept the v0 file. Run `yolonot migrate` when ready; this prompt will not repeat.")
}

func migrateConfig(cfg Config) {
	if data, err := os.ReadFile(configPath()); err == nil {
		os.WriteFile(configPath()+".bak", data, 0600)
	}
	SaveConfig(cfg)
	os.Remove(migrateDeclinedPath())
	fmt.Println("Migrated to v1. Backup: " + tildePath(configPath()) + ".bak")
	printMigrationSummary(cfg)
}

func printMigrationSummary(cfg Config) {
	fmt.Println("  models:   " + strings.Join(cfg.ModelNames(), ", "))
	fmt.Println("  judges:   " + judgeNames(cfg.Judges))
	if cfg.Escalation != nil && cfg.Escalation.Model != "" {
		fmt.Println("  escalation: " + cfg.Escalation.Model)
	}
	if cfg.Policy.Profile != "" {
		fmt.Println("  policy.profile: " + cfg.Policy.Profile)
	}
}

// cmdMigrate: `yolonot migrate [--dry-run|--undo]`.
func cmdMigrate(args []string) {
	cfg := LoadConfig()
	flag := ""
	if len(args) > 0 {
		flag = args[0]
	}
	switch flag {
	case "--undo":
		bak := configPath() + ".bak"
		data, err := os.ReadFile(bak)
		if err != nil {
			fmt.Fprintln(os.Stderr, "No backup at "+tildePath(bak))
			os.Exit(1)
		}
		if err := atomicWriteFile(configPath(), data, 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Restored " + tildePath(configPath()) + " from .bak")
	case "--dry-run":
		if !cfg.Legacy {
			fmt.Println("config.json is already v1.")
			return
		}
		cfg.ConfigVersion = 1
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))
		fmt.Println()
		printMigrationSummary(cfg)
	case "":
		if !cfg.Legacy {
			fmt.Println("config.json is already v1.")
			return
		}
		migrateConfig(cfg)
	default:
		fmt.Fprintln(os.Stderr, "Usage: yolonot migrate [--dry-run|--undo]")
		os.Exit(2)
	}
}
