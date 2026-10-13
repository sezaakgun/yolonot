package yolonot

import (
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

var Version = "dev"

// Verbose is a package-level flag set by the global -v/--verbose flag.
// Commands that write files, edit config, or otherwise take action should
// print extra detail via Verbosef when this is true.
var Verbose bool

// Verbosef prints to stderr only when Verbose is set. Stderr is used so
// that `yolonot hook`'s stdout JSON stays untouched — verbose on the hook
// path shouldn't corrupt Claude Code's protocol.
func Verbosef(format string, args ...interface{}) {
	if !Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "[v] "+format+"\n", args...)
}

func init() {
	if Version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			Version = info.Main.Version
		}
	}
}

// stripGlobalFlags pulls -v/--verbose out of args (at any position) and
// sets Verbose. Returns args with the flag removed so the rest of main's
// switch works unchanged.
func stripGlobalFlags(args []string) []string {
	out := args[:0:len(args)]
	for _, a := range args {
		if a == "-v" || a == "--verbose" {
			Verbose = true
			continue
		}
		out = append(out, a)
	}
	return out
}

// Run is the CLI entry point. The root main.go shim calls this.
func Run() {
	// Strip global flags from all positions so `-v` can appear before or
	// after the subcommand: `yolonot -v install` and `yolonot install -v`
	// both work.
	os.Args = append([]string{os.Args[0]}, stripGlobalFlags(os.Args[1:])...)

	if len(os.Args) < 2 {
		// Bare `yolonot` in a terminal on an installed setup opens the
		// settings screen; scripts and fresh installs get the text status.
		if IsInstalled() && stdinIsTerminal() {
			cmdConfigTUI()
			return
		}
		cmdDefault()
		return
	}

	switch os.Args[1] {
	case "setup":
		cmdSetup()
	case "models", "model":
		cmdModels(os.Args[2:])
	case "migrate":
		cmdMigrate(os.Args[2:])
	case "prompt":
		cmdClassifier(os.Args[2:])
	case "provider", "decision":
		fmt.Fprintln(os.Stderr, "yolonot: `"+os.Args[1]+"` was replaced by the model catalog. Use: yolonot models add")
		os.Exit(2)
	case "rules":
		cmdRules()
	case "status":
		cmdStatus()
	case "log":
		n := 20
		if len(os.Args) > 2 {
			arg := os.Args[2]
			if arg == "-n" && len(os.Args) > 3 {
				arg = os.Args[3]
			}
			if v, err := strconv.Atoi(arg); err == nil && v > 0 {
				n = v
			}
		}
		cmdLog(n)
	case "suggest":
		cmdEvolve(os.Args[2:])
	case "uninstall":
		cmdUninstall()
	case "pause":
		cmdPause(os.Args[2:])
	case "resume":
		cmdResume(os.Args[2:])
	case "stats":
		cmdStats()
	case "threshold":
		fmt.Fprintln(os.Stderr, "yolonot: `threshold` was removed. Use `yolonot risk` to configure per-harness tier→action policy.")
		os.Exit(2)
	case "risk":
		cmdRisk(os.Args[2:])
	case "profile":
		cmdProfile(os.Args[2:])
	case "config", "settings":
		cmdConfigTUI()
	case "judges", "judge":
		cmdJudges(os.Args[2:])
	case "pre-check", "precheck":
		fmt.Fprintln(os.Stderr, "yolonot: `pre-check` was replaced by the judge chain. Use: yolonot judges [add|remove|move]")
		os.Exit(2)
	case "classifier":
		fmt.Fprintln(os.Stderr, "yolonot: `classifier` was renamed. Use: yolonot prompt [defaults|config|review|verify]")
		os.Exit(2)
	case "escalation":
		cmdEscalation(os.Args[2:])
	case "quiet":
		cmdQuiet(os.Args[2:])
	case "local-allow", "localallow":
		fmt.Fprintln(os.Stderr, "yolonot: `local-allow` was replaced by the judge chain.")
		fmt.Fprintln(os.Stderr, "  enable:  yolonot judges add fast_allow")
		fmt.Fprintln(os.Stderr, "  disable: yolonot judges remove fast_allow")
		fmt.Fprintln(os.Stderr, "  status:  yolonot judges")
		os.Exit(2)
	case "check":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: yolonot check <command>")
			os.Exit(1)
		}
		cmdCheck(strings.Join(os.Args[2:], " "))
	case "upgrade":
		cmdUpgrade()
	case "version":
		fmt.Printf("yolonot %s\n", Version)

	// Hidden commands (still work, not shown in help)
	case "hook":
		cmdHook()
	case "install":
		cmdInstall()
	case "init":
		cmdInit()
	case "eval":
		opts := parseEvalArgs(os.Args[2:])
		if Verbose {
			opts.Verbose = true
		}
		cmdEval(opts)
	case "evolve":
		cmdEvolve(os.Args[2:])

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		cmdDefault()
		os.Exit(1)
	}
}

func cmdDefault() {
	installed := IsInstalled()
	config := LoadConfig()

	// Status overview
	fmt.Println("yolonot — smart auto-mode for Claude Code")
	fmt.Println()

	offerMigration(config)
	config = LoadConfig()

	if !installed {
		fmt.Println("  Status: not installed")
		if config.Legacy {
			fmt.Println("  Config:   v0 format (run: yolonot migrate)")
		}
		fmt.Println()
		fmt.Println("  Get started:")
		fmt.Println("    yolonot setup      First-run wizard (install + rules + models)")
		fmt.Println()
		return
	}

	fmt.Printf("  Status:   installed\n")
	fmt.Printf("  Version:  %s\n", Version)
	if config.Legacy {
		fmt.Printf("  Config:   v0 format (run: yolonot migrate)\n")
	}
	if names := config.ModelNames(); len(names) > 0 {
		parts := make([]string, 0, len(names))
		for _, n := range names {
			parts = append(parts, n+" ("+config.Models[n].Model+")")
		}
		fmt.Printf("  Models:   %s\n", strings.Join(parts, ", "))
	} else {
		fmt.Printf("  Models:   none (run: yolonot models add)\n")
	}
	if len(config.Judges) > 0 {
		fmt.Printf("  Judges:   %s\n", judgeNames(config.Judges))
	} else {
		fmt.Printf("  Judges:   none — commands pass through to the host (run: yolonot judges add)\n")
	}
	if esc := GetEscalationConfig(); esc.URL != "" && esc.Model != "" {
		switch escalationGateReason(config, esc) {
		case "":
			fmt.Printf("  Escalation: on — %s\n", config.Escalation.Model)
		default:
			fmt.Printf("  Escalation: off (configured: %s)\n", config.Escalation.Model)
		}
	}
	fmt.Printf("  Data:     %s\n", YolonotDir())
	{
		profileName := config.Policy.Profile
		if profileName == "" {
			profileName = DefaultProfileName + " (default)"
		}
		if n := len(harnessProfilePins(config)); n > 0 {
			profileName += fmt.Sprintf(" (+%d harness override(s))", n)
		}
		fmt.Printf("  Profile:  %s\n", profileName)
	}
	printUpdateHint()

	// Session summary if available
	sessionID := GetSessionIDFromEnv()
	if sessionID == "" {
		sessionID = FindSessionID()
	}
	if sessionID != "" {
		if isPaused(sessionID) {
			fmt.Printf("  Session:  PAUSED (run: yolonot resume)\n")
		} else {
			approved := ReadLines(sessionID, "approved")
			asked := ReadLines(sessionID, "asked")
			denied := ReadLines(sessionID, "denied")
			if len(approved)+len(asked)+len(denied) > 0 {
				fmt.Printf("  Session:  %d approved · %d asked · %d denied\n", len(approved), len(asked), len(denied))
			}
		}
	}

	if os.Getenv("YOLONOT_DISABLED") == "1" {
		fmt.Println("  ⚠ Disabled via YOLONOT_DISABLED=1 env var")
	}

	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  setup       First-run wizard (install + rules + models)")
	fmt.Println("  config      Settings screen (judges, models, policy)")
	fmt.Println("  models      Model catalog: list, add, remove, test")
	fmt.Println("  judges      The judge chain: list, add, remove, move")
	fmt.Println("  rules       Show active rules + sensitive patterns")
	fmt.Println("  status      Show session state (approved/asked/denied)")
	fmt.Println("  log         Show recent decisions")
	fmt.Println("  stats       Show analytics from decision history")
	fmt.Println("  check       Dry-run: test what the pipeline would decide for a command")
	fmt.Println("  suggest     Analyze history, suggest permanent rules")
	fmt.Println("  profile     Pick a named risk policy (fast/balanced/strict/paranoid + custom)")
	fmt.Println("  risk        Show/set per-harness risk tier → action policy")
	fmt.Println("  prompt      Inspect/review the chat-model prompt customization")
	fmt.Println("  escalation  Second-opinion model consulted before surfacing an ask")
	fmt.Println("  quiet       Silence banners for allow decisions (only show ask/deny)")
	fmt.Println("  pause       Disable yolonot for current session (total bypass)")
	fmt.Println("  resume      Re-enable yolonot for current session")
	fmt.Println("  migrate     Rewrite a v0 config.json in the v1 format (--dry-run, --undo)")
	fmt.Println("  uninstall   Remove hooks from Claude Code")
	fmt.Println("  upgrade     Update to latest version")
	fmt.Println("  version     Show version")
}

func cmdSetup() {
	fmt.Println("yolonot setup")
	fmt.Println()

	// Step 1: Install hooks
	if IsInstalled() {
		fmt.Println("  [1/4] Hooks: already installed")
	} else {
		fmt.Println("  [1/4] Installing hooks...")
		cmdInstall()
	}

	// Step 2: Init rules
	fmt.Println()
	fmt.Println("  [2/4] Creating rule files...")
	cmdInit()

	// Step 3: chat model
	fmt.Println()
	fmt.Println("  [3/4] Chat model")
	fmt.Println()
	cfg := LoadConfig()
	if cfg.Legacy {
		fmt.Println("      config.json is in the v0 format; setup writes v1.")
		if !tuiConfirm("Migrate config.json to v1 now? A backup is kept at config.json.bak") {
			fmt.Println("      Setup stopped. Run `yolonot migrate` first, then `yolonot setup` again.")
			return
		}
		migrateConfig(cfg)
		cfg = LoadConfig()
	}
	chat := cfg.ChatModelName()
	if chat != "" {
		fmt.Println("      Chat model: " + chat + " (" + cfg.Models[chat].Model + ")")
	} else {
		name, m, ok := pickModel(cfg, false)
		if !ok {
			fmt.Println("Setup stopped: no chat model chosen. Run `yolonot setup` again when ready.")
			os.Exit(1)
		}
		cfg.putModel(name, m)
		chat = name
		SaveConfig(cfg)
		fmt.Printf("\nModel %s set: %s via %s\n", name, m.Model, m.URL)
		testProviderConnection(m)
	}

	// Step 3b: typed decision model, in front of the chat model.
	fmt.Println()
	typed := offerDecisionModel(&cfg)

	// Step 4: the chain. fast_allow first (saves model calls on the bulk of
	// read-only commands), then the typed model, then the chat model.
	fmt.Println()
	fmt.Println("  [4/4] Judge chain")
	var judges JudgeList
	for _, name := range []string{judgeFastAllow, typed, chat} {
		if name == "" {
			continue
		}
		if sp := (JudgeSpec{Use: name}); !hasJudgeUse(cfg.Judges, name) {
			judges = append(judges, sp)
		}
	}
	if len(cfg.Judges) == 0 {
		cfg.Judges = judges
	} else {
		cfg.Judges = append(cfg.Judges, judges...)
	}
	SaveConfig(cfg)
	fmt.Println("      judges: " + judgeNames(cfg.Judges))

	fmt.Println()
	fmt.Println("Setup complete. Restart Claude Code to activate.")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// offerDecisionModel asks whether to add a typed decision model. Returns
// the catalog name to put in the chain ("" when declined or unavailable).
func offerDecisionModel(cfg *Config) string {
	for _, n := range cfg.ModelNames() {
		if isDecisionURL(cfg.Models[n].URL) {
			fmt.Println("  [3b] Typed model: " + n + " (" + cfg.Models[n].Model + ")")
			return n
		}
	}
	fmt.Println("  [3b] Typed decision model")
	fmt.Println("       A typed decision model (TypeSafe Jev) answers in ~300ms and runs")
	fmt.Println("       before the chat model, which then only sees what it could not decide.")
	if os.Getenv("TYPESAFE_API_KEY") == "" {
		fmt.Println("       (needs TYPESAFE_API_KEY; export it and run `yolonot models add typed` to enable)")
		return ""
	}
	if !tuiConfirm("Use TypeSafe Jev as a typed decision model?") {
		return ""
	}
	name := cfg.addModel(typesafeDecision)
	SaveConfig(*cfg)
	fmt.Println("       added model: " + name)
	return name
}

func hasJudgeUse(specs []JudgeSpec, use string) bool {
	for _, sp := range specs {
		if sp.Use == use {
			return true
		}
	}
	return false
}

func judgeNames(specs []JudgeSpec) string {
	names := make([]string, 0, len(specs))
	for _, sp := range specs {
		names = append(names, sp.Use)
	}
	return strings.Join(names, " → ")
}
