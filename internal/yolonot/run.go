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
		cmdDefault()
		return
	}

	switch os.Args[1] {
	case "setup":
		cmdSetup()
	case "provider":
		cmdProvider()
	case "rules":
		cmdRules()
	case "status":
		cmdStatus()
	case "log":
		n := 20
		if len(os.Args) > 2 {
			if os.Args[2] == "-n" && len(os.Args) > 3 {
				if v, err := strconv.Atoi(os.Args[3]); err == nil {
					n = v
				}
			}
		}
		cmdLog(n)
	case "suggest":
		cmdEvolve()
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
	case "pre-check", "precheck":
		cmdPreCheck(os.Args[2:])
	case "quiet":
		cmdQuiet(os.Args[2:])
	case "local-allow", "localallow":
		fmt.Fprintln(os.Stderr, "yolonot: `local-allow` was replaced by the unified pre-check list.")
		fmt.Fprintln(os.Stderr, "  enable:  yolonot pre-check add fast-allow")
		fmt.Fprintln(os.Stderr, "  disable: yolonot pre-check remove fast-allow")
		fmt.Fprintln(os.Stderr, "  status:  yolonot pre-check")
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
		cmdEvolve()

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		cmdDefault()
		os.Exit(1)
	}
}

func cmdDefault() {
	installed := IsInstalled()
	config := LoadConfig()
	model := envOr("LLM_MODEL", config.Provider.Model)

	// Status overview
	fmt.Println("yolonot — smart auto-mode for Claude Code")
	fmt.Println()

	if !installed {
		fmt.Println("  Status: not installed")
		fmt.Println()
		fmt.Println("  Get started:")
		fmt.Println("    yolonot setup      First-run wizard (install + rules + provider)")
		fmt.Println()
		return
	}

	provider := model
	if provider == "" {
		provider = "not configured"
	}

	fmt.Printf("  Status:   installed\n")
	fmt.Printf("  Version:  %s\n", Version)
	fmt.Printf("  Provider: %s\n", provider)
	fmt.Printf("  Data:     %s\n", YolonotDir())
	if n := len(config.PreCheck); n > 0 {
		if n == 1 {
			fmt.Printf("  PreCheck: %s\n", config.PreCheck[0])
		} else {
			fmt.Printf("  PreCheck: %d hooks (run: yolonot pre-check)\n", n)
		}
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
	fmt.Println("  setup       First-run wizard (install + rules + provider)")
	fmt.Println("  provider    Change LLM provider")
	fmt.Println("  rules       Show active rules + sensitive patterns")
	fmt.Println("  status      Show session state (approved/asked/denied)")
	fmt.Println("  log         Show recent decisions")
	fmt.Println("  stats       Show analytics from decision history")
	fmt.Println("  check       Dry-run: test what the pipeline would decide for a command")
	fmt.Println("  suggest     Analyze history, suggest permanent rules")
	fmt.Println("  risk        Show/set per-harness risk tier → action policy")
	fmt.Println("  pre-check   Manage pre-checkers (fast-allow + external hooks like dippy)")
	fmt.Println("  quiet       Silence banners for allow decisions (only show ask/deny)")
	fmt.Println("  pause       Disable yolonot for current session (total bypass)")
	fmt.Println("  resume      Re-enable yolonot for current session")
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

	// Step 3: Provider
	fmt.Println()
	fmt.Println("  [3/4] Configure LLM provider")
	fmt.Println()
	cmdProvider()

	// Step 4: Fast-allow pre-check — recommend on by default. Saves LLM
	// calls on the bulk of safe read-only commands (ls, cat, git status, ...)
	// without depending on any external tool. Lives in the pre-check list
	// so users can reorder it alongside Dippy or other external hooks.
	fmt.Println()
	fmt.Println("  [4/4] Enabling built-in fast-allow for read-only commands...")
	cfg := LoadConfig()
	hasFastAllow := false
	for _, p := range cfg.PreCheck {
		if p == FastAllowSentinel {
			hasFastAllow = true
			break
		}
	}
	if !hasFastAllow {
		cfg.PreCheck = append(PreCheckList{FastAllowSentinel}, cfg.PreCheck...)
		SaveConfig(cfg)
		fmt.Println("      fast-allow: ON (yolonot pre-check remove fast-allow to disable)")
	} else {
		fmt.Println("      fast-allow: already ON")
	}

	fmt.Println()
	fmt.Println("Setup complete. Restart Claude Code to activate.")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
