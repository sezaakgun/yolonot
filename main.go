package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

var Version = "dev"

func init() {
	if Version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			Version = info.Main.Version
		}
	}
}

func main() {
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
		cmdThreshold(os.Args[2:])
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
	printUpdateHint()

	// Session summary if available
	sessionID := os.Getenv("CLAUDE_SESSION_ID")
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
	fmt.Println("  threshold   Set confidence threshold for auto-allow")
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
		fmt.Println("  [1/3] Hooks: already installed")
	} else {
		fmt.Println("  [1/3] Installing hooks...")
		cmdInstall()
	}

	// Step 2: Init rules
	fmt.Println()
	fmt.Println("  [2/3] Creating rule files...")
	cmdInit()

	// Step 3: Provider
	fmt.Println()
	fmt.Println("  [3/3] Configure LLM provider")
	fmt.Println()
	cmdProvider()

	fmt.Println()
	fmt.Println("Setup complete. Restart Claude Code to activate.")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
