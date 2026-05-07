package yolonot

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// RiskProfile is a named tier→action policy bundle. Built-in profiles are
// shipped in code (BuiltinProfiles); user-defined profiles live in
// Config.CustomProfiles. Both go through the same translation pipeline at
// resolve time so harnesses without a real "ask" primitive get sensible
// defaults.
//
// Canonical profile actions are {allow, ask, deny}. "passthrough" is a
// per-harness translation result, not a profile-author concept.
type RiskProfile struct {
	Name        string
	Description string
	Builtin     bool
	Map         map[string]string
}

// builtinProfiles is the registry of shipped profiles, defined by user
// intent ("how cautious do I want to be") rather than by harness specifics.
// Each profile gets translated per-harness at apply time.
//
// fast: skip-permissions-style speed. No ask cells; deny only the
//
//	prod-breaking / irreversible tiers.
//
// balanced: today's status-quo for ask-capable harnesses (Claude/Gemini).
//
//	Asks on moderate+, denies on critical.
//
// strict: fewer auto-allows, hard-deny on high. For shared/staging work.
// paranoid: ask on everything, deny moderate+. CI-style lockdown.
var builtinProfiles = []RiskProfile{
	{
		Name:        "fast",
		Description: "Skip-permissions speed. Allow everything reversible; hard-deny prod-breaking / irreversible (high+critical). No ask prompts.",
		Builtin:     true,
		Map: map[string]string{
			RiskSafe:     ActionAllow,
			RiskLow:      ActionAllow,
			RiskModerate: ActionAllow,
			RiskHigh:     ActionDeny,
			RiskCritical: ActionDeny,
		},
	},
	{
		Name:        "balanced",
		Description: "Default. Auto-allow safe/low; ask on moderate+. Matches the pre-profile shipped behavior of ask-capable harnesses (Claude/Gemini); other harnesses still hard-deny high+critical via translation.",
		Builtin:     true,
		Map: map[string]string{
			RiskSafe:     ActionAllow,
			RiskLow:      ActionAllow,
			RiskModerate: ActionAsk,
			RiskHigh:     ActionAsk,
			RiskCritical: ActionAsk,
		},
	},
	{
		Name:        "strict",
		Description: "Cautious. Ask on low+moderate; hard-deny on high+critical.",
		Builtin:     true,
		Map: map[string]string{
			RiskSafe:     ActionAllow,
			RiskLow:      ActionAsk,
			RiskModerate: ActionAsk,
			RiskHigh:     ActionDeny,
			RiskCritical: ActionDeny,
		},
	},
	{
		Name:        "paranoid",
		Description: "Lockdown. Ask even on safe/low; deny moderate+.",
		Builtin:     true,
		Map: map[string]string{
			RiskSafe:     ActionAsk,
			RiskLow:      ActionAsk,
			RiskModerate: ActionDeny,
			RiskHigh:     ActionDeny,
			RiskCritical: ActionDeny,
		},
	},
}

// DefaultProfileName is the profile used when Config.Profile is empty.
// Matches the pre-profile shipped behavior so existing configs don't
// silently shift policy on upgrade.
const DefaultProfileName = "balanced"

// BuiltinProfiles returns shipped profiles in display order (safest →
// loosest perception aside, ordered by user mental model: fast first
// because that's the headline use case).
func BuiltinProfiles() []RiskProfile {
	out := make([]RiskProfile, len(builtinProfiles))
	copy(out, builtinProfiles)
	return out
}

// GetBuiltinProfile returns a built-in profile by name, or nil. Lookup is
// case-sensitive by design — profile names are CLI tokens.
func GetBuiltinProfile(name string) *RiskProfile {
	for i := range builtinProfiles {
		if builtinProfiles[i].Name == name {
			return &builtinProfiles[i]
		}
	}
	return nil
}

// IsBuiltinProfileName reports whether name collides with a shipped profile.
// Used at custom-create time to refuse shadowing.
func IsBuiltinProfileName(name string) bool {
	return GetBuiltinProfile(name) != nil
}

// LookupProfile resolves a name to a profile (built-in or custom). Returns
// nil if neither matches. Custom profiles loaded from a hand-edited
// config.json are re-validated here: cells with unknown actions or unknown
// tiers are dropped with a Verbosef warning, and a missing tier falls
// through to the built-in default's value for that tier so a partially-
// corrupt config can't leave a tier resolving to "" (which would later
// fail action dispatch).
func LookupProfile(cfg Config, name string) *RiskProfile {
	if p := GetBuiltinProfile(name); p != nil {
		return p
	}
	m, ok := cfg.CustomProfiles[name]
	if !ok {
		return nil
	}
	fallback := GetBuiltinProfile(DefaultProfileName).Map
	cp := map[string]string{}
	for _, tier := range allRiskTiers {
		v, ok := m[tier]
		if !ok {
			Verbosef("LookupProfile: custom profile %q missing tier %q, using %s default", name, tier, DefaultProfileName)
			cp[tier] = fallback[tier]
			continue
		}
		// Custom profiles use canonical {allow, ask, deny} only — passthrough
		// is a per-harness translation result, not a profile-author concept.
		if v != ActionAllow && v != ActionAsk && v != ActionDeny {
			Verbosef("LookupProfile: custom profile %q tier %q has invalid action %q, using %s default", name, tier, v, DefaultProfileName)
			cp[tier] = fallback[tier]
			continue
		}
		cp[tier] = v
	}
	return &RiskProfile{Name: name, Description: "custom", Builtin: false, Map: cp}
}

// ResolveActiveProfile returns the profile that should apply to harness h.
// Resolution order, highest precedence last. Same scope tier: more-specific
// (per-harness) beats more-general (global).
//
//  1. DefaultProfileName ("balanced")
//  2. Config.Profile (global, persistent)
//  3. YOLONOT_PROFILE env var (global, per-session) — beats Config.Profile
//     so a one-shot launch can override saved policy
//  4. Config.ProfileOverride[harness] (per-harness, persistent) — more
//     specific, beats global env above
//  5. YOLONOT_<HARNESS>_PROFILE env var (per-harness, per-session) —
//     beats per-harness config because env is the user's freshest signal
//  6. Session profile file (mid-session pin via `yolonot profile use --session`).
//     Highest because the user actively set it during a running session;
//     dies when the session ends (CleanOldSessions sweeps it).
//
// Unknown profile names fall back to DefaultProfileName with a Verbosef
// warning rather than returning nil — callers treat the result as the
// active baseline.
func ResolveActiveProfile(cfg Config, h Harness) *RiskProfile {
	name := DefaultProfileName
	if cfg.Profile != "" {
		name = cfg.Profile
	}
	if v := os.Getenv("YOLONOT_PROFILE"); v != "" {
		name = v
	}
	if h != nil {
		if v, ok := cfg.ProfileOverride[h.Name()]; ok && v != "" {
			name = v
		}
		envKey := "YOLONOT_" + strings.ToUpper(h.Name()) + "_PROFILE"
		if v := os.Getenv(envKey); v != "" {
			name = v
		}
	}
	if sid := currentSessionID(h); sid != "" {
		if v := readSessionProfile(sid); v != "" {
			name = v
		}
	}
	if p := LookupProfile(cfg, name); p != nil {
		return p
	}
	Verbosef("ResolveActiveProfile: profile %q not found, falling back to %s", name, DefaultProfileName)
	return GetBuiltinProfile(DefaultProfileName)
}

// currentSessionID picks the best session ID for profile resolution.
// Prefers the harness's own env (CLAUDE_SESSION_ID etc), falls back to the
// most-recent decision log session for cases where Resolve runs outside a
// hook (CLI listings).
func currentSessionID(h Harness) string {
	if h != nil {
		if sid := h.SessionIDFromEnv(); sid != "" {
			return sid
		}
	}
	if sid := GetSessionIDFromEnv(); sid != "" {
		return sid
	}
	return FindSessionID()
}

// sessionProfilePath returns the marker file for a session-pinned profile.
// One line of plain text = profile name. Same sessions/ dir as pause.
// Returns "" for invalid IDs so a hostile --session-id can't escape the
// sessions/ dir via path traversal.
func sessionProfilePath(sessionID string) string {
	if !IsValidSessionID(sessionID) {
		return ""
	}
	return filepath.Join(YolonotDir(), "sessions", sessionID+".profile")
}

// readSessionProfile reads the pinned profile name for a session, or "" if
// not set or sessionID is invalid. Errors (missing file, unreadable)
// treated as "no pin".
func readSessionProfile(sessionID string) string {
	path := sessionProfilePath(sessionID)
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// writeSessionProfile pins a profile name for a session. Creates the
// sessions/ dir if missing. Returns an error if sessionID is invalid.
func writeSessionProfile(sessionID, name string) error {
	path := sessionProfilePath(sessionID)
	if path == "" {
		return fmt.Errorf("invalid session id %q", sessionID)
	}
	if err := os.MkdirAll(filepath.Join(YolonotDir(), "sessions"), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(name+"\n"), 0644)
}

// clearSessionProfile removes a session pin. Missing file is not an error.
// Invalid sessionIDs are a no-op so callers can chain reset blindly.
func clearSessionProfile(sessionID string) error {
	path := sessionProfilePath(sessionID)
	if path == "" {
		return nil
	}
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// TranslateProfile maps a canonical profile (allow/ask/deny only) to the
// actions actually emitted for harness h. Harnesses without a real "ask"
// primitive collapse ask→passthrough on lower tiers and ask→deny on
// high+critical. Mirrors each harness's shipped RiskMap philosophy so
// profiles inherit the same safety floor as the harness defaults.
func TranslateProfile(profile map[string]string, h Harness) map[string]string {
	out := map[string]string{}
	for tier, act := range profile {
		out[tier] = translateProfileAction(h, tier, act)
	}
	return out
}

// translateProfileAction handles one cell. Only "ask" is reinterpreted —
// allow/deny pass through unchanged.
func translateProfileAction(h Harness, tier, act string) string {
	if act != ActionAsk {
		return act
	}
	if h == nil {
		return ActionAsk
	}
	switch h.Name() {
	case "claude", "gemini":
		return ActionAsk
	case "codex", "cursor":
		// Codex/Cursor: passthrough on lower tiers (host's native engine
		// can prompt), hard-deny on high+critical (won't be downgraded).
		if tier == RiskHigh || tier == RiskCritical {
			return ActionDeny
		}
		return ActionPassthrough
	case "opencode":
		// OpenCode plugin shim has no passthrough — empty stdout = allow.
		// Below high we surface as allow (visible in config); high+ deny.
		if tier == RiskHigh || tier == RiskCritical {
			return ActionDeny
		}
		return ActionAllow
	default:
		return ActionAsk
	}
}

// validProfileName matches CLI-safe profile identifiers. Lowercase ASCII,
// digits, dash, underscore; must start with a letter; ≤32 chars.
var validProfileName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// ValidateCustomProfile enforces structural invariants for a user-defined
// profile: legal name, no built-in collision, all 5 tiers present, all
// values in {allow, ask, deny}. Returns a user-facing error message.
func ValidateCustomProfile(name string, m map[string]string) error {
	if !validProfileName.MatchString(name) {
		return fmt.Errorf("invalid profile name %q: must match [a-z][a-z0-9_-]{0,31}", name)
	}
	if IsBuiltinProfileName(name) {
		return fmt.Errorf("profile %q collides with a built-in profile", name)
	}
	if len(m) != len(allRiskTiers) {
		return fmt.Errorf("profile must define all %d tiers (%s)", len(allRiskTiers), strings.Join(allRiskTiers, ", "))
	}
	for _, tier := range allRiskTiers {
		v, ok := m[tier]
		if !ok {
			return fmt.Errorf("profile missing tier %q", tier)
		}
		if v != ActionAllow && v != ActionAsk && v != ActionDeny {
			return fmt.Errorf("tier %q action %q invalid: must be allow|ask|deny", tier, v)
		}
	}
	return nil
}

// cmdProfile dispatches `yolonot profile ...` subcommands. Surface:
//
//	yolonot profile                                    show active profile + overrides
//	yolonot profile list                               list built-in + custom profiles
//	yolonot profile show <name>                        print one profile
//	yolonot profile use <name> [--harness=<h>]         set global or per-harness profile
//	yolonot profile reset [--harness=<h>]              clear global or per-harness override
//	yolonot profile create <name> --base=<existing>    clone an existing profile
//	yolonot profile create <name> --safe=allow ...     fully inline form
//	yolonot profile delete <name>                      remove custom profile
//
// Unknown subcommand prints usage to stderr and exits 1.
func cmdProfile(args []string) {
	if len(args) == 0 {
		printActiveProfile()
		return
	}
	switch args[0] {
	case "list", "ls":
		cmdProfileList()
	case "show":
		cmdProfileShow(args[1:])
	case "use", "set":
		cmdProfileUse(args[1:])
	case "reset", "clear":
		cmdProfileReset(args[1:])
	case "create", "new":
		cmdProfileCreate(args[1:])
	case "delete", "rm":
		cmdProfileDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown profile subcommand %q.\n", args[0])
		profileUsage(os.Stderr)
		os.Exit(1)
	}
}

func profileUsage(w *os.File) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  yolonot profile                              Show active profile")
	fmt.Fprintln(w, "  yolonot profile list                         List built-in + custom profiles")
	fmt.Fprintln(w, "  yolonot profile show <name>                  Show one profile's tier→action map")
	fmt.Fprintln(w, "  yolonot profile use <name> [--harness=<h>]   Set global / per-harness profile")
	fmt.Fprintln(w, "  yolonot profile reset [--harness=<h>]        Clear global / per-harness override")
	fmt.Fprintln(w, "  yolonot profile create <name> --base=<existing> [--<tier>=<action>...]")
	fmt.Fprintln(w, "  yolonot profile delete <name>                Remove a custom profile")
}

func printActiveProfile() {
	cfg := LoadConfig()
	globalName := cfg.Profile
	if globalName == "" {
		globalName = DefaultProfileName
	}
	if cfg.Profile == "" {
		fmt.Printf("Active profile: %s (default — set with: yolonot profile use <name>)\n", globalName)
	} else {
		fmt.Printf("Active profile: %s (global)\n", globalName)
	}
	if len(cfg.ProfileOverride) > 0 {
		fmt.Println("Per-harness overrides:")
		names := make([]string, 0, len(cfg.ProfileOverride))
		for k := range cfg.ProfileOverride {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, h := range names {
			fmt.Printf("  %-10s → %s\n", h, cfg.ProfileOverride[h])
		}
	}

	// Env pins (per-session, beat config).
	if v := os.Getenv("YOLONOT_PROFILE"); v != "" {
		fmt.Printf("Env pin (this session): YOLONOT_PROFILE=%s\n", v)
	}
	for _, h := range Harnesses() {
		key := "YOLONOT_" + strings.ToUpper(h.Name()) + "_PROFILE"
		if v := os.Getenv(key); v != "" {
			fmt.Printf("Env pin (this session): %s=%s\n", key, v)
		}
	}

	// Session-file pin (mid-session, beats env).
	if sid := currentSessionID(nil); sid != "" {
		if v := readSessionProfile(sid); v != "" {
			fmt.Printf("Session pin (%s, mid-session): %s\n", shortSession(sid), v)
		}
	}

	fmt.Println()
	fmt.Println("Run `yolonot profile list` to see available profiles.")
}

func cmdProfileList() {
	cfg := LoadConfig()
	all := ListProfiles(cfg)
	fmt.Println("Profiles:")
	fmt.Println()
	for _, p := range all {
		tag := "built-in"
		if !p.Builtin {
			tag = "custom"
		}
		fmt.Printf("  %-10s  [%s]  %s\n", p.Name, tag, p.Description)
		// Inline tier map preview.
		parts := make([]string, 0, len(allRiskTiers))
		for _, t := range allRiskTiers {
			parts = append(parts, fmt.Sprintf("%s=%s", t, p.Map[t]))
		}
		fmt.Printf("              %s\n", strings.Join(parts, "  "))
	}
}

func cmdProfileShow(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: yolonot profile show <name>")
		os.Exit(1)
	}
	cfg := LoadConfig()
	p := LookupProfile(cfg, args[0])
	if p == nil {
		fmt.Fprintf(os.Stderr, "Unknown profile %q.\n", args[0])
		os.Exit(1)
	}
	tag := "built-in"
	if !p.Builtin {
		tag = "custom"
	}
	fmt.Printf("Profile %q [%s]\n", p.Name, tag)
	if p.Description != "" {
		fmt.Printf("  %s\n", p.Description)
	}
	fmt.Println()
	fmt.Printf("  %-9s  %s\n", "tier", "action")
	for _, t := range allRiskTiers {
		fmt.Printf("  %-9s  %s\n", t, p.Map[t])
	}
}

func cmdProfileUse(args []string) {
	name, harness, session := parseProfileNameHarnessSession(args)
	if name == "" {
		fmt.Fprintln(os.Stderr, "Usage: yolonot profile use <name> [--harness=<h>] [--session]")
		os.Exit(1)
	}
	cfg := LoadConfig()
	if LookupProfile(cfg, name) == nil {
		fmt.Fprintf(os.Stderr, "Unknown profile %q. Run: yolonot profile list\n", name)
		os.Exit(1)
	}
	if session {
		sid := resolveSessionID(args)
		if sid == "" {
			fmt.Fprintln(os.Stderr, "Error: --session requires an active session.")
			fmt.Fprintln(os.Stderr, "Pass --current, --session-id <id>, or set CLAUDE_SESSION_ID.")
			os.Exit(1)
		}
		if err := writeSessionProfile(sid, name); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Session %s profile → %s (this session only)\n", shortSession(sid), name)
		fmt.Println("Pin clears automatically when the session ends, or run: yolonot profile reset --session")
		return
	}
	if harness != "" {
		if GetHarness(harness) == nil {
			fmt.Fprintf(os.Stderr, "Unknown harness %q.\n", harness)
			os.Exit(1)
		}
		if cfg.ProfileOverride == nil {
			cfg.ProfileOverride = map[string]string{}
		}
		cfg.ProfileOverride[harness] = name
		SaveConfig(cfg)
		fmt.Printf("%s profile → %s (per-harness override)\n", harness, name)
		return
	}
	cfg.Profile = name
	SaveConfig(cfg)
	fmt.Printf("Global profile → %s\n", name)
}

func shortSession(sid string) string {
	if len(sid) > 8 {
		return sid[:8]
	}
	return sid
}

func cmdProfileReset(args []string) {
	_, harness, session := parseProfileNameHarnessSession(args)
	if session {
		sid := resolveSessionID(args)
		if sid == "" {
			fmt.Fprintln(os.Stderr, "Error: --session requires an active session (use --current, --session-id, or CLAUDE_SESSION_ID).")
			os.Exit(1)
		}
		if err := clearSessionProfile(sid); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Cleared session profile pin for %s.\n", shortSession(sid))
		return
	}
	cfg := LoadConfig()
	if harness != "" {
		if cfg.ProfileOverride == nil {
			fmt.Printf("No override for %s.\n", harness)
			return
		}
		if _, ok := cfg.ProfileOverride[harness]; !ok {
			fmt.Printf("No override for %s.\n", harness)
			return
		}
		delete(cfg.ProfileOverride, harness)
		if len(cfg.ProfileOverride) == 0 {
			cfg.ProfileOverride = nil
		}
		SaveConfig(cfg)
		fmt.Printf("Cleared profile override for %s. Falling back to global %s.\n", harness, effectiveGlobal(cfg))
		return
	}
	if cfg.Profile == "" {
		fmt.Printf("Global profile already at default (%s).\n", DefaultProfileName)
		return
	}
	cfg.Profile = ""
	SaveConfig(cfg)
	fmt.Printf("Global profile reset → %s\n", DefaultProfileName)
}

func cmdProfileCreate(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: yolonot profile create <name> --base=<existing> | --safe=allow --low=... --moderate=... --high=... --critical=...")
		os.Exit(1)
	}
	name := args[0]
	rest := args[1:]

	flags, err := parseProfileFlags(rest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	cfg := LoadConfig()

	// Build the tier map. Start from --base if given, then apply per-tier overrides.
	tierMap := map[string]string{}
	if flags["base"] != "" {
		base := LookupProfile(cfg, flags["base"])
		if base == nil {
			fmt.Fprintf(os.Stderr, "Unknown base profile %q.\n", flags["base"])
			os.Exit(1)
		}
		for k, v := range base.Map {
			tierMap[k] = v
		}
	}
	for _, t := range allRiskTiers {
		if v, ok := flags[t]; ok {
			tierMap[t] = v
		}
	}

	if err := ValidateCustomProfile(name, tierMap); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if _, exists := cfg.CustomProfiles[name]; exists {
		fmt.Fprintf(os.Stderr, "Custom profile %q already exists. Delete it first.\n", name)
		os.Exit(1)
	}

	if cfg.CustomProfiles == nil {
		cfg.CustomProfiles = map[string]map[string]string{}
	}
	cfg.CustomProfiles[name] = tierMap
	SaveConfig(cfg)

	fmt.Printf("Created custom profile %q:\n", name)
	for _, t := range allRiskTiers {
		fmt.Printf("  %-9s  %s\n", t, tierMap[t])
	}
	fmt.Println()
	fmt.Printf("Activate with: yolonot profile use %s\n", name)
}

func cmdProfileDelete(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: yolonot profile delete <name>")
		os.Exit(1)
	}
	name := args[0]
	if IsBuiltinProfileName(name) {
		fmt.Fprintf(os.Stderr, "Cannot delete built-in profile %q.\n", name)
		os.Exit(1)
	}
	cfg := LoadConfig()
	if _, ok := cfg.CustomProfiles[name]; !ok {
		fmt.Fprintf(os.Stderr, "Unknown custom profile %q.\n", name)
		os.Exit(1)
	}
	if cfg.Profile == name {
		fmt.Fprintf(os.Stderr, "Profile %q is the active global profile. Switch first: yolonot profile use <other>\n", name)
		os.Exit(1)
	}
	for h, p := range cfg.ProfileOverride {
		if p == name {
			fmt.Fprintf(os.Stderr, "Profile %q is the active override for harness %q. Reset first: yolonot profile reset --harness=%s\n", name, h, h)
			os.Exit(1)
		}
	}
	delete(cfg.CustomProfiles, name)
	if len(cfg.CustomProfiles) == 0 {
		cfg.CustomProfiles = nil
	}
	SaveConfig(cfg)
	fmt.Printf("Deleted custom profile %q.\n", name)
}

// parseProfileNameHarnessSession extracts the first positional arg as
// `name`, plus optional `--harness=<h>` and `--session` flags.
// Session-related arg flags (--session-id=<id>, --current) are
// intentionally ignored here — resolveSessionID handles them downstream
// so the same args slice can be passed through.
func parseProfileNameHarnessSession(args []string) (name, harness string, session bool) {
	skipNext := false
	for i, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		switch {
		case strings.HasPrefix(a, "--harness="):
			harness = strings.TrimPrefix(a, "--harness=")
			continue
		case a == "--harness":
			if i+1 < len(args) {
				harness = args[i+1]
				skipNext = true
			}
			continue
		case a == "--session":
			session = true
			continue
		case strings.HasPrefix(a, "--session-id=") || a == "--session-id" || a == "--current":
			// resolveSessionID consumes these — ignore here so they don't
			// land in `name`.
			if a == "--session-id" {
				skipNext = true
			}
			continue
		}
		if strings.HasPrefix(a, "--") {
			continue
		}
		if name == "" {
			name = a
		}
	}
	return name, harness, session
}

// parseProfileFlags parses --base=<name> and --<tier>=<action> flags for
// `profile create`. Unknown flags return an error.
func parseProfileFlags(args []string) (map[string]string, error) {
	out := map[string]string{}
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			return nil, fmt.Errorf("unexpected positional arg %q", a)
		}
		eq := strings.IndexByte(a, '=')
		if eq < 0 {
			return nil, fmt.Errorf("flag %q must use --key=value form", a)
		}
		key := strings.TrimPrefix(a[:eq], "--")
		val := a[eq+1:]
		switch key {
		case "base":
			out["base"] = val
		case RiskSafe, RiskLow, RiskModerate, RiskHigh, RiskCritical:
			out[key] = val
		default:
			return nil, fmt.Errorf("unknown flag --%s (valid: --base, --safe, --low, --moderate, --high, --critical)", key)
		}
	}
	return out, nil
}

func effectiveGlobal(cfg Config) string {
	if cfg.Profile != "" {
		return cfg.Profile
	}
	return DefaultProfileName
}

// ListProfiles returns built-in + custom profiles, built-ins first then
// custom in alphabetical order. Used by `yolonot profile list`.
func ListProfiles(cfg Config) []RiskProfile {
	out := BuiltinProfiles()
	customNames := make([]string, 0, len(cfg.CustomProfiles))
	for k := range cfg.CustomProfiles {
		customNames = append(customNames, k)
	}
	sort.Strings(customNames)
	for _, name := range customNames {
		m := cfg.CustomProfiles[name]
		cp := map[string]string{}
		for k, v := range m {
			cp[k] = v
		}
		out = append(out, RiskProfile{Name: name, Description: "custom", Builtin: false, Map: cp})
	}
	return out
}
