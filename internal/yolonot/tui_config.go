package yolonot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/x/term"
)

// `yolonot config` — a settings page over the same config.json fields the
// CLI verbs edit. Rows carry a label, the current value and a status word;
// Enter runs the row's editor (a huh prompt); save writes once with a
// backup. The page owns no policy: every editor calls what the matching
// CLI verb calls. Stdin that is not a terminal falls back to cmdDefault.

type configRow struct {
	Section string
	Label   string
	Value   string
	Hint    string
	Edit    func(cfg *Config) // nil = display only
}

// Status vocabulary for the hint column. Colour carries good/bad; no glyphs.
const (
	hintKeySet     = "key set"
	hintKeyMissing = "key missing"
	hintNotFound   = "not found"
	hintNoModel    = "no model"
	hintOn         = "on"
	hintOff        = "off"
)

var goodHints = map[string]bool{hintKeySet: true, hintOn: true, "ok": true, "ready": true, "installed": true}
var badHints = map[string]bool{hintKeyMissing: true, hintNotFound: true, hintNoModel: true, hintOff: true, "not installed": true, "not running": true}

func keyHint(envKey string) string {
	switch {
	case envKey == "":
		return ""
	case os.Getenv(envKey) != "":
		return hintKeySet
	}
	return hintKeyMissing
}

func onOff(b bool) string {
	if b {
		return hintOn
	}
	return hintOff
}

func tildePath(p string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, home) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

// configRows builds the page model from a config. Pure; unit-tested.
func configRows(cfg Config) []configRow {
	var rows []configRow
	add := func(r configRow) { rows = append(rows, r) }

	// JUDGES — the chain, one row per judge in order.
	for i, sp := range cfg.JudgeSpecs() {
		hint := "may " + strings.Join(sp.effectiveMay(), "/")
		val := sp.Use
		switch sp.Kind() {
		case judgeExec:
			path := strings.TrimPrefix(sp.Use, "exec:")
			val = "exec:" + preCheckShortName(path)
			if !execPathFound(path) {
				hint = hintNotFound
			}
		case judgeUnknown:
			hint = hintNoModel
		}
		add(configRow{"JUDGES", fmt.Sprintf("  %d", i+1), val, hint, editJudgeAt(i)})
	}
	add(configRow{"JUDGES", "  Add judge", "", "", editAddJudge})
	add(configRow{"JUDGES", "  Reset chain", "", "", editResetChain})

	// MODELS — the catalog, then the escalation reference.
	for _, name := range cfg.ModelNames() {
		m := cfg.Models[name]
		add(configRow{"MODELS", name, m.Model, keyHint(m.EnvKey), editModel(name)})
	}
	// Exec hooks live in the chain only; show them here so they read like models.
	for i, sp := range cfg.JudgeSpecs() {
		if sp.Kind() != judgeExec {
			continue
		}
		path := strings.TrimPrefix(sp.Use, "exec:")
		hint := "ready"
		if !execPathFound(path) {
			hint = hintNotFound
		}
		add(configRow{"MODELS", "exec:" + preCheckShortName(path), tildePath(path), hint, editExec(i)})
	}
	add(configRow{"MODELS", "Add model", "", "", editAddModel})
	esc, escHint := hintOff, ""
	if cfg.Escalation != nil && cfg.Escalation.Model != "" {
		esc = cfg.Escalation.Model
		escHint = onOff(!cfg.Escalation.Disabled)
	}
	add(configRow{"MODELS", "Escalation", esc, escHint, editEscalation})
	add(configRow{"MODELS", "If still unsure", EscalationUnresolved(cfg), "", editUnresolved})

	// POLICY — the active profile with its tier map, then per-harness pins.
	prof := activeProfileName(cfg)
	p := LookupProfile(cfg, prof)
	profHint := "built-in"
	switch {
	case p == nil:
		profHint = hintNotFound
	case !p.Builtin:
		profHint = "custom"
	}
	add(configRow{"POLICY", "Profile", prof, profHint, editProfile})
	for _, tier := range allRiskTiers {
		val := ""
		if p != nil {
			val = p.Map[tier]
		}
		add(configRow{"POLICY", "  " + tier, val, "", editTier(tier)})
	}
	add(configRow{"POLICY", "Harness overrides", harnessOverridesSummary(cfg), "", editHarnessOverrides})
	add(configRow{"POLICY", "Attach scripts outside root", onOff(cfg.AttachOutsideRoot), "", editAttach})
	add(configRow{"POLICY", "Quiet on allow", onOff(cfg.QuietOnAllow), "", editQuiet})
	add(configRow{"POLICY", "Rules", tildePath(filepath.Join(YolonotDir(), "rules")), "", editRules})
	proj, projHint := projectRulesPath()
	add(configRow{"POLICY", "Project rules", tildePath(proj), projHint, editProjectRules})
	add(configRow{"POLICY", "Failure behavior", "provider / parse / config / size / timeout", "", editFailures})
	budget := cfg.HookTimeout
	if budget == 0 {
		budget = 55
	}
	add(configRow{"POLICY", "Decision budget", fmt.Sprintf("%ds", budget), "max 55s", func(c *Config) {
		editPositiveSetting("Hook budget, seconds (0 = 55)", c.HookTimeout, 55, func(n int) { c.HookTimeout = n })
	}})

	// PROMPT — what the chat model (and, as state text, the typed model) sees.
	add(configRow{"PROMPT", "Context", hintListSummary(cfg.Prompt.Context), "", editPromptList("Context", "trusted background facts", func(c *Config) *[]string { return &c.Prompt.Context })})
	add(configRow{"PROMPT", "Allow hints", hintListSummary(cfg.Prompt.AllowHints), "", editPromptList("Allow hints", "routine patterns to lean allow on", func(c *Config) *[]string { return &c.Prompt.AllowHints })})
	add(configRow{"PROMPT", "Ask hints", hintListSummary(cfg.Prompt.AskHints), "", editPromptList("Ask hints", "environment-specific risks to lean ask on", func(c *Config) *[]string { return &c.Prompt.AskHints })})
	sys := "built-in"
	if cfg.Prompt.SystemPrompt != "" {
		sys = fmt.Sprintf("custom (%d chars)", len(cfg.Prompt.SystemPrompt))
	}
	add(configRow{"PROMPT", "System prompt", sys, "", editSystemPrompt})
	return rows
}

func activeProfileName(cfg Config) string {
	if cfg.Policy.Profile == "" {
		return DefaultProfileName
	}
	return cfg.Policy.Profile
}

// harnessOverridesSummary: "codex: strict, high→deny; cursor: moderate→ask" or "none".
func harnessOverridesSummary(cfg Config) string {
	names := make([]string, 0, len(cfg.Policy.Harness))
	for n := range cfg.Policy.Harness {
		names = append(names, n)
	}
	sort.Strings(names)
	var parts []string
	for _, n := range names {
		hp := cfg.Policy.Harness[n]
		var bits []string
		if hp.Profile != "" {
			bits = append(bits, hp.Profile)
		}
		for _, t := range allRiskTiers {
			if a, ok := hp.RiskMap[t]; ok {
				bits = append(bits, t+"→"+a)
			}
		}
		parts = append(parts, n+": "+strings.Join(bits, ", "))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "; ")
}

// hintListSummary: "none", "defaults", "defaults + 2", "3 lines".
func hintListSummary(list []string) string {
	n, defaults := 0, false
	for _, s := range list {
		switch {
		case strings.TrimSpace(s) == "$defaults":
			defaults = true
		case strings.TrimSpace(s) != "":
			n++
		}
	}
	switch {
	case defaults && n > 0:
		return fmt.Sprintf("defaults + %d", n)
	case defaults:
		return "defaults"
	case n == 0:
		return "none"
	}
	return fmt.Sprintf("%d lines", n)
}

// projectRulesPath is the nearest .yolonot file from the cwd up to the repo
// root (or $HOME); when none exists the cwd path is offered for creation.
func projectRulesPath() (string, string) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", ""
	}
	home, _ := os.UserHomeDir()
	root := findRepoRoot(cwd)
	for cur := cwd; ; cur = filepath.Dir(cur) {
		p := filepath.Join(cur, ".yolonot")
		if info, err := os.Lstat(p); err == nil && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			return p, ""
		}
		if cur == root || cur == home || cur == filepath.Dir(cur) {
			break
		}
	}
	return filepath.Join(cwd, ".yolonot"), "not created"
}

// --- chain editors ---

var mayChoices = [][]string{{"allow"}, {"allow", "deny"}, {"allow", "ask"}, {"allow", "ask", "deny"}, {"ask", "deny"}, {"deny"}, nil}

var mayLabels = []string{"Allow (else hand to the next judge)", "Allow, deny", "Allow, ask", "Allow, ask, deny", "Ask, deny", "Deny", "Default for this judge kind"}

func mayIndex(may []string) int {
	for i, c := range mayChoices {
		if strings.Join(c, ",") == strings.Join(may, ",") {
			return i
		}
	}
	return len(mayChoices) - 1
}

func editJudgeAt(i int) func(*Config) {
	return func(cfg *Config) {
		if i < 0 || i >= len(cfg.Judges) {
			return
		}
		sp := cfg.Judges[i]
		choice := tuiSelect(sp.Use, []string{"Move up", "Move down", "Remove", "Change what it may decide"}, 0)
		if choice < 0 {
			return
		}
		if choice == 3 {
			m := tuiSelect("What may "+sp.Use+" decide?", mayLabels, mayIndex(sp.May))
			if m < 0 {
				return
			}
			cfg.Judges[i].May = mayChoices[m]
			return
		}
		cfg.Judges = applyJudgeMove(cfg.Judges, i, choice)
	}
}

// applyJudgeMove: 0 = up, 1 = down, 2 = remove (never below one judge).
func applyJudgeMove(specs []JudgeSpec, i, op int) []JudgeSpec {
	switch op {
	case 0:
		if i > 0 {
			specs[i-1], specs[i] = specs[i], specs[i-1]
		}
	case 1:
		if i < len(specs)-1 {
			specs[i+1], specs[i] = specs[i], specs[i+1]
		}
	case 2:
		if len(specs) == 1 {
			tuiNote("Keep at least one judge", "")
			return specs
		}
		specs = append(specs[:i], specs[i+1:]...)
	}
	return specs
}

func editAddJudge(cfg *Config) {
	items := []string{"fast_allow    built-in read-only parser, no network", "exec          external hook binary"}
	names := cfg.ModelNames()
	for _, n := range names {
		kind := "chat"
		if isTypedModel(cfg.Models[n]) {
			kind = "typed"
		}
		items = append(items, fmt.Sprintf("%-13s %s model: %s", n, kind, cfg.Models[n].Model))
	}
	idx := tuiSelect("Add judge", items, 0)
	if idx < 0 {
		return
	}
	var sp JudgeSpec
	switch idx {
	case 0:
		sp = JudgeSpec{Use: judgeFastAllow}
	case 1:
		path := tuiInput("Path to hook", "/path/to/hook", "")
		if path == "" {
			return
		}
		sp = JudgeSpec{Use: "exec:" + path}
	default:
		sp = JudgeSpec{Use: names[idx-2]}
	}
	if err := validateJudgeSpec(*cfg, sp); err != nil {
		tuiNote("Judge not added", err.Error())
		return
	}
	for _, e := range cfg.Judges {
		if e.Use == sp.Use {
			tuiNote("Already in the chain", sp.Use)
			return
		}
	}
	cfg.Judges = append(cfg.Judges, sp)
	tuiNote("Added "+sp.Use+" at the end", "move it with Enter on its row")
}

// chainPresets rebuild the model slots from the catalog: the first typed
// and the first chat model, in catalog order.
func editResetChain(cfg *Config) {
	// Prefer the models already in the chain; otherwise the first of each
	// kind that is not the escalation model.
	typed, chat := "", cfg.ChatModelName()
	esc := ""
	if cfg.Escalation != nil {
		esc = cfg.Escalation.Model
	}
	for _, sp := range cfg.Judges {
		if cfg.kindOf(sp) == judgeTyped && typed == "" {
			typed = sp.Use
		}
	}
	for _, n := range cfg.ModelNames() {
		if n == esc {
			continue
		}
		if isTypedModel(cfg.Models[n]) {
			if typed == "" {
				typed = n
			}
		} else if chat == "" {
			chat = n
		}
	}
	items := []string{
		"Chat only         " + orNone(chat) + " judges",
		"Typed only        " + orNone(typed) + " judges",
		"Typed first       " + orNone(typed) + ", then " + orNone(chat),
		"Edit as JSON      in $EDITOR",
	}
	idx := tuiSelect("Reset chain", items, 0)
	if idx < 0 {
		return
	}
	var models []JudgeSpec
	switch idx {
	case 0:
		models = specsFor(chat)
	case 1:
		models = specsFor(typed)
	case 2:
		models = specsFor(typed, chat)
	case 3:
		editJudgesInEditor(cfg)
		return
	}
	if len(models) == 0 {
		tuiNote("No such model in the catalog", "add one under MODELS first")
		return
	}
	cfg.Judges = withModelSlots(*cfg, cfg.Judges, models)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func specsFor(names ...string) []JudgeSpec {
	var out []JudgeSpec
	for _, n := range names {
		if n != "" {
			out = append(out, JudgeSpec{Use: n})
		}
	}
	return out
}

// withModelSlots replaces the model entries of specs with models, at the
// position of the first model, or at the end when there was none.
func withModelSlots(cfg Config, specs, models []JudgeSpec) []JudgeSpec {
	pos := -1
	var rest []JudgeSpec
	for _, s := range specs {
		switch cfg.kindOf(s) {
		case judgeTyped, judgeChat, judgeUnknown:
			if pos < 0 {
				pos = len(rest)
			}
		default:
			rest = append(rest, s)
		}
	}
	if pos < 0 {
		pos = len(rest)
	}
	out := append([]JudgeSpec{}, rest[:pos]...)
	out = append(out, models...)
	return append(out, rest[pos:]...)
}

func editJudgesInEditor(cfg *Config) {
	out, err := editJSONInEditor(cfg.Judges)
	if err != nil {
		tuiNote("Chain not changed", err.Error())
		return
	}
	for _, spec := range out {
		if err := validateJudgeSpec(*cfg, spec); err != nil {
			tuiNote("Chain not changed", err.Error())
			return
		}
	}
	cfg.Judges = out
}

func editJSONInEditor(specs JudgeList) (JudgeList, error) {
	tmp, err := os.CreateTemp("", "yolonot-judges-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	b, _ := json.MarshalIndent(specs, "", "  ")
	if _, err := tmp.Write(b); err != nil {
		return nil, err
	}
	tmp.Close()
	if err := runEditor(tmp.Name()); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, err
	}
	var out JudgeList
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty chain")
	}
	return out, nil
}

// --- model and policy editors ---

func editModel(name string) func(*Config) {
	return func(cfg *Config) {
		m := cfg.Models[name]
		switch tuiSelect(name+"  "+m.Model, []string{"Test connection", "Replace", "Remove", "Protocol"}, 0) {
		case 0:
			if testProviderConnection(m) {
				tuiNote("Connection ok", m.Model)
			} else {
				tuiNote("Connection failed", m.Model+" — check the key and URL")
			}
		case 1:
			var sel ProviderConfig
			var ok bool
			if isTypedModel(m) {
				sel, ok = pickDecisionProvider()
			} else {
				sel, ok = pickProvider(*cfg, false)
			}
			if ok {
				cfg.Models[name] = sel
			}
		case 2:
			for _, sp := range cfg.Judges {
				if sp.Use == name {
					tuiNote("In the judge chain", "remove it from JUDGES first")
					return
				}
			}
			if cfg.Escalation != nil && cfg.Escalation.Model == name {
				tuiNote("Used for escalation", "change Escalation first")
				return
			}
			delete(cfg.Models, name)
		case 3:
			editModelProtocol(cfg, name)
		}
	}
}

// editExec edits the exec hook at judge index i: test it on a sample
// command, change its path, or drop it from the chain.
func editExec(i int) func(*Config) {
	return func(cfg *Config) {
		if i < 0 || i >= len(cfg.Judges) {
			return
		}
		path := strings.TrimPrefix(cfg.Judges[i].Use, "exec:")
		switch tuiSelect("exec:"+preCheckShortName(path)+"  "+tildePath(path), []string{"Test", "Replace path", "Remove"}, 0) {
		case 0:
			if !execPathFound(path) {
				tuiNote("Not found", path)
				return
			}
			cwd, _ := os.Getwd()
			input, _ := json.Marshal(HookPayload{HookEventName: "PreToolUse", ToolName: "Bash", Cwd: cwd,
				ToolInput: map[string]interface{}{"command": "ls -la"}})
			if _, reason, ok := runPreCheck(path, input); ok {
				tuiNote("Hook ok: allowed `ls -la`", reason)
			} else {
				tuiNote("Hook ran, no allow for `ls -la`", "it falls through to the next judge; check it prints PreToolUse JSON")
			}
		case 1:
			if p := tuiInput("Path to hook", path, path); p != "" {
				sp := cfg.Judges[i]
				sp.Use = "exec:" + p
				if err := validateJudgeSpec(*cfg, sp); err != nil {
					tuiNote("Path not changed", err.Error())
					return
				}
				cfg.Judges[i] = sp
			}
		case 2:
			cfg.Judges = applyJudgeMove(cfg.Judges, i, 2)
		}
	}
}

func editAddModel(cfg *Config) {
	kind := tuiSelect("Add model", []string{"Chat model (judges, similarity, suggest)", "Typed decision model (TypeSafe Jev, Microsoft-Decision-1, OpenAI Decisions)", "Exec hook (external PreToolUse binary, e.g. a local classifier)"}, 0)
	if kind < 0 {
		return
	}
	if kind == 2 {
		path := tuiInput("Path to hook", "/path/to/hook", "")
		if path == "" {
			return
		}
		if err := validateJudgeSpec(*cfg, JudgeSpec{Use: "exec:" + path}); err != nil {
			tuiNote("Judge not added", err.Error())
			return
		}
		for _, e := range cfg.Judges {
			if e.Use == "exec:"+path {
				tuiNote("Already in the chain", path)
				return
			}
		}
		cfg.Judges = append(cfg.Judges, JudgeSpec{Use: "exec:" + path})
		tuiNote("Added exec:"+preCheckShortName(path)+" at the end of JUDGES", "an exec hook is a judge; move it with Enter on its row")
		return
	}
	name, m, ok := pickModel(*cfg, kind == 1)
	if !ok {
		return
	}
	cfg.putModel(name, m)
	if testProviderConnection(m) {
		tuiNote("Added "+name, "connection ok — add it to JUDGES to use it")
	} else {
		tuiNote("Added "+name, "connection failed — check the key and URL")
	}
}

func editEscalation(cfg *Config) {
	// One editor for model and switch: Off, or pick a model (which turns it on).
	cur := escalationSelection(*cfg)
	switch tuiSelect("Escalation", []string{"Off", "Pick escalation model"}, cur) {
	case 0:
		if cfg.Escalation != nil {
			cfg.Escalation.Disabled = true
		}
	case 1:
		if name, ok := pickEscalationModel(cfg); ok {
			setEscalationModel(cfg, name)
		}
	}
}

func escalationSelection(cfg Config) int {
	if cfg.Escalation != nil && cfg.Escalation.Model != "" && !cfg.Escalation.Disabled {
		return 1
	}
	return 0
}

func execPathFound(path string) bool {
	parts := strings.Fields(path)
	if len(parts) == 0 {
		return false
	}
	_, err := exec.LookPath(parts[0])
	return err == nil
}

// pickEscalationModel offers the catalog's chat models plus "Add a new
// model", which runs the picker with escalation-sized suggestions.
func pickEscalationModel(cfg *Config) (string, bool) {
	var names []string
	var items []string
	for _, n := range cfg.ModelNames() {
		if m := cfg.Models[n]; !isTypedModel(m) {
			names = append(names, n)
			items = append(items, fmt.Sprintf("%-13s %s", n, m.Model))
		}
	}
	items = append(items, "Add a new model")
	idx := tuiSelect("Escalation model", items, 0)
	switch {
	case idx < 0:
		return "", false
	case idx < len(names):
		return names[idx], true
	}
	sel, ok := pickProvider(*cfg, true)
	if !ok {
		return "", false
	}
	return cfg.addModel(sel), true
}

// setEscalationModel is shared with `yolonot escalation setup`.
func setEscalationModel(cfg *Config, name string) {
	if cfg.Escalation == nil {
		cfg.Escalation = &EscalationConfig{}
	}
	cfg.Escalation.Model = name
	cfg.Escalation.Disabled = false
}

func editUnresolved(cfg *Config) {
	cur := 0
	if EscalationUnresolved(*cfg) == ActionDeny {
		cur = 1
	}
	idx := tuiSelect("If still unsure after escalation", []string{"Ask me", "Deny"}, cur)
	if idx < 0 {
		return
	}
	if cfg.Escalation == nil {
		if idx == 0 {
			return
		}
		cfg.Escalation = &EscalationConfig{}
	}
	cfg.Escalation.Unresolved = []string{"", "deny"}[idx]
}

// profileItems lists profiles as "name  description" with the active index.
func profileItems(cfg Config) ([]RiskProfile, []string, int) {
	profiles := ListProfiles(cfg)
	items := make([]string, len(profiles))
	cur := 0
	for i, p := range profiles {
		desc := p.Description
		if cut := strings.Index(desc, ". "); cut > 0 {
			desc = desc[:cut]
		}
		items[i] = fmt.Sprintf("%-10s %s", p.Name, desc)
		if p.Name == activeProfileName(cfg) {
			cur = i
		}
	}
	return profiles, items, cur
}

func editProfile(cfg *Config) {
	prof := activeProfileName(*cfg)
	menu := []string{"Use another profile", "Create new profile"}
	if _, custom := cfg.Policy.Profiles[prof]; custom {
		menu = append(menu, "Delete "+prof)
	}
	switch tuiSelect("Profile  "+prof, menu, 0) {
	case 0:
		profiles, items, cur := profileItems(*cfg)
		if idx := tuiSelect("Use profile", items, cur); idx >= 0 {
			cfg.Policy.Profile = profiles[idx].Name
		}
	case 1:
		editProfileCreate(cfg)
	case 2:
		for h, hp := range cfg.Policy.Harness {
			if hp.Profile == prof {
				tuiNote("Pinned by harness "+h, "change Harness overrides first")
				return
			}
		}
		delete(cfg.Policy.Profiles, prof)
		if len(cfg.Policy.Profiles) == 0 {
			cfg.Policy.Profiles = nil
		}
		cfg.Policy.Profile = DefaultProfileName
		tuiNote("Deleted "+prof, "active profile is now "+DefaultProfileName)
	}
}

var profileActions = []string{ActionAllow, ActionAsk, ActionDeny}

func indexOf(list []string, v string) int {
	for i, s := range list {
		if s == v {
			return i
		}
	}
	return 0
}

// editProfileCreate: name, base profile, then the five tiers on one screen.
// The new profile becomes the active one.
func editProfileCreate(cfg *Config) {
	name := strings.TrimSpace(tuiInput("New profile name", "a-z, digits, - or _", ""))
	if name == "" {
		return
	}
	if _, exists := cfg.Policy.Profiles[name]; exists {
		tuiNote("Not created", "profile "+name+" exists")
		return
	}
	profiles, items, cur := profileItems(*cfg)
	base := tuiSelect("Start from", items, cur)
	if base < 0 {
		return
	}
	fields := make([]menuField, 0, len(allRiskTiers))
	for _, tier := range allRiskTiers {
		fields = append(fields, menuField{Title: tier, Items: profileActions, Cur: indexOf(profileActions, profiles[base].Map[tier])})
	}
	fields, ok := runMenu("Profile "+name, "", fields)
	if !ok {
		return
	}
	m := map[string]string{}
	for i, tier := range allRiskTiers {
		m[tier] = profileActions[fields[i].Cur]
	}
	if err := ValidateCustomProfile(name, m); err != nil {
		tuiNote("Not created", err.Error())
		return
	}
	if cfg.Policy.Profiles == nil {
		cfg.Policy.Profiles = map[string]map[string]string{}
	}
	cfg.Policy.Profiles[name] = m
	cfg.Policy.Profile = name
	tuiNote("Created "+name, "active after save")
}

// editTier changes one tier of the active profile. Built-ins are read-only,
// so the change lands in a custom copy that becomes active.
func editTier(tier string) func(*Config) {
	return func(cfg *Config) {
		prof := activeProfileName(*cfg)
		p := LookupProfile(*cfg, prof)
		if p == nil {
			tuiNote("Unknown profile "+prof, "pick another under Profile")
			return
		}
		a := tuiSelect(prof+"  "+tier+" →", profileActions, indexOf(profileActions, p.Map[tier]))
		if a < 0 || profileActions[a] == p.Map[tier] {
			return
		}
		target := prof
		if p.Builtin {
			target = tuiInput("Built-in profiles are read-only. Save as", prof+"-custom", prof+"-custom")
			if target == "" {
				return
			}
			if _, exists := cfg.Policy.Profiles[target]; exists && !tuiConfirm("Replace existing profile "+target+"?") {
				return
			}
		}
		m := map[string]string{}
		for k, v := range p.Map {
			m[k] = v
		}
		m[tier] = profileActions[a]
		if err := ValidateCustomProfile(target, m); err != nil {
			tuiNote("Not saved", err.Error())
			return
		}
		if cfg.Policy.Profiles == nil {
			cfg.Policy.Profiles = map[string]map[string]string{}
		}
		cfg.Policy.Profiles[target] = m
		cfg.Policy.Profile = target
	}
}

// editHarnessOverrides: pick a harness, then one screen with its profile pin
// and five tier overrides ("inherit" clears a cell).
func editHarnessOverrides(cfg *Config) {
	hs := Harnesses()
	items := make([]string, len(hs))
	for i, h := range hs {
		s := "inherits global"
		if hp, ok := cfg.Policy.Harness[h.Name()]; ok {
			sum := harnessOverridesSummary(Config{Policy: PolicyConfig{Harness: map[string]HarnessPolicy{h.Name(): hp}}})
			s = strings.TrimPrefix(sum, h.Name()+": ")
		}
		items[i] = fmt.Sprintf("%-9s %s", h.Name(), s)
	}
	i := tuiSelect("Harness", items, 0)
	if i < 0 {
		return
	}
	name := hs[i].Name()
	hp := cfg.harnessPolicy(name)

	profiles, pitems, _ := profileItems(*cfg)
	pins := []string{"inherit global (" + activeProfileName(*cfg) + ")"}
	pinNames := []string{""}
	for j, p := range profiles {
		pins = append(pins, pitems[j])
		pinNames = append(pinNames, p.Name)
	}
	cells := []string{"inherit", ActionAllow, ActionAsk, ActionDeny, ActionPassthrough}
	fields := []menuField{{Title: "Profile", Items: pins, Cur: indexOf(pinNames, hp.Profile)}}
	for _, tier := range allRiskTiers {
		v := "inherit"
		if a, ok := hp.RiskMap[tier]; ok {
			v = a
		}
		fields = append(fields, menuField{Title: tier + " override", Items: cells, Cur: indexOf(cells, v)})
	}
	fields, ok := runMenu("Harness "+name, "", fields)
	if !ok {
		return
	}
	hp.Profile = pinNames[fields[0].Cur]
	hp.RiskMap = nil
	for i, tier := range allRiskTiers {
		if v := cells[fields[i+1].Cur]; v != "inherit" {
			if hp.RiskMap == nil {
				hp.RiskMap = map[string]string{}
			}
			hp.RiskMap[tier] = v
		}
	}
	cfg.setHarnessPolicy(name, hp)
}

func editAttach(cfg *Config) { cfg.AttachOutsideRoot = !cfg.AttachOutsideRoot }

func editProjectRules(cfg *Config) {
	p, _ := projectRulesPath()
	if p == "" {
		return
	}
	editRuleDraft(p)
}

// editPromptList opens the list in $EDITOR, one entry per line; `#` lines
// are dropped and `$defaults` keeps the built-in set.
func editPromptList(title, what string, get func(*Config) *[]string) func(*Config) {
	return func(cfg *Config) {
		list := get(cfg)
		var b strings.Builder
		fmt.Fprintf(&b, "# %s: %s. One entry per line.\n", title, what)
		b.WriteString("# Keep `$defaults` to include yolonot's built-in list; `#` lines are ignored.\n\n")
		for _, s := range *list {
			b.WriteString(s + "\n")
		}
		text, ok := editText("yolonot-"+strings.ToLower(strings.ReplaceAll(title, " ", "-"))+"-*.txt", b.String())
		if !ok {
			return
		}
		var out []string
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			out = append(out, line)
		}
		*list = out
	}
}

func editSystemPrompt(cfg *Config) {
	switch tuiSelect("System prompt", []string{"Edit custom prompt", "Use the built-in prompt", "Verify custom prompt (yolonot prompt verify)"}, 0) {
	case 0:
		text, ok := editText("yolonot-system-prompt-*.txt", cfg.Prompt.SystemPrompt)
		if ok {
			cfg.Prompt.SystemPrompt = strings.TrimSpace(text)
		}
	case 1:
		cfg.Prompt.SystemPrompt = ""
	case 2:
		tuiNote("Run after saving", "yolonot prompt verify")
	}
}

// editText round-trips text through $EDITOR via a temp file.
func editText(pattern, initial string) (string, bool) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		tuiNote("Editor failed", err.Error())
		return "", false
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(initial); err != nil {
		f.Close()
		tuiNote("Editor failed", err.Error())
		return "", false
	}
	if err := f.Close(); err != nil {
		tuiNote("Editor failed", err.Error())
		return "", false
	}
	if err := runEditor(f.Name()); err != nil {
		tuiNote("Editor failed", err.Error())
		return "", false
	}
	data, err := os.ReadFile(f.Name())
	if err != nil {
		tuiNote("Editor failed", err.Error())
		return "", false
	}
	return string(data), true
}

func editQuiet(cfg *Config) { cfg.QuietOnAllow = !cfg.QuietOnAllow }

func editRules(cfg *Config) {
	editRuleDraft(filepath.Join(YolonotDir(), "rules"))
}

// runEditor opens path in $VISUAL / $EDITOR (default vi) and waits.
func runEditor(path string) error {
	ed := os.Getenv("VISUAL")
	if ed == "" {
		ed = os.Getenv("EDITOR")
	}
	if ed == "" {
		ed = "vi"
	}
	parts := strings.Fields(ed)
	if len(parts) == 0 {
		return fmt.Errorf("EDITOR must name an executable")
	}
	cmd := exec.Command(parts[0], append(parts[1:], path)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	// A full-screen editor leaves the alternate screen on exit; the page
	// would otherwise draw over (and clear) the user's shell screen.
	if tuiInPage {
		fmt.Print("\x1b[?1049h")
	}
	return err
}

// stdinIsTerminal is a real isatty check: /dev/null is a character device
// too, so Stat alone would call a redirected stdin a terminal.
func stdinIsTerminal() bool {
	return term.IsTerminal(os.Stdin.Fd())
}

// cmdConfigTUI runs the settings page until save or quit. Editors run
// between page instances so huh prompts get the terminal.
func cmdConfigTUI() {
	if !stdinIsTerminal() {
		cmdDefault()
		return
	}
	offerMigration(LoadConfig())
	// One alternate screen for the whole session: the page, menus and
	// prompts are separate programs, and entering/leaving the alt screen
	// per program flashes the shell between them. They clear and redraw
	// inside this one instead.
	tuiInPage = true
	tuiExitMsg = ""
	tuiRuleDrafts = &ruleDrafts{}
	fmt.Print("\x1b[?1049h")
	defer func() {
		tuiInPage = false
		tuiRuleDrafts = nil
		tuiConfigSnapshot = nil
		fmt.Print("\x1b[?1049l")
		if tuiExitMsg != "" {
			fmt.Println(tuiExitMsg)
		}
	}()
	tuiConfigSnapshot, _ = readConfigSnapshot()
	cfg := LoadConfig()
	orig, _ := json.Marshal(cfg)
	cur := 0
	for {
		now, _ := json.Marshal(cfg)
		dirty := string(now) != string(orig) || tuiRuleDrafts.dirty()
		rows := configRows(cfg)
		action, chosen, pos := runPage(rows, dirty, tuiNotice, cur)
		cur = pos
		tuiNotice = ""
		switch action {
		case pageEdit:
			if chosen >= 0 && chosen < len(rows) && rows[chosen].Edit != nil {
				rows[chosen].Edit(&cfg)
			}
		case pageSave:
			if !dirty {
				tuiExitMsg = "No changes."
				return
			}
			if saveConfigWithBackup(cfg) {
				return
			}
		case pageQuit:
			if !dirty {
				return
			}
			switch tuiSelect("Unsaved changes", []string{"Save and quit", "Discard and quit", "Keep editing"}, 0) {
			case 0:
				if saveConfigWithBackup(cfg) {
					return
				}
			case 1:
				tuiExitMsg = "Discarded."
				return
			}
		}
	}
}

// tuiExitMsg is printed once the settings screen has left the alternate
// screen, where a plain Println would vanish.
var tuiExitMsg string

// configSnapshot is config.json as the settings page read it; saving
// refuses to replace a file another verb rewrote while the page was open.
type configSnapshot struct {
	data    []byte
	existed bool
}

var tuiConfigSnapshot *configSnapshot

func readConfigSnapshot() (*configSnapshot, error) {
	data, err := os.ReadFile(configPath())
	if errors.Is(err, os.ErrNotExist) {
		return &configSnapshot{}, nil
	}
	if err != nil {
		return nil, err
	}
	return &configSnapshot{data: data, existed: true}, nil
}

func saveConfigWithBackup(cfg Config) bool {
	if err := ValidateConfig(cfg); err != nil {
		tuiNote("Not saved", err.Error())
		return false
	}
	if cfg.Legacy && !tuiConfirm("config.json is in the v0 format; saving writes v1. Continue? (backup kept at .bak)") {
		tuiNote("Not saved", "keep editing or discard the changes")
		return false
	}
	for _, spec := range cfg.Judges {
		if err := validateJudgeSpec(cfg, spec); err != nil {
			tuiNote("Not saved", err.Error())
			return false
		}
	}
	if tuiConfigSnapshot != nil {
		now, err := readConfigSnapshot()
		if err != nil {
			tuiNote("Not saved", err.Error())
			return false
		}
		if now.existed != tuiConfigSnapshot.existed || !bytes.Equal(now.data, tuiConfigSnapshot.data) {
			tuiNote("Not saved", "config changed outside settings; reopen settings before saving: "+configPath())
			return false
		}
	}
	backedUp := false
	if data, err := os.ReadFile(configPath()); err == nil {
		if err := atomicWriteFile(configPath()+".bak", data, 0600); err != nil {
			tuiNote("Not saved", "config backup: "+err.Error())
			return false
		}
		backedUp = true
	} else if !errors.Is(err, os.ErrNotExist) {
		tuiNote("Not saved", err.Error())
		return false
	}
	rollback, err := tuiRuleDrafts.commit()
	if err != nil {
		tuiNote("Not saved", err.Error())
		return false
	}
	if err := saveConfig(cfg); err != nil {
		err = errors.Join(err, rollback())
		tuiNote("Not saved", err.Error())
		return false
	}
	tuiExitMsg = "Saved."
	if backedUp {
		tuiExitMsg += " Previous config kept at " + tildePath(configPath()) + ".bak"
	}
	return true
}
