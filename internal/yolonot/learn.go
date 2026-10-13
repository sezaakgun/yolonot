package yolonot

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Precedents are the user's own answers to asks (layer "human"), kept in a
// small file next to the decision log so every judge call can read them.
// "Allow once" answers are not precedents: the user said not to remember.

type precedent struct {
	Ts       string `json:"ts"`
	Cwd      string `json:"cwd"`
	Command  string `json:"command"`
	Decision string `json:"decision"`
}

func precedentsPath() string { return filepath.Join(YolonotDir(), "precedents.jsonl") }

func isPrecedent(e DecisionEntry) bool {
	return e.Layer == "human" && (e.Source == "ask_approved" || e.Source == "ask_rejected") && e.Cwd != ""
}

func recordPrecedent(e DecisionEntry) {
	if !isPrecedent(e) {
		return
	}
	b, err := json.Marshal(precedent{Ts: e.Timestamp, Cwd: e.Cwd, Command: e.Command, Decision: e.Decision})
	if err != nil {
		return
	}
	os.MkdirAll(YolonotDir(), 0700)
	f, err := os.OpenFile(precedentsPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

// rebuildPrecedents scans the decision log once, for installs that logged
// human answers before the precedent file existed.
func rebuildPrecedents() {
	f, err := os.Open(decisionsPath())
	if err != nil {
		return
	}
	defer f.Close()
	out, err := os.OpenFile(precedentsPath(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	defer out.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var e DecisionEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || !isPrecedent(e) {
			continue
		}
		b, _ := json.Marshal(precedent{Ts: e.Timestamp, Cwd: e.Cwd, Command: e.Command, Decision: e.Decision})
		out.Write(append(b, '\n'))
	}
}

func loadPrecedents() []precedent {
	if _, err := os.Stat(precedentsPath()); err != nil {
		rebuildPrecedents()
	}
	f, err := os.Open(precedentsPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []precedent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var p precedent
		if json.Unmarshal(sc.Bytes(), &p) == nil && p.Command != "" {
			out = append(out, p)
		}
	}
	return out
}

func projectRoot(cwd string) string {
	if cwd == "" {
		return ""
	}
	if root := gitRoot(cwd); root != "" {
		return root
	}
	return cwd
}

// projectPrecedents keeps the latest verdict per command under the project
// root, newest first.
func projectPrecedents(cwd string) []precedent {
	root := projectRoot(cwd)
	if root == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []precedent
	all := loadPrecedents()
	for i := len(all) - 1; i >= 0; i-- {
		p := all[i]
		if p.Cwd != root && !strings.HasPrefix(p.Cwd, root+string(os.PathSeparator)) {
			continue
		}
		if seen[p.Command] {
			continue
		}
		seen[p.Command] = true
		out = append(out, p)
	}
	return out
}

func cmdTokens(s string) map[string]bool {
	t := map[string]bool{}
	for _, w := range strings.Fields(strings.ToLower(s)) {
		w = strings.Trim(w, `"'`)
		if w != "" {
			t[w] = true
		}
	}
	return t
}

// cmdSimilarity is token Jaccard with a bonus for a shared first word, so
// `wget -q a.com` and `wget -q b.com` rank near each other and `ls` does not.
func cmdSimilarity(a, b string) float64 {
	ta, tb := cmdTokens(a), cmdTokens(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	inter := 0
	for w := range ta {
		if tb[w] {
			inter++
		}
	}
	score := float64(inter) / float64(len(ta)+len(tb)-inter)
	if firstToken(a) == firstToken(b) {
		score += 0.3
	}
	return score
}

const (
	precedentLimit    = 5
	precedentMinScore = 0.3
)

// Precedents returns the past human verdicts in this project closest to
// command, split by decision.
func Precedents(command, cwd string) (allowed, rejected []string) {
	type scored struct {
		p precedent
		s float64
	}
	var hits []scored
	for _, p := range projectPrecedents(cwd) {
		if s := cmdSimilarity(command, p.Command); s >= precedentMinScore {
			hits = append(hits, scored{p, s})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].s > hits[j].s })
	if len(hits) > precedentLimit {
		hits = hits[:precedentLimit]
	}
	for _, h := range hits {
		if h.p.Decision == "deny" {
			rejected = append(rejected, h.p.Command)
		} else {
			allowed = append(allowed, h.p.Command)
		}
	}
	return allowed, rejected
}

// addPrecedentHints folds the precedents into the hint lists every judge
// already reads: an allowed precedent is an "Allow when" line, a rejected one
// an "Ask when" line.
func addPrecedentHints(h *WalkupHints, command, cwd string) {
	allowed, rejected := Precedents(command, cwd)
	for _, c := range allowed {
		h.AllowHints = append(h.AllowHints, "the user allowed `"+c+"` in this project; treat the same command or a close variant the same way")
	}
	for _, c := range rejected {
		h.AskHints = append(h.AskHints, "the user rejected `"+c+"` in this project; ask again for it or a close variant")
	}
}

func cmdLogHuman() {
	cwd, _ := os.Getwd()
	ps := projectPrecedents(cwd)
	if len(ps) == 0 {
		fmt.Println("No answers to asks recorded for this project yet. They accrue as you allow or deny what yolonot asks about.")
		return
	}
	fmt.Printf("Your answers to asks in %s (latest per command, newest first):\n\n", filepath.Base(projectRoot(cwd)))
	for _, p := range ps {
		day := p.Ts
		if len(day) > 10 {
			day = day[:10]
		}
		fmt.Printf("  %s  %-5s %s\n", day, p.Decision, p.Command)
	}
}
