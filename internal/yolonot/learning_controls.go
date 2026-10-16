package yolonot

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func learningEnabled(cfg Config) bool {
	return cfg.LoadError == nil && (cfg.Learning.Enabled == nil || *cfg.Learning.Enabled)
}

func withPrecedentLock(fn func() error) error {
	if err := os.MkdirAll(YolonotDir(), 0700); err != nil {
		return err
	}
	path := precedentsPath() + ".lock"
	deadline := time.Now().Add(2 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			f.Close()
			defer os.Remove(path)
			return fn()
		}
		if !os.IsExist(err) {
			return err
		}
		if info, e := os.Stat(path); e == nil && time.Since(info.ModTime()) > time.Minute {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("precedent store is busy; retry")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readStoredPrecedents() []precedent {
	f, err := os.Open(precedentsPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	var records []precedent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var p precedent
		if json.Unmarshal(sc.Bytes(), &p) == nil && p.Command != "" {
			records = append(records, p)
		}
	}
	return records
}

func retainedPrecedents(all []precedent, cfg LearningConfig, now time.Time) []precedent {
	var kept []precedent
	for _, p := range all {
		if cfg.RetentionDays > 0 {
			ts, err := time.Parse(time.RFC3339Nano, p.Ts)
			if err != nil || ts.Before(now.Add(-time.Duration(cfg.RetentionDays)*24*time.Hour)) {
				continue
			}
		}
		kept = append(kept, p)
	}
	if cfg.MaxEntries > 0 && len(kept) > cfg.MaxEntries {
		kept = kept[len(kept)-cfg.MaxEntries:]
	}
	return kept
}

func writePrecedents(records []precedent) error {
	var b strings.Builder
	for _, p := range records {
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return atomicWriteFile(precedentsPath(), []byte(b.String()), 0600)
}

func changePrecedents(keep func(precedent) bool, cfg LearningConfig) (int, error) {
	removed := 0
	err := withPrecedentLock(func() error {
		all := readStoredPrecedents()
		var selected []precedent
		for _, p := range all {
			if keep(p) {
				selected = append(selected, p)
			}
		}
		selected = retainedPrecedents(selected, cfg, time.Now())
		removed = len(all) - len(selected)
		return writePrecedents(selected)
	})
	return removed, err
}

func cmdLearning(args []string) {
	cfg := LoadConfig()
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "status":
		fmt.Printf("Learning enabled: %t\nRetention days: %d (0 = unlimited)\nMaximum entries: %d (0 = unlimited)\nStored answers: %d\n", learningEnabled(cfg), cfg.Learning.RetentionDays, cfg.Learning.MaxEntries, len(readStoredPrecedents()))
	case "list":
		cmdLogHuman()
	case "on", "off":
		if !requireV1(&cfg) {
			return
		}
		enabled := sub == "on"
		cfg.Learning.Enabled = &enabled
		mustSaveConfig(cfg)
		fmt.Printf("Learning %s. Existing history is retained; use forget/clear to remove it.\n", sub)
	case "retention", "limit":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "Usage: yolonot learning retention <days> | limit <entries> (0 = unlimited)")
			os.Exit(2)
		}
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 0 {
			fmt.Fprintln(os.Stderr, "Expected a nonnegative integer")
			os.Exit(2)
		}
		if !requireV1(&cfg) {
			return
		}
		if sub == "retention" {
			cfg.Learning.RetentionDays = n
		} else {
			cfg.Learning.MaxEntries = n
		}
		mustSaveConfig(cfg)
	case "forget", "clear", "prune":
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		root := projectRoot(cwd)
		command := ""
		if sub == "forget" && len(args) > 2 {
			fmt.Fprintln(os.Stderr, "Pass the command as one quoted argument: yolonot learning forget '<exact command>'")
			os.Exit(2)
		}
		if sub == "prune" && len(args) > 1 {
			fmt.Fprintln(os.Stderr, "Usage: yolonot learning prune")
			os.Exit(2)
		}
		if len(args) > 1 {
			command = args[1]
		}
		if sub == "forget" && command == "" {
			fmt.Fprintln(os.Stderr, "Usage: yolonot learning forget '<exact command>'")
			os.Exit(2)
		}
		allProjects := sub == "clear" && len(args) == 2 && args[1] == "--all"
		if sub == "clear" && len(args) > 1 && !allProjects && !(len(args) == 2 && args[1] == "--project") {
			fmt.Fprintln(os.Stderr, "Usage: yolonot learning clear [--project|--all]")
			os.Exit(2)
		}
		removed, err := changePrecedents(func(p precedent) bool {
			if sub == "prune" {
				return true
			}
			pcwd := canonicalDirectory(p.Cwd)
			inProject := pcwd == root || strings.HasPrefix(pcwd, root+string(os.PathSeparator))
			if sub == "clear" {
				return !allProjects && !inProject
			}
			return !inProject || p.Command != command
		}, cfg.Learning)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("Removed %d learned answers. Decision logs are retained.\n", removed)
	default:
		fmt.Fprintln(os.Stderr, "Usage: yolonot learning [status|list|on|off|retention <days>|limit <entries>|forget <command>|clear [--all]|prune]")
		os.Exit(2)
	}
}
