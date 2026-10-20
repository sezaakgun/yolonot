package yolonot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

func init() { RegisterHarness(newCodexHarness()) }

// CodexHarness is the OpenAI Codex CLI adapter.
type CodexHarness struct {
	baseHarness
}

func newCodexHarness() *CodexHarness {
	h := &CodexHarness{
		baseHarness: baseHarness{
			name:                 "codex",
			usesPermRequestPhase: true,
			riskMap:              allowDenyRiskMap(),
			sessionEnvKeys:       []string{"YOLONOT_CODEX_SESSION_ID"},
			configDirFn:          codexConfigDir,
			settingsPathFn: func() string {
				return filepath.Join(codexConfigDir(), "hooks.json")
			},
			skillDirFn: func() string {
				home, _ := os.UserHomeDir()
				return filepath.Join(home, ".agents", "skills", "yolonot")
			},
			parseFn: func(input []byte) (HookPayload, error) {
				if len(input) == 0 {
					return HookPayload{}, nil
				}
				var p HookPayload
				if err := json.Unmarshal(input, &p); err != nil {
					return HookPayload{}, err
				}
				if wd, ok := p.ToolInput["workdir"].(string); ok && wd != "" {
					if !filepath.IsAbs(wd) && p.Cwd != "" {
						p.Cwd = filepath.Join(p.Cwd, wd)
					} else {
						p.Cwd = wd
					}
				}
				if !p.BypassSandbox {
					p.BypassSandbox = extractToolInputBypassSandbox(p.ToolInput)
				}
				return p, nil
			},
			formatFn: func(r HookResponse) string {
				return formatPermissionRequestOrClaude(r, false)
			},
			notes: []string{
				"PreToolUse blocks deny decisions; PermissionRequest approves allowed requests and leaves ask decisions to Codex's own permission dialog.",
				"Use 'deny' rules for hard blocks; see 'yolonot risk codex' for the default risk map.",
				"Review and trust the installed hooks in Codex /hooks; changed non-managed hooks are skipped until trusted.",
				"yolonot install enables features.hooks in Codex config.toml (CODEX_HOME is supported).",
			},
		},
	}
	h.useNestedJSONHooks(nestedJSONHooksSpec{
		harnessName:     "codex",
		events:          []string{"PreToolUse", "PermissionRequest", "PostToolUse"},
		matcher:         "Bash",
		matchAnyYolonot: true,
		preInstall: func(string) error {
			if err := ensureCodexFeatureFlag(); err != nil {
				return fmt.Errorf("enable Codex hooks: %w", err)
			}
			return nil
		},
	})
	return h
}

func codexConfigDir() string {
	if dir := os.Getenv("CODEX_HOME"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".codex")
}

// ensureCodexFeatureFlag enables canonical hooks and migrates its deprecated
// codex_hooks alias. Surgical edits preserve comments and unrelated settings;
// parsing before and after refuses invalid TOML rather than appending a
// duplicate [features] table.
func ensureCodexFeatureFlag() error {
	path := filepath.Join(codexConfigDir(), "config.toml")
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	updated, err := enableCodexHookFlags(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if bytes.Equal(updated, data) {
		return nil
	}
	perm := os.FileMode(0600)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	if err := atomicWriteFile(path, updated, perm); err != nil {
		return err
	}
	Verbosef("enabled Codex hooks in %s", path)
	return nil
}

func enableCodexHookFlags(data []byte) ([]byte, error) {
	var config map[string]interface{}
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("invalid TOML: %w", err)
	}
	features, ok := config["features"].(map[string]interface{})
	if _, exists := config["features"]; exists && !ok {
		return nil, fmt.Errorf("features must be a table")
	}
	hasFlag := false
	for _, key := range []string{"hooks", "codex_hooks"} {
		if value, exists := features[key]; exists {
			if _, ok := value.(bool); !ok {
				return nil, fmt.Errorf("features.%s must be a boolean", key)
			}
			hasFlag = true
		}
	}
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	var parser unstable.Parser
	var table []string
	featureHeaderEnd, inlineStart := -1, -1
	inlineNonempty := false
	keys := func(n *unstable.Node) []string {
		var parts []string
		it := n.Key()
		for it.Next() {
			parts = append(parts, string(it.Node().Data))
		}
		return parts
	}
	var visit func(*unstable.Node, []string, bool)
	visit = func(n *unstable.Node, prefix []string, inline bool) {
		path := append(append([]string{}, prefix...), keys(n)...)
		value := n.Value()
		legacy := len(path) == 2 && path[0] == "features" && path[1] == "codex_hooks"
		_, canonicalExists := features["hooks"]
		if legacy {
			it := n.Key()
			var first, last *unstable.Node
			for it.Next() {
				last = it.Node()
				if first == nil {
					first = last
				}
			}
			if !canonicalExists {
				start, length := int(last.Raw.Offset), int(last.Raw.Length)
				key := "hooks"
				if data[start] == '\'' {
					key = "'hooks'"
				}
				if data[start] == '"' {
					key = "\"hooks\""
				}
				edits = append(edits, edit{start, start + length, key})
			} else {
				span := parser.Range(value.Data)
				start, end := int(first.Raw.Offset), int(span.Offset+span.Length)
				if inline {
					// Remove this entry and one adjacent comma, preserving
					// every other inline-table field and its formatting.
					right := end
					for right < len(data) && strings.ContainsRune(" \t\r\n", rune(data[right])) {
						right++
					}
					if right < len(data) && data[right] == ',' {
						end = right + 1
					} else {
						left := start - 1
						for left >= 0 && strings.ContainsRune(" \t\r\n", rune(data[left])) {
							left--
						}
						if left < 0 || data[left] != ',' {
							return
						}
						start = left
					}
					edits = append(edits, edit{start, end, ""})
				} else {
					// Keep the old line/comment as an inert migration note.
					edits = append(edits, edit{start, end, "# deprecated alias: " + string(data[start:end])})
				}
			}
		}
		if len(path) == 2 && path[0] == "features" && (path[1] == "hooks" || (legacy && !canonicalExists)) && string(value.Data) == "false" {
			span := parser.Range(value.Data)
			start := int(span.Offset)
			edits = append(edits, edit{start, start + int(span.Length), "true"})
		}
		if value.Kind == unstable.InlineTable {
			children := value.Children()
			if len(path) == 1 && path[0] == "features" {
				inlineStart = int(value.Raw.Offset) + 1 // immediately after {
				inlineNonempty = value.Child() != nil
			}
			for children.Next() {
				visit(children.Node(), path, true)
			}
		}
	}
	parser.Reset(data)
	for parser.NextExpression() {
		n := parser.Expression()
		switch n.Kind {
		case unstable.Table, unstable.ArrayTable:
			table = keys(n)
			if n.Kind == unstable.Table && len(table) == 1 && table[0] == "features" {
				it := n.Key()
				it.Next()
				start := int(it.Node().Raw.Offset)
				featureHeaderEnd = len(data)
				if end := bytes.IndexByte(data[start:], '\n'); end >= 0 {
					featureHeaderEnd = start + end + 1
				}
			}
		case unstable.KeyValue:
			visit(n, table, false)
		}
	}
	if err := parser.Error(); err != nil {
		return nil, err
	}
	if !hasFlag {
		newline := "\n"
		if bytes.Contains(data, []byte("\r\n")) {
			newline = "\r\n"
		}
		switch {
		case inlineStart >= 0:
			text := "hooks = true"
			if inlineNonempty {
				text += ", "
			}
			edits = append(edits, edit{inlineStart, inlineStart, text})
		case featureHeaderEnd >= 0:
			text := "hooks = true" + newline
			if featureHeaderEnd > 0 && data[featureHeaderEnd-1] != '\n' {
				text = newline + text
			}
			edits = append(edits, edit{featureHeaderEnd, featureHeaderEnd, text})
		case features != nil:
			// A dotted key or child table can define features without an
			// explicit [features] header. A root dotted key extends it safely.
			edits = append(edits, edit{0, 0, "features.hooks = true" + newline})
		default:
			text := "[features]" + newline + "hooks = true" + newline
			if len(data) > 0 && data[len(data)-1] != '\n' {
				text = newline + text
			}
			edits = append(edits, edit{len(data), len(data), text})
		}
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	updated := append([]byte{}, data...)
	for _, e := range edits {
		updated = append(append(append([]byte{}, updated[:e.start]...), e.text...), updated[e.end:]...)
	}
	var verified map[string]interface{}
	if err := toml.Unmarshal(updated, &verified); err != nil {
		return nil, fmt.Errorf("cannot safely enable hooks: %w", err)
	}
	flags, _ := verified["features"].(map[string]interface{})
	if _, exists := flags["codex_hooks"]; exists {
		return nil, fmt.Errorf("cannot safely migrate deprecated features.codex_hooks")
	}
	if flags["hooks"] != true {
		return nil, fmt.Errorf("cannot safely enable features.hooks")
	}
	return updated, nil
}
