package yolonot

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

func discoverExtendedHarness(name, home string, projDirs []string, addFile func(*DiscoveredHostFile)) {
	switch name {
	case "crush":
		if h := GetHarness("crush"); h != nil {
			if p := h.SettingsPath(); p != "" {
				addFile(parseCrushConfigFile("user", p))
			}
		}
		for _, d := range projDirs {
			addFile(parseCrushConfigFile("project", filepath.Join(d, "crush.json")))
			addFile(parseCrushConfigFile("project", filepath.Join(d, ".crush.json")))
		}

	case "qwen":
		if dir := qwenConfigDir(); dir != "" {
			addFile(parseQwenSettingsFile("user", filepath.Join(dir, "settings.json")))
		}
		for _, d := range projDirs {
			addFile(parseQwenSettingsFile("project", filepath.Join(d, ".qwen", "settings.json")))
		}

	case "zcode":
		if h := GetHarness("zcode"); h != nil {
			if p := h.SettingsPath(); p != "" {
				addFile(parseZcodeSettingsFile("user", p))
			}
		}
		if home != "" {
			addFile(parseZcodeSettingsFile("user", filepath.Join(home, ".zcode", "cli", "config.json")))
		}
		for _, d := range projDirs {
			addFile(parseZcodeSettingsFile("project", filepath.Join(d, "zcode.json")))
			addFile(parseZcodeSettingsFile("project", filepath.Join(d, ".zcode", "config.json")))
		}

	case "copilot":
		if dir := copilotConfigDir(); dir != "" {
			addFile(parseCopilotSettingsFile("user", filepath.Join(dir, "settings.json")))
		}
		for _, d := range projDirs {
			addFile(parseCopilotSettingsFile("project", filepath.Join(d, ".github", "copilot", "settings.json")))
			addFile(parseCopilotSettingsFile("project", filepath.Join(d, ".github", "copilot", "settings.local.json")))
		}

	case "grok":
		if dir := grokConfigDir(); dir != "" {
			for _, fn := range []string{"requirements.toml", "managed_config.toml", "config.toml"} {
				addFile(parseGrokTOMLFile("user", filepath.Join(dir, fn)))
			}
		}
		for _, d := range projDirs {
			addFile(parseGrokTOMLFile("project", filepath.Join(d, ".grok", "config.toml")))
		}

	case "deepseek":
		if dir := dshConfigDir(); dir != "" {
			addFile(parseDeepseekCordisFile("user", filepath.Join(dir, "cordis.patch.yml")))
		}

	case "hermes":
		if dir := hermesConfigDir(); dir != "" {
			addFile(parseHermesConfigFile("user", filepath.Join(dir, "config.yaml")))
		}

	case "kimi":
		if dir := kimiConfigDir(); dir != "" {
			addFile(parseKimiTOMLFile("user", filepath.Join(dir, "config.toml")))
		}

	case "devin":
		if dir := devinConfigDir(); dir != "" {
			addFile(parseDevinConfigFile("user", filepath.Join(dir, "config.json")))
		}
		for _, d := range projDirs {
			addFile(parseDevinConfigFile("project", filepath.Join(d, ".devin", "config.json")))
			addFile(parseDevinConfigFile("project", filepath.Join(d, ".devin", "config.local.json")))
		}

	case "muse":
		if dir := museConfigDir(); dir != "" {
			addFile(parseMuseSettingsFile("user", filepath.Join(dir, "settings.json")))
			addFile(parseMuseApprovalPolicyFile("user", filepath.Join(dir, "approval-policy.json")))
		}

	case "goose":
		if dir := gooseConfigDir(); dir != "" {
			addFile(parseGoosePermissionFile("user", filepath.Join(dir, "permission.yaml")))
			addFile(parseGooseConfigFile("user", filepath.Join(dir, "config.yaml")))
		}

	case "openhands":
		if dir := openhandsConfigDir(); dir != "" {
			addFile(parseOpenhandsSettingsFile("user", filepath.Join(dir, "agent_settings.json")))
		}

	case "kiro":
		if dir := kiroConfigDir(); dir != "" {
			addFile(parseKiroCLISettingsFile("user", filepath.Join(dir, "settings", "cli.json")))
			for _, p := range globSorted(filepath.Join(dir, "agents", "*.json")) {
				addFile(parseKiroAgentFile("user", p))
			}
		}
		for _, d := range projDirs {
			for _, p := range globSorted(filepath.Join(d, ".kiro", "agents", "*.json")) {
				addFile(parseKiroAgentFile("project", p))
			}
		}

	case "cline":
		if dir := clineConfigDir(); dir != "" {
			addFile(parseClineSettingsFile("user", filepath.Join(dir, "data", "settings", "global-settings.json")))
		}

	case "kilo":
		if dir := kiloConfigDir(); dir != "" {
			for _, fn := range []string{"kilo.json", "kilo.jsonc", "opencode.json", "opencode.jsonc", "config.json"} {
				addFile(parseKiloConfigFile("user", filepath.Join(dir, fn)))
			}
		}
		for _, d := range projDirs {
			addFile(parseKiloConfigFile("project", filepath.Join(d, "kilo.json")))
			addFile(parseKiloConfigFile("project", filepath.Join(d, "kilo.jsonc")))
			for _, fn := range []string{"kilo.json", "kilo.jsonc", "opencode.json", "opencode.jsonc"} {
				addFile(parseKiloConfigFile("project", filepath.Join(d, ".kilo", fn)))
				addFile(parseKiloConfigFile("project", filepath.Join(d, ".kilocode", fn)))
			}
		}

	case "openclaw":
		if dir := openclawConfigDir(); dir != "" {
			addFile(parseOpenclawConfigFile("user", filepath.Join(dir, "openclaw.json")))
			addFile(parseOpenclawApprovalsFile("user", filepath.Join(dir, "exec-approvals.json")))
		}

	case "pi":
		if dir := piConfigDir(); dir != "" {
			addFile(parsePiSettingsFile("user", filepath.Join(dir, "settings.json")))
		}
		for _, d := range projDirs {
			addFile(parsePiSettingsFile("project", filepath.Join(d, ".pi", "settings.json")))
		}

	case "mirror":
		if dir := mirrorConfigDir(); dir != "" {
			addFile(parseMirrorConfigFile("user", filepath.Join(dir, "config.json")))
			addFile(parseMirrorApprovalsFile("user", filepath.Join(dir, "tool_approvals.json")))
		}

	case "amp":
		if dir := ampConfigDir(); dir != "" {
			addFile(parseAmpSettingsFile("user", filepath.Join(dir, "settings.json")))
		}
		for _, d := range projDirs {
			addFile(parseAmpSettingsFile("project", filepath.Join(d, ".amp", "settings.json")))
		}
	}
}

func convertExtendedShellPermissionRule(action, raw string, extraPrefixes ...string) (DiscoveredRule, bool) {
	if dr, ok := convertClaudePermissionRule(action, raw); ok {
		return dr, true
	}
	s := strings.TrimSpace(raw)
	for _, tool := range extraPrefixes {
		if s == tool || s == tool+"(*)" {
			return DiscoveredRule{
				Action:        action,
				Raw:           s,
				SuggestedRule: action + "-cmd *",
			}, true
		}
		prefix := tool + "("
		if strings.HasPrefix(s, prefix) && strings.HasSuffix(s, ")") {
			inner := normalizeColonWildcard(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, prefix), ")")))
			return buildSuggestedShellRule(action, s, inner, false), true
		}
	}
	return DiscoveredRule{}, false
}

func parseCrushConfigFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "crush", Scope: scope, Path: path}
	if perms, ok := raw["permissions"].(map[string]interface{}); ok {
		if allowed, ok := perms["allowed_tools"].([]interface{}); ok {
			for _, it := range allowed {
				s, _ := it.(string)
				if s == "bash" || s == "bash:execute" || s == "*" {
					out.Rules = append(out.Rules, DiscoveredRule{
						Action:        "allow",
						Raw:           fmt.Sprintf("permissions.allowed_tools=%q", s),
						SuggestedRule: "allow-cmd *",
					})
					out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
						Category: "host_permissions",
						Detail:   fmt.Sprintf("permissions.allowed_tools contains %q in %s (auto-approves bash commands)", s, path),
					})
				}
			}
		}
	}
	if opts, ok := raw["options"].(map[string]interface{}); ok {
		if disabled, ok := opts["disabled_tools"].([]interface{}); ok {
			for _, it := range disabled {
				if s, _ := it.(string); s == "bash" {
					out.Rules = append(out.Rules, DiscoveredRule{
						Action:        "deny",
						Raw:           `options.disabled_tools="bash"`,
						SuggestedRule: "deny-cmd *",
					})
				}
			}
		}
	}
	return out
}

func parseQwenSettingsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "qwen", Scope: scope, Path: path}
	if mode, _ := raw["approvalMode"].(string); mode == "yolo" {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("approvalMode is yolo in %s", path),
		})
	}
	if tools, ok := raw["tools"].(map[string]interface{}); ok {
		if mode, _ := tools["approvalMode"].(string); mode == "yolo" {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("tools.approvalMode is yolo in %s", path),
			})
		}
		if aa, ok := tools["autoAccept"].(bool); ok && aa {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("tools.autoAccept is true in %s", path),
			})
		}
		if sb, ok := tools["sandbox"].(bool); ok && !sb {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_sandbox",
				Detail:   fmt.Sprintf("tools.sandbox is false in %s", path),
			})
		}
	}
	if perms, ok := raw["permissions"].(map[string]interface{}); ok {
		for _, action := range []string{"allow", "deny", "ask"} {
			items, _ := perms[action].([]interface{})
			for _, it := range items {
				s, ok := it.(string)
				if !ok {
					continue
				}
				if dr, ok := convertExtendedShellPermissionRule(action, s, "Shell", "run_shell_command"); ok {
					out.Rules = append(out.Rules, dr)
				}
			}
		}
		if am, ok := perms["autoMode"].(map[string]interface{}); ok {
			if envs, ok := am["environment"].([]interface{}); ok {
				for _, it := range envs {
					if s := strings.TrimSpace(asString(it)); s != "" {
						out.Hints = append(out.Hints, DiscoveredHint{Kind: "context", Text: s})
					}
				}
			}
			if hints, ok := am["hints"].(map[string]interface{}); ok {
				for _, it := range sliceAny(hints["allow"]) {
					if s := strings.TrimSpace(asString(it)); s != "" {
						out.Hints = append(out.Hints, DiscoveredHint{Kind: "allow-hint", Text: s})
					}
				}
				for _, field := range []string{"softDeny", "hardDeny", "deny"} {
					for _, it := range sliceAny(hints[field]) {
						if s := strings.TrimSpace(asString(it)); s != "" {
							out.Hints = append(out.Hints, DiscoveredHint{Kind: "ask-hint", Text: s})
						}
					}
				}
			}
		}
	}
	return out
}

func parseZcodeSettingsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "zcode", Scope: scope, Path: path}
	if perm, ok := raw["permission"].(map[string]interface{}); ok {
		if mode, _ := perm["mode"].(string); mode == "yolo" || mode == "guarded" {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("permission.mode is %s in %s", mode, path),
			})
		}
		if aa, ok := perm["autoApproveHighRisk"].(bool); ok && aa {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("permission.autoApproveHighRisk is true in %s", path),
			})
		}
		for _, it := range sliceAny(perm["allowedTools"]) {
			s := asString(it)
			if s == "Bash" || s == "*" {
				out.Rules = append(out.Rules, DiscoveredRule{
					Action:        "allow",
					Raw:           fmt.Sprintf("permission.allowedTools=%q", s),
					SuggestedRule: "allow-cmd *",
				})
				out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
					Category: "host_permissions",
					Detail:   fmt.Sprintf("permission.allowedTools contains %q in %s", s, path),
				})
			} else if dr, ok := convertExtendedShellPermissionRule("allow", s, "Shell"); ok {
				out.Rules = append(out.Rules, dr)
			}
		}
		for _, it := range sliceAny(perm["disallowedTools"]) {
			s := asString(it)
			if s == "Bash" {
				out.Rules = append(out.Rules, DiscoveredRule{
					Action:        "deny",
					Raw:           `permission.disallowedTools="Bash"`,
					SuggestedRule: "deny-cmd *",
				})
			} else if dr, ok := convertExtendedShellPermissionRule("deny", s, "Shell"); ok {
				out.Rules = append(out.Rules, dr)
			}
		}
	}
	return out
}

func parseCopilotSettingsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "copilot", Scope: scope, Path: path}
	if mode, _ := raw["defaultPermissionMode"].(string); mode == "allow-all" {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("defaultPermissionMode is allow-all in %s", path),
		})
	}
	if mode, _ := raw["defaultMode"].(string); mode == "autopilot" || mode == "allow-all" {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("defaultMode is %s in %s", mode, path),
		})
	}
	if perms, ok := raw["permissions"].(map[string]interface{}); ok {
		if mode, _ := perms["defaultMode"].(string); mode == "allow-all" {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("permissions.defaultMode is allow-all in %s", path),
			})
		}
		for _, action := range []string{"allow", "deny", "ask"} {
			for _, it := range sliceAny(perms[action]) {
				if s := asString(it); s != "" {
					if dr, ok := convertExtendedShellPermissionRule(action, s, "Shell", "bash", "local_shell"); ok {
						out.Rules = append(out.Rules, dr)
					}
				}
			}
		}
	}
	if sb, ok := raw["sandbox"].(map[string]interface{}); ok {
		if enabled, ok := sb["enabled"].(bool); ok && !enabled {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_sandbox",
				Detail:   fmt.Sprintf("sandbox.enabled is false in %s", path),
			})
		}
	}
	return out
}

func parseGrokTOMLFile(scope, path string) *DiscoveredHostFile {
	data, err := readDiscoveryFile(path, scope == "project")
	if err != nil {
		return nil
	}
	var parsed map[string]interface{}
	if toml.Unmarshal(data, &parsed) != nil {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "grok", Scope: scope, Path: path}
	if ui, ok := parsed["ui"].(map[string]interface{}); ok {
		if pm, _ := ui["permission_mode"].(string); pm == "always-approve" || pm == "bypassPermissions" || pm == "auto" || pm == "dontAsk" {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("ui.permission_mode is %q in %s", pm, path),
			})
		}
	}
	if sb, ok := parsed["sandbox"].(map[string]interface{}); ok {
		if prof, _ := sb["profile"].(string); prof == "off" {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_sandbox",
				Detail:   fmt.Sprintf("sandbox.profile is \"off\" in %s", path),
			})
		}
	}
	if perm, ok := parsed["permission"].(map[string]interface{}); ok {
		for _, action := range []string{"allow", "deny", "ask"} {
			for _, it := range sliceAny(perm[action]) {
				if s := asString(it); s != "" {
					if dr, ok := convertExtendedShellPermissionRule(action, s, "Shell", "run_terminal_command"); ok {
						out.Rules = append(out.Rules, dr)
					}
				}
			}
		}
		for _, r := range sliceMapAny(perm["rules"]) {
			act := asString(r["action"])
			tool := asString(r["tool"])
			pat := asString(r["pattern"])
			if act != "allow" && act != "ask" && act != "deny" {
				continue
			}
			raw := fmt.Sprintf("%s(%s)", tool, pat)
			if dr, ok := convertExtendedShellPermissionRule(act, raw, "Shell", "run_terminal_command"); ok {
				out.Rules = append(out.Rules, dr)
			}
		}
	}
	return out
}

func sliceMapAny(v interface{}) []map[string]interface{} {
	if s, ok := v.([]map[string]interface{}); ok {
		return s
	}
	raw := sliceAny(v)
	var out []map[string]interface{}
	for _, it := range raw {
		if m, ok := it.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}

func asString(v interface{}) string {
	s, _ := v.(string)
	return s
}

func sliceAny(v interface{}) []interface{} {
	s, _ := v.([]interface{})
	return s
}

func parseDeepseekCordisFile(scope, path string) *DiscoveredHostFile {
	data, err := readDiscoveryFile(path, scope == "project")
	if err != nil {
		return nil
	}
	text := string(data)
	out := &DiscoveredHostFile{Harness: "deepseek", Scope: scope, Path: path}
	if strings.Contains(text, "danger-full-access") {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_sandbox",
			Detail:   fmt.Sprintf("danger-full-access configured in %s (disables DSH OS sandbox or permission gate)", path),
		})
	}
	if strings.Contains(text, "policy: never") || strings.Contains(text, `policy: "never"`) {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("approval policy is never in %s", path),
		})
	}
	return out
}

func parseHermesConfigFile(scope, path string) *DiscoveredHostFile {
	data, err := readDiscoveryFile(path, scope == "project")
	if err != nil {
		return nil
	}
	text := string(data)
	out := &DiscoveredHostFile{Harness: "hermes", Scope: scope, Path: path}
	for _, item := range extractYAMLList(text, "command_allowlist") {
		out.Rules = append(out.Rules, buildSuggestedShellRule("allow", "command_allowlist="+item, item, true))
	}
	for _, item := range extractYAMLList(text, "deny") {
		out.Rules = append(out.Rules, buildSuggestedShellRule("deny", "approvals.deny="+item, item, true))
	}
	if strings.Contains(text, "mode: off") || strings.Contains(text, "mode: \"off\"") || strings.Contains(text, "mode: false") {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("approvals.mode is off/false in %s", path),
		})
	}
	if strings.Contains(text, "backend: local") || strings.Contains(text, `backend: "local"`) {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_sandbox",
			Detail:   fmt.Sprintf("terminal.backend is local in %s (unsandboxed host execution)", path),
		})
	}
	return out
}

func extractYAMLList(text, key string) []string {
	lines := strings.Split(text, "\n")
	var out []string
	inList := false
	keyIndent := 0
	target := key + ":"
	for _, rawLine := range lines {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(rawLine) - len(strings.TrimLeft(rawLine, " \t"))
		if !inList {
			if strings.HasPrefix(trimmed, target) {
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, target))
				if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
					inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rest, "["), "]"))
					for _, part := range strings.Split(inner, ",") {
						v := strings.Trim(strings.TrimSpace(part), `"'`)
						if v != "" {
							out = append(out, v)
						}
					}
				} else if rest == "" {
					inList = true
					keyIndent = indent
				}
			}
			continue
		}
		if indent < keyIndent || (indent == keyIndent && !strings.HasPrefix(trimmed, "-")) {
			inList = false
			continue
		}
		if strings.HasPrefix(trimmed, "-") {
			v := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			if !strings.HasPrefix(v, `"`) && !strings.HasPrefix(v, `'`) {
				if idx := strings.Index(v, " #"); idx >= 0 {
					v = strings.TrimSpace(v[:idx])
				}
			}
			v = strings.Trim(v, `"'`)
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

func parseKimiTOMLFile(scope, path string) *DiscoveredHostFile {
	data, err := readDiscoveryFile(path, scope == "project")
	if err != nil {
		return nil
	}
	var parsed map[string]interface{}
	if toml.Unmarshal(data, &parsed) != nil {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "kimi", Scope: scope, Path: path}
	if mode, _ := parsed["default_permission_mode"].(string); mode == "auto" || mode == "yolo" {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("default_permission_mode is %q in %s (skips dangerous-command-ask)", mode, path),
		})
	}
	if perm, ok := parsed["permission"].(map[string]interface{}); ok {
		if guard, ok := perm["dangerous_command_guard"].(bool); ok && !guard {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("permission.dangerous_command_guard is false in %s", path),
			})
		}
		for _, it := range sliceAny(perm["rules"]) {
			m, ok := it.(map[string]interface{})
			if !ok {
				continue
			}
			dec := asString(m["decision"])
			pat := asString(m["pattern"])
			if dec == "allow" || dec == "ask" || dec == "deny" {
				if dr, ok := convertExtendedShellPermissionRule(dec, pat, "Shell"); ok {
					out.Rules = append(out.Rules, dr)
				}
			}
		}
	}
	return out
}

func parseDevinConfigFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "devin", Scope: scope, Path: path}
	if perms, ok := raw["permissions"].(map[string]interface{}); ok {
		for _, action := range []string{"allow", "deny", "ask"} {
			for _, it := range sliceAny(perms[action]) {
				s := asString(it)
				if s == "exec" || s == "Exec(*)" {
					out.Rules = append(out.Rules, DiscoveredRule{
						Action:        action,
						Raw:           s,
						SuggestedRule: action + "-cmd *",
					})
					if action == "allow" {
						out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
							Category: "host_permissions",
							Detail:   fmt.Sprintf("permissions.allow contains %q in %s", s, path),
						})
					}
				} else if dr, ok := convertExtendedShellPermissionRule(action, s, "Exec", "exec"); ok {
					out.Rules = append(out.Rules, dr)
				}
			}
		}
	}
	if sb, ok := raw["sandbox"].(map[string]interface{}); ok {
		if excl, ok := sb["excluded"].(map[string]interface{}); ok {
			for _, it := range sliceAny(excl["allow"]) {
				if s := asString(it); s != "" {
					out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
						Category: "host_sandbox",
						Detail:   fmt.Sprintf("sandbox.excluded.allow contains %q in %s (runs outside OS sandbox without prompting)", s, path),
					})
				}
			}
		}
	}
	return out
}

func parseMuseSettingsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "muse", Scope: scope, Path: path}
	if perms, ok := raw["permissions"].(map[string]interface{}); ok {
		if prof, _ := perms["default_profile"].(string); prof == ":unrestricted" {
			out.PolicyAlerts = append(out.PolicyAlerts,
				DiscoveredPolicyAlert{
					Category: "host_permissions",
					Detail:   fmt.Sprintf("permissions.default_profile is :unrestricted in %s", path),
				},
				DiscoveredPolicyAlert{
					Category: "host_sandbox",
					Detail:   fmt.Sprintf("permissions.default_profile is :unrestricted in %s (OS sandbox disabled)", path),
				},
			)
		}
	}
	return out
}

func parseMuseApprovalPolicyFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, false, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "muse", Scope: scope, Path: path}
	for _, it := range sliceAny(raw["rules"]) {
		entry, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		eff := asString(entry["effect"])
		act := "allow"
		switch eff {
		case "deny":
			act = "deny"
		case "prompt":
			act = "ask"
		case "allow":
			act = "allow"
		default:
			continue
		}
		ruleObj, _ := entry["rule"].(map[string]interface{})
		switch asString(ruleObj["kind"]) {
		case "shell_command_argv_prefix":
			var toks []string
			for _, t := range sliceAny(ruleObj["argv_prefix"]) {
				if s := asString(t); s != "" {
					toks = append(toks, s)
				}
			}
			if len(toks) > 0 {
				joined := strings.Join(toks, " ")
				out.Rules = append(out.Rules, buildSuggestedShellRule(act, "argv_prefix:"+joined, joined+" *", false))
			}
		case "shell_command_exact_raw":
			if cmd := strings.TrimSpace(asString(ruleObj["command"])); cmd != "" {
				out.Rules = append(out.Rules, buildSuggestedShellRule(act, "exact:"+cmd, cmd, false))
			}
		}
	}
	return out
}

func parseGoosePermissionFile(scope, path string) *DiscoveredHostFile {
	data, err := readDiscoveryFile(path, scope == "project")
	if err != nil {
		return nil
	}
	text := string(data)
	out := &DiscoveredHostFile{Harness: "goose", Scope: scope, Path: path}
	for _, s := range extractYAMLList(text, "always_allow") {
		if s == "shell" || s == "developer__shell" {
			out.Rules = append(out.Rules, DiscoveredRule{
				Action:        "allow",
				Raw:           "user.always_allow=" + s,
				SuggestedRule: "allow-cmd *",
			})
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("user.always_allow contains %q in %s", s, path),
			})
		}
	}
	for _, s := range extractYAMLList(text, "never_allow") {
		if s == "shell" || s == "developer__shell" {
			out.Rules = append(out.Rules, DiscoveredRule{
				Action:        "deny",
				Raw:           "user.never_allow=" + s,
				SuggestedRule: "deny-cmd *",
			})
		}
	}
	return out
}

func parseGooseConfigFile(scope, path string) *DiscoveredHostFile {
	data, err := readDiscoveryFile(path, scope == "project")
	if err != nil {
		return nil
	}
	text := string(data)
	out := &DiscoveredHostFile{Harness: "goose", Scope: scope, Path: path}
	if strings.Contains(text, "GOOSE_MODE: auto") || strings.Contains(text, `GOOSE_MODE: "auto"`) || strings.Contains(text, "GOOSE_MODE: 'auto'") {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("GOOSE_MODE is set to auto in %s (skips permission.yaml)", path),
		})
	}
	return out
}

func parseOpenhandsSettingsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, false, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "openhands", Scope: scope, Path: path}
	if v, exists := raw["security_policy_filename"]; exists && asString(v) == "" {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("security_policy_filename is empty in %s", path),
		})
	}
	return out
}

func parseKiroCLISettingsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "kiro", Scope: scope, Path: path}
	if b, ok := raw["chat.disableTrustAllConfirmation"].(bool); ok && b {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("chat.disableTrustAllConfirmation is true in %s", path),
		})
	}
	for _, it := range sliceAny(raw["policyPreset"]) {
		if asString(it) == "allow-all" {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("policyPreset contains allow-all in %s", path),
			})
		}
	}
	return out
}

func parseKiroAgentFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "kiro", Scope: scope, Path: path}
	if ts, ok := raw["toolsSettings"].(map[string]interface{}); ok {
		for _, tool := range []string{"shell", "execute_bash"} {
			if sh, ok := ts[tool].(map[string]interface{}); ok {
				for _, it := range sliceAny(sh["allowedCommands"]) {
					if s := strings.TrimSpace(asString(it)); s != "" {
						out.Rules = append(out.Rules, buildSuggestedShellRule("allow", tool+".allowedCommands="+s, s, true))
					}
				}
				for _, it := range sliceAny(sh["deniedCommands"]) {
					if s := strings.TrimSpace(asString(it)); s != "" {
						out.Rules = append(out.Rules, buildSuggestedShellRule("deny", tool+".deniedCommands="+s, s, true))
					}
				}
			}
		}
	}
	return out
}

func parseClineSettingsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "cline", Scope: scope, Path: path}
	if b, ok := raw["toolAutoApprove"].(bool); ok && b {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("toolAutoApprove is enabled in %s", path),
		})
	}
	if b, ok := raw["yolo"].(bool); ok && b {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("yolo is true in %s (disables all Cline runtime hooks)", path),
		})
	}
	return out
}

func parseKiloConfigFile(scope, path string) *DiscoveredHostFile {
	out := parseOpencodeConfigFile(scope, path)
	if out == nil {
		return nil
	}
	out.Harness = "kilo"
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return out
	}
	if perm, ok := raw["permission"].(map[string]interface{}); ok {
		if bash, ok := perm["bash"].(string); ok && bash == "allow" {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("permission.bash is \"allow\" in %s (Kilo Code migrateBashPermission default)", path),
			})
		}
	}
	if sb, ok := raw["sandbox"].(map[string]interface{}); ok {
		if enabled, ok := sb["enabled"].(bool); ok && !enabled {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_sandbox",
				Detail:   fmt.Sprintf("sandbox.enabled is false in %s", path),
			})
		}
	}
	return out
}

func parseOpenclawConfigFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "openclaw", Scope: scope, Path: path}
	if tools, ok := raw["tools"].(map[string]interface{}); ok {
		if execCfg, ok := tools["exec"].(map[string]interface{}); ok {
			if mode := asString(execCfg["mode"]); mode == "full" || mode == "auto" {
				out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
					Category: "host_permissions",
					Detail:   fmt.Sprintf("tools.exec.mode is %q in %s", mode, path),
				})
			}
			for _, it := range sliceAny(execCfg["safeBins"]) {
				if bin := strings.TrimSpace(asString(it)); bin != "" {
					out.Rules = append(out.Rules, buildSuggestedShellRule("allow", "tools.exec.safeBins="+bin, bin, true))
				}
			}
		}
	}
	if agents, ok := raw["agents"].(map[string]interface{}); ok {
		if defs, ok := agents["defaults"].(map[string]interface{}); ok {
			if sb, ok := defs["sandbox"].(map[string]interface{}); ok {
				if mode := asString(sb["mode"]); mode == "off" || mode == "non-main" {
					out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
						Category: "host_sandbox",
						Detail:   fmt.Sprintf("agents.defaults.sandbox.mode is %q in %s", mode, path),
					})
				}
			}
		}
	}
	return out
}

func parseOpenclawApprovalsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "openclaw", Scope: scope, Path: path}
	if defs, ok := raw["defaults"].(map[string]interface{}); ok {
		for _, it := range sliceAny(defs["allowlist"]) {
			if m, ok := it.(map[string]interface{}); ok {
				if pat := strings.TrimSpace(asString(m["pattern"])); pat != "" {
					out.Rules = append(out.Rules, buildSuggestedShellRule("allow", "allowlist:"+pat, pat, true))
				}
			}
		}
	}
	return out
}

func parsePiSettingsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "pi", Scope: scope, Path: path}
	if asString(raw["defaultProjectTrust"]) == "always" {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("defaultProjectTrust is always in %s", path),
		})
	}
	return out
}

func parseMirrorConfigFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "mirror", Scope: scope, Path: path}
	if asString(raw["approval_mode"]) == "auto" {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("approval_mode is auto in %s", path),
		})
	}
	return out
}

func parseMirrorApprovalsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, false, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "mirror", Scope: scope, Path: path}
	for _, it := range sliceAny(raw["approvals"]) {
		m, ok := it.(map[string]interface{})
		if !ok || asString(m["kind"]) != "argv_prefix" {
			continue
		}
		var toks []string
		for _, t := range sliceAny(m["argv"]) {
			if s := asString(t); s != "" {
				toks = append(toks, s)
			}
		}
		if len(toks) > 0 {
			joined := strings.Join(toks, " ")
			out.Rules = append(out.Rules, buildSuggestedShellRule("allow", "argv_prefix:"+joined, joined+" *", false))
		}
	}
	return out
}

func parseAmpSettingsFile(scope, path string) *DiscoveredHostFile {
	raw, ok := readJSONObjectFile(path, true, scope == "project")
	if !ok {
		return nil
	}
	out := &DiscoveredHostFile{Harness: "amp", Scope: scope, Path: path}
	if b, ok := raw["amp.dangerouslyAllowAll"].(bool); ok && b {
		out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
			Category: "host_permissions",
			Detail:   fmt.Sprintf("amp.dangerouslyAllowAll is true in %s", path),
		})
	}
	for _, it := range sliceAny(raw["amp.permissions"]) {
		m, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		tool := asString(m["tool"])
		if tool != "Bash" && tool != "shell_command" && tool != "async_shell_command" && tool != "*" {
			continue
		}
		act := asString(m["action"])
		if act == "reject" {
			act = "deny"
		}
		if act != "allow" && act != "ask" && act != "deny" {
			continue
		}
		matches, _ := m["matches"].(map[string]interface{})
		pat := "*"
		if matches != nil {
			if c := asString(matches["cmd"]); c != "" {
				pat = c
			} else if c := asString(matches["command"]); c != "" {
				pat = c
			}
		}
		if pat == "*" && act == "allow" {
			out.PolicyAlerts = append(out.PolicyAlerts, DiscoveredPolicyAlert{
				Category: "host_permissions",
				Detail:   fmt.Sprintf("amp.permissions allows all %s commands in %s", tool, path),
			})
		}
		out.Rules = append(out.Rules, buildSuggestedShellRule(act, fmt.Sprintf("amp.permissions[%s:%s]=%s", tool, pat, act), pat, true))
	}
	return out
}


