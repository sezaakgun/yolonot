package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverHostPermissionsAcrossAllHarnessesAndScopes(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	origGOOS := discoverGOOS
	discoverGOOS = "darwin"
	defer func() { discoverGOOS = origGOOS }()

	sysRoot := os.Getenv("YOLONOT_SYSTEM_ROOT")
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(repo, "pkg", "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}

	// Active yolonot rules in repo: one duplicate and one conflict.
	if err := os.WriteFile(filepath.Join(repo, ".yolonot"), []byte(
		"allow-cmd go test *\n"+
			"deny-cmd npm publish *\n"+
			"sensitive .env\n",
	), 0600); err != nil {
		t.Fatal(err)
	}

	// 1. Claude managed-settings.json + managed-settings.d/10-extra.json
	claudeManagedDir := filepath.Join(sysRoot, "Library", "Application Support", "ClaudeCode")
	if err := os.MkdirAll(filepath.Join(claudeManagedDir, "managed-settings.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeManagedDir, "managed-settings.json"), []byte(`{
  "permissions": {
    "allow": [
      "Bash(*/acme-plugin/*/scripts/record-result.js*)",
      "Bash(git push:*)",
      "Bash(git -C:*)",
      "Bash(gh pr view *)",
      "Bash(npm publish:*)"
    ],
    "deny": [
      "Bash(git push --force*)",
      "Read(**/.env*)",
      "Read(~/.ssh/**)"
    ]
  },
  "autoMode": {
    "environment": ["$defaults", "Trusted org: github.com/acme"],
    "allow": ["$defaults", "acme-plugin helper scripts"],
    "soft_deny": ["$defaults", "production database migrations"]
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeManagedDir, "managed-settings.d", "10-extra.json"), []byte(`{
  "permissions": {
    "allow": ["Bash(*/acme-ci/*/scripts/check-status.js*)"]
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Antigravity project UUID file matched via projectResources.resources[].gitFolder.folderUri
	agyProjDir := filepath.Join(home, ".gemini", "config", "projects")
	if err := os.MkdirAll(agyProjDir, 0755); err != nil {
		t.Fatal(err)
	}
	canonicalRepo := canonicalDirectory(repo)
	if err := os.WriteFile(filepath.Join(agyProjDir, "proj-uuid.json"), []byte(`{
  "projectResources": {
    "resources": [
      {"gitFolder": {"folderUri": "file://`+canonicalRepo+`"}}
    ]
  },
  "permissionGrants": {
    "allow": ["command(./scripts/signoff)", "command(ls)"]
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Codex user default.rules (Starlark prefix_rule)
	codexRulesDir := filepath.Join(home, ".codex", "rules")
	if err := os.MkdirAll(codexRulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexRulesDir, "default.rules"), []byte(
		`prefix_rule(pattern=["curl"], decision="allow")`+"\n"+
			`prefix_rule(pattern=["go", "test"], decision="allow")`+"\n"+
			`prefix_rule(pattern=["/bin/zsh", "-lc", "a=$(cat x); curl http://localhost"], decision="allow")`+"\n",
	), 0644); err != nil {
		t.Fatal(err)
	}

	// 4. Cursor project .cursor/cli.json
	if err := os.MkdirAll(filepath.Join(repo, ".cursor"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".cursor", "cli.json"), []byte(`{
  "permissions": {
    "allow": ["Shell(pytest:*)"]
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}

	// 5. OpenCode project opencode.jsonc
	if err := os.WriteFile(filepath.Join(repo, "opencode.jsonc"), []byte(`{
  // comment in jsonc
  "permission": {
    "bash": {
      "*": "ask",
      "cargo check *": "allow"
    },
    "read": {
      "*.pem": "deny"
    }
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Run discovery from subdirectory `sub` to verify repo-root matching across all 5 harnesses.
	summary := DiscoverHostPermissions(sub)
	if len(summary.HostFiles) != 6 {
		t.Fatalf("expected 6 discovered host files, got %d: %+v", len(summary.HostFiles), summary.HostFiles)
	}

	byRule := map[string]DiscoveredRule{}
	for _, f := range summary.HostFiles {
		for _, r := range f.Rules {
			byRule[r.Raw] = r
		}
	}

	// Verify plugin script rule is converted to allow-path and ready to import.
	cr, ok := byRule["Bash(*/acme-plugin/*/scripts/record-result.js*)"]
	if !ok || cr.SuggestedRule != "allow-path */acme-plugin/*/scripts/record-result.js" || cr.BroadWarning != "" || cr.Overlap.Status != "none" {
		t.Fatalf("unexpected plugin rule classification: %+v", cr)
	}

	// Verify broad warnings on git push:*, git -C:*, and Codex curl prefix_rule.
	for _, raw := range []string{
		"Bash(git push:*)",
		"Bash(git -C:*)",
		`prefix_rule(pattern=["curl"], decision="allow")`,
	} {
		if r := byRule[raw]; r.BroadWarning == "" {
			t.Errorf("expected broad warning on %s, got %+v", raw, r)
		}
	}

	// Verify overlap classifications: fast_allow, exact_duplicate, conflict, and sensitive duplicate.
	if r := byRule["Bash(gh pr view *)"]; r.Overlap.Status != "covered_by_fast_allow" {
		t.Errorf("expected covered_by_fast_allow for gh pr view *, got %+v", r)
	}
	if r := byRule[`prefix_rule(pattern=["go", "test"], decision="allow")`]; r.Overlap.Status != "exact_duplicate" {
		t.Errorf("expected exact_duplicate for go test prefix_rule, got %+v", r)
	}
	if r := byRule["Bash(npm publish:*)"]; r.Overlap.Status != "conflict" {
		t.Errorf("expected conflict for npm publish:*, got %+v", r)
	}
	if r := byRule["Read(**/.env*)"]; r.SuggestedRule != "sensitive .env" || r.Overlap.Status != "exact_duplicate" {
		t.Errorf("expected sensitive .env exact_duplicate, got %+v", r)
	}
	if r := byRule["Read(~/.ssh/**)"]; r.SuggestedRule != "sensitive .ssh/" || r.Overlap.Status != "none" {
		t.Errorf("expected sensitive .ssh/ ready to import, got %+v", r)
	}
	if r := byRule[`permission.read["*.pem"]="deny"`]; r.SuggestedRule != "sensitive .pem" || r.Overlap.Status != "none" {
		t.Errorf("expected sensitive .pem from permission.read[*.pem]=\"deny\", got %+v", r)
	}

	// Verify complex inline shell is marked unconvertible.
	for raw, r := range byRule {
		if strings.Contains(raw, "a=$(cat x)") && r.UnconvertibleReason == "" {
			t.Errorf("expected UnconvertibleReason on complex inline shell %s, got %+v", raw, r)
		}
	}

	// Verify CLI `yolonot rules discover --json` and text output, plus `yolonot audit` and nudge.
	jsonOut := captureStdout(func() { cmdRulesDiscover([]string{"--json", "--cwd", sub}) })
	var decoded DiscoverSummary
	if err := json.Unmarshal([]byte(jsonOut), &decoded); err != nil || len(decoded.HostFiles) != 6 {
		t.Fatalf("rules discover --json failed (err=%v):\n%s", err, jsonOut)
	}

	textOut := captureStdout(func() { cmdRulesDiscover([]string{"--cwd", sub}) })
	for _, want := range []string{
		"[claude · managed]",
		"[antigravity · project]",
		"[codex · user]",
		"[cursor · project]",
		"[opencode · project]",
		"/yolonot sync host permissions",
	} {
		if !strings.Contains(textOut, want) {
			t.Errorf("rules discover text output missing %q:\n%s", want, textOut)
		}
	}

	// Verify `yolonot audit` catches broad rules in Claude managed-settings.json and Codex default.rules.
	checks := hostPermissionChecks(supportedHarnesses(), sub)
	joined := ""
	for _, c := range checks {
		joined += c.Harness + "/" + c.Name + ": " + c.Detail + "\n"
	}
	for _, want := range []string{"Bash(git push:*)", `prefix_rule(pattern=["curl"], decision="allow")`} {
		if !strings.Contains(joined, want) {
			t.Errorf("hostPermissionChecks missed %q:\n%s", want, joined)
		}
	}

	// Verify printHostPermissionsNudge outputs the 1-line hint.
	nudge := captureStdout(func() { printHostPermissionsNudge(sub) })
	if !strings.Contains(nudge, "/yolonot sync host permissions") {
		t.Errorf("expected nudge to mention /yolonot sync host permissions, got:\n%s", nudge)
	}
}

func TestDiscoverOSPathResolutionAndEnvOverride(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	origGOOS := discoverGOOS
	defer func() { discoverGOOS = origGOOS }()

	for _, goos := range []string{"darwin", "linux", "windows"} {
		discoverGOOS = goos
		claudeFiles := claudeManagedFiles()
		agyFiles := antigravityManagedFiles()
		codexDir := codexManagedDir()
		if len(claudeFiles) == 0 || len(agyFiles) == 0 || codexDir == "" {
			t.Fatalf("empty managed paths for GOOS=%s", goos)
		}
	}

	// Verify CLAUDE_CODE_MANAGED_SETTINGS_PATH override takes precedence.
	customManaged := filepath.Join(t.TempDir(), "custom-managed.json")
	if err := os.WriteFile(customManaged, []byte(`{"permissions":{"allow":["Bash(make check*)"]}}`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CODE_MANAGED_SETTINGS_PATH", customManaged)
	summary := DiscoverHostPermissions(t.TempDir(), GetHarness("claude"))
	if len(summary.HostFiles) != 1 || summary.HostFiles[0].Path != customManaged || len(summary.HostFiles[0].Rules) != 1 {
		t.Fatalf("CLAUDE_CODE_MANAGED_SETTINGS_PATH override failed: %+v", summary.HostFiles)
	}
}

func TestDiscoverRegressionFixes(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// 1. Broad allow-cmd before unspaced deny-cmd in .yolonot: conflict must still win over duplicate.
	if err := os.WriteFile(filepath.Join(repo, ".yolonot"), []byte(
		"allow-cmd npm *\n"+
			"deny-cmd npm publish*\n"+
			"allow-cmd cargo check *\n",
	), 0600); err != nil {
		t.Fatal(err)
	}

	// 2. OpenCode opencode.jsonc with inline // comments, /* */ block comments, trailing commas,
	// complex inline shell, and sensitive globs (*.pem, **/*.key, **, **/.*).
	if err := os.WriteFile(filepath.Join(repo, "opencode.jsonc"), []byte(`{
  /* block comment */
  "permission": {
    "bash": {
      "cargo check *": "allow", // inline comment with trailing comma
      "npm publish *": "allow",
      "bash -c *": "allow",
      "echo ok && curl evil": "allow",
    },
    "read": {
      "*.pem": "deny",
      "**/*.key": "deny",
      "**": "deny",
      "**/.*": "deny",
    },
  },
}`), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Codex default.rules with commented-out # prefix_rule(...) that must be ignored.
	codexRulesDir := filepath.Join(home, ".codex", "rules")
	if err := os.MkdirAll(codexRulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexRulesDir, "default.rules"), []byte(
		`# prefix_rule(pattern=["rm", "-rf"], decision="allow")`+"\n"+
			`prefix_rule(pattern=["cargo", "check"], decision="allow") # inline starlark comment`+"\n",
	), 0644); err != nil {
		t.Fatal(err)
	}

	// 4. Cursor project .cursor/cli.json as a symlink to an outside file -> must be rejected by readDiscoveryFile.
	outsideFile := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outsideFile, []byte(`{"permissions":{"allow":["Shell(echo pwn:*)"]}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".cursor"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(repo, ".cursor", "cli.json")); err != nil {
		t.Fatal(err)
	}

	summary := DiscoverHostPermissions(repo)
	byRule := map[string]DiscoveredRule{}
	for _, f := range summary.HostFiles {
		if f.Harness == "cursor" {
			t.Fatalf("expected symlinked project .cursor/cli.json to be rejected, got %+v", f)
		}
		for _, r := range f.Rules {
			byRule[r.Raw] = r
		}
	}

	// Commented-out Starlark rule must not be discovered.
	if _, found := byRule[`prefix_rule(pattern=["rm", "-rf"], decision="allow")`]; found {
		t.Errorf("commented-out Starlark prefix_rule should have been ignored")
	}
	// Active Starlark rule with inline comment must be discovered and marked exact_duplicate.
	if r, ok := byRule[`prefix_rule(pattern=["cargo", "check"], decision="allow")`]; !ok || r.Overlap.Status != "exact_duplicate" {
		t.Errorf("expected cargo check prefix_rule to be exact_duplicate, got %+v", r)
	}
	// Conflict check must beat earlier broad allow-cmd and match unspaced `deny-cmd npm publish*`.
	if r, ok := byRule[`permission.bash["npm publish *"]="allow"`]; !ok || r.Overlap.Status != "conflict" {
		t.Errorf("expected conflict on npm publish *, got %+v", r)
	}
	// Broad warning on interpreter/shell flag pattern `bash -c *`.
	if r, ok := byRule[`permission.bash["bash -c *"]="allow"`]; !ok || r.BroadWarning == "" {
		t.Errorf("expected BroadWarning on bash -c *, got %+v", r)
	}
	// Complex inline shell in OpenCode must get UnconvertibleReason.
	if r, ok := byRule[`permission.bash["echo ok && curl evil"]="allow"`]; !ok || r.UnconvertibleReason == "" {
		t.Errorf("expected UnconvertibleReason on OpenCode compound command, got %+v", r)
	}
	// normalizeSensitiveGlob: *.pem -> .pem, **/*.key -> .key, ** and **/.* -> skipped.
	if r, ok := byRule[`permission.read["*.pem"]="deny"`]; !ok || r.SuggestedRule != "sensitive .pem" {
		t.Errorf("expected sensitive .pem, got %+v", r)
	}
	if r, ok := byRule[`permission.read["**/*.key"]="deny"`]; !ok || r.SuggestedRule != "sensitive .key" {
		t.Errorf("expected sensitive .key, got %+v", r)
	}
	if _, found := byRule[`permission.read["**"]="deny"`]; found {
		t.Errorf("expected permission.read[**]=\"deny\" to be skipped")
	}
	if _, found := byRule[`permission.read["**/.*"]="deny"`]; found {
		t.Errorf("expected permission.read[**/.*]=\"deny\" to be skipped")
	}

	// 5. Verify printHostPermissionsNudge is silent when all rules are already synced/non-importable.
	if err := os.WriteFile(filepath.Join(repo, ".yolonot"), []byte(
		"allow-cmd npm *\n"+
			"deny-cmd npm publish*\n"+
			"allow-cmd cargo check *\n"+
			"sensitive .pem\n"+
			"sensitive .key\n",
	), 0600); err != nil {
		t.Fatal(err)
	}
	silentNudge := captureStdout(func() { printHostPermissionsNudge(repo) })
	if silentNudge != "" {
		t.Errorf("expected silent nudge when all host rules are synced/non-actionable, got: %q", silentNudge)
	}
}

func TestDiscoverExtendedHarnessesAndPayloadEdgeCases(t *testing.T) {
	home, _ := withFakeHome(t)
	repo := filepath.Join(home, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	// Qwen settings + Goose config + Amp settings + Muse approval-policy
	mustWrite := func(rel, content string) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(".qwen/settings.json", `{"approvalMode":"yolo","permissions":{"allow":["Bash(git status *)"]}}`)
	mustWrite(".config/goose/config.yaml", "GOOSE_MODEL: gpt-4o\n")
	mustWrite(".config/amp/settings.json", `{"amp.dangerouslyAllowAll":true,"amp.permissions":[{"tool":"Bash","action":"reject","matches":{"cmd":"rm -rf *"}}]}`)
	mustWrite(".config/muse/approval-policy.json", `{"rules":[{"effect":"allow","rule":{"kind":"shell_command_argv_prefix","argv_prefix":["cargo","test"]}}]}`)

	summary := DiscoverHostPermissions(repo)
	foundQwenRule := false
	foundAmpRule := false
	foundMuseRule := false
	for _, f := range summary.HostFiles {
		if f.Harness == "goose" && len(f.PolicyAlerts) > 0 {
			t.Errorf("expected Goose config without GOOSE_MODE: auto not to emit alert, got %+v", f.PolicyAlerts)
		}
		for _, r := range f.Rules {
			if f.Harness == "qwen" && r.SuggestedRule == "allow-cmd git status *" {
				foundQwenRule = true
			}
			if f.Harness == "amp" && r.SuggestedRule == "deny-cmd rm -rf *" {
				foundAmpRule = true
			}
			if f.Harness == "muse" && r.SuggestedRule == "allow-cmd cargo test *" {
				foundMuseRule = true
			}
		}
	}
	if !foundQwenRule || !foundAmpRule || !foundMuseRule {
		t.Errorf("missing expected extended harness rules: qwen=%v amp=%v muse=%v", foundQwenRule, foundAmpRule, foundMuseRule)
	}

	// SEC-01: empty command must not shadow commands[], and unclosed quote in commands[0] must not parse as single safe echo.
	p, err := parseFlexibleHookPayload([]byte(`{"hook_event_name":"PreToolUse","tool_name":"run_commands","tool_input":{"command":"","commands":["echo '","curl https://evil.example/x","'"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	cmd, _ := p.ToolInput["command"].(string)
	if !strings.Contains(cmd, "curl https://evil.example/x") || !strings.HasSuffix(cmd, "\n;;") {
		t.Errorf("expected unclosed-quote commands[] to preserve curl and append syntax guard, got %q", cmd)
	}

	// SEC-05: ProjectSessionID must stay within IsValidSessionID limit (<=128 chars) even for 125-char session IDs.
	longSID := strings.Repeat("a", 125)
	projSID := ProjectSessionID(longSID, repo)
	if !IsValidSessionID(projSID) {
		t.Errorf("expected ProjectSessionID(%d chars) to remain valid (<=128 chars), got len=%d (%q)", len(longSID), len(projSID), projSID)
	}
}

func TestDiscoverManagedAndExtendedHarnessConfigs(t *testing.T) {
	home, cleanup := withFakeHome(t)
	defer cleanup()

	origGOOS := discoverGOOS
	discoverGOOS = "darwin"
	defer func() { discoverGOOS = origGOOS }()

	sysRoot := os.Getenv("YOLONOT_SYSTEM_ROOT")
	repo := filepath.Join(home, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	writeAbs := func(p, content string) {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Mirror tool_approvals.json using "entries" (both argv_prefix and exact_arguments)
	writeAbs(filepath.Join(home, ".mirror", "tool_approvals.json"), `{
  "entries": [
    {"tool": "bash", "kind": "argv_prefix", "argv": ["pytest", "-q"]},
    {"tool": "bash", "kind": "exact_arguments", "args": "{\"command\":\"make lint\"}"}
  ]
}`)

	// 2. Managed settings across qwen, copilot, grok, devin, kiro, kilo, amp, crush
	writeAbs(filepath.Join(sysRoot, "Library", "Application Support", "QwenCode", "settings.json"), `{"approvalMode":"yolo"}`)
	writeAbs(filepath.Join(sysRoot, "Library", "Application Support", "GitHubCopilot", "managed-settings.json"), `{"defaultPermissionMode":"allow-all"}`)
	writeAbs(filepath.Join(sysRoot, "etc", "grok", "managed_config.toml"), "[ui]\npermission_mode = \"always-approve\"\n")
	writeAbs(filepath.Join(sysRoot, "Library", "Application Support", "Devin", "system.json"), `{"permissions":{"allow":["Exec(go vet *)"]}}`)
	writeAbs(filepath.Join(sysRoot, "Library", "Application Support", "Kiro", "managed-settings.json"), `{"policyPreset":["allow-all"]}`)
	writeAbs(filepath.Join(sysRoot, "Library", "Application Support", "kilo", "kilo.json"), `{"permission":{"bash":"allow"}}`)
	writeAbs(filepath.Join(sysRoot, "Library", "Application Support", "ampcode", "managed-settings.json"), `{"amp.dangerouslyAllowAll":true}`)
	writeAbs(filepath.Join(sysRoot, "etc", "crush", "crush.json"), `{"permissions":{"allowed_tools":["bash"]}}`)

	// 3. Crush .crush/crush.json & crushrc
	writeAbs(filepath.Join(repo, ".crush", "crush.json"), `{"options":{"disabled_tools":["bash"]}}`)
	writeAbs(filepath.Join(home, ".config", "crush", "crushrc"), "permissions allow bash\n")

	// 4. Kiro V3 permissions.yaml, sandbox.json, and V3 permissions.rules in agents/*.json
	//    (including non-shell tools that must NOT become allow-cmd rules, and wildcard "*")
	writeAbs(filepath.Join(home, ".kiro", "settings", "permissions.yaml"), "allow:\n  - \"npm run build\"\n")
	writeAbs(filepath.Join(home, ".kiro", "settings", "sandbox.json"), `{"enabled":false}`)
	writeAbs(filepath.Join(home, ".kiro", "agents", "v3.json"), `{
  "permissions": {
    "allow": ["fs_read", "@git", "execute_bash(cargo fmt *)"],
    "rules": [
      {"tool": "execute_bash", "action": "allow", "command": "cargo check"},
      {"tool": "shell", "action": "ask", "pattern": "*"}
    ]
  }
}`)

	// 5. Hermes profile config (including commented-out / unrelated mode keys that must not alert)
	writeAbs(filepath.Join(home, ".hermes", "profiles", "ci", "config.yaml"), "approvals:\n  unattended_mode: approve\n  command_allowlist:\n    - \"ruff check\"\n")
	writeAbs(filepath.Join(home, ".hermes", "config.yaml"), "# unattended_mode: approve\nvim_mode: false\n")

	// 6. OpenHands conversation base_state.json
	writeAbs(filepath.Join(home, ".openhands", "conversations", "conv-1", "base_state.json"), `{"confirmation_policy":{"kind":"NeverConfirm"}}`)

	// 7. Muse project .muse/settings.json custom profile
	writeAbs(filepath.Join(repo, ".muse", "settings.json"), `{
  "permissions": {
    "default_profile": "ci",
    "profiles": {
      "ci": {"approval": "allow_all", "filesystem": "unrestricted"}
    }
  }
}`)

	// 8. Antigravity ~/.gemini/antigravity-cli/settings.json and <repo>/.agents/settings.json
	writeAbs(filepath.Join(home, ".gemini", "antigravity-cli", "settings.json"), `{"permissionGrants":{"allow":["command(git diff)"]}}`)
	writeAbs(filepath.Join(repo, ".agents", "settings.json"), `{"permissionGrants":{"deny":["command(rm -rf /)"]}}`)

	summary := DiscoverHostPermissions(repo)
	byHarnessScope := map[string]bool{}
	bySuggested := map[string]bool{}
	for _, f := range summary.HostFiles {
		byHarnessScope[f.Harness+":"+f.Scope] = true
		for _, r := range f.Rules {
			bySuggested[f.Harness+":"+r.SuggestedRule] = true
		}
	}

	for _, wantHS := range []string{
		"qwen:managed",
		"copilot:managed",
		"grok:managed",
		"devin:managed",
		"kiro:managed",
		"kilo:managed",
		"amp:managed",
		"crush:managed",
		"crush:project",
		"crush:user",
		"kiro:user",
		"hermes:user",
		"openhands:user",
		"muse:project",
		"antigravity:user",
		"antigravity:project",
	} {
		if !byHarnessScope[wantHS] {
			t.Errorf("missing discovered host file for %s; got %v", wantHS, byHarnessScope)
		}
	}

	for _, wantRule := range []string{
		"mirror:allow-cmd pytest -q *",
		"mirror:allow-cmd make lint",
		"devin:allow-cmd go vet *",
		"kiro:allow-cmd npm run build",
		"kiro:allow-cmd cargo check *",
		"kiro:allow-cmd cargo fmt *",
		"kiro:ask-cmd *",
		"hermes:allow-cmd ruff check",
		"antigravity:allow-cmd git diff",
		"antigravity:deny-cmd rm -rf /",
	} {
		if !bySuggested[wantRule] {
			t.Errorf("missing discovered rule %s; got %v", wantRule, bySuggested)
		}
	}
	for _, unwanted := range []string{"kiro:allow-cmd fs_read", "kiro:allow-cmd @git", "kiro:ask-cmd * *"} {
		if bySuggested[unwanted] {
			t.Errorf("unexpected bogus rule %s in %v", unwanted, bySuggested)
		}
	}
	for _, f := range summary.HostFiles {
		if f.Harness == "hermes" && strings.HasSuffix(f.Path, filepath.Join(".hermes", "config.yaml")) && len(f.PolicyAlerts) > 0 {
			t.Errorf("commented-out or unrelated YAML keys in %s triggered false alerts: %+v", f.Path, f.PolicyAlerts)
		}
	}
}
