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
