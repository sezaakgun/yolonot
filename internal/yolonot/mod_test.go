package yolonot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModRecordAndLookupReplaySameToolUse(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	modRun, modSessionID, modToolUseID = true, "sess-mod-1", "toolu_1"
	defer func() { modRun, modSessionID, modToolUseID = false, "", "" }()

	modRecord("ask", "rule", "rule *wget *")
	modAppend("sess-mod-1", modEntry{ID: "toolu_1", Decision: "allow", Layer: "human", Reason: "allowed once"})
	modAppend("sess-mod-1", modEntry{ID: "toolu_2", Decision: "deny", Layer: "rule"})

	got := modLookup("sess-mod-1", "toolu_1")
	if got == nil || got.Decision != "allow" || got.Layer != "human" {
		t.Fatalf("last entry for toolu_1 should win: %+v", got)
	}
	if modLookup("sess-mod-1", "toolu_9") != nil || modLookup("sess-mod-1", "") != nil {
		t.Fatal("unknown or empty tool_use_id must not match")
	}

	modRun = false
	modRecord("allow", "fast_allow", "")
	if n := len(ReadLines("sess-mod-1", "mod")); n != 3 {
		t.Fatalf("classic (non-mod) runs must not record; got %d lines", n)
	}
}

func TestDropLineRemovesEveryCopy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	AppendLine("sess-drop", "asked", "wget x")
	AppendLine("sess-drop", "asked", "ls")
	AppendLine("sess-drop", "asked", "wget x")
	if !dropLine("sess-drop", "asked", "wget x") {
		t.Fatal("expected a drop")
	}
	if lines := ReadLines("sess-drop", "asked"); len(lines) != 1 || lines[0] != "ls" {
		t.Fatalf("got %q", lines)
	}
	if dropLine("sess-drop", "asked", "wget x") {
		t.Fatal("second drop must report nothing to do")
	}
}

func TestDropLineOrVariantMatchesWrappedForms(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	w := SessionWrappers()
	if len(w) == 0 {
		t.Skip("no wrappers registered")
	}
	AppendLine("sess-var", "once", "ls -la")
	if !dropLineOrVariant("sess-var", "once", w[0]+" ls -la") {
		t.Fatal("wrapped PostToolUse command must consume a plain once line")
	}
	AppendLine("sess-var", "once", w[0]+" ls -la")
	if !dropLineOrVariant("sess-var", "once", "ls -la") {
		t.Fatal("plain command must consume a wrapped once line")
	}
	if dropLineOrVariant("sess-var", "once", "ls -la") {
		t.Fatal("nothing left to drop")
	}
}

func runModResolve(t *testing.T, r modResolve) {
	t.Helper()
	b, _ := json.Marshal(r)
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	f.Write(b)
	f.Seek(0, 0)
	old := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = old }()
	cmdMod([]string{"resolve"})
}

func TestModResolveVerdicts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sid, cwd, cmd := "sess-res", t.TempDir(), "wget -q https://example.com"
	proj := ProjectSessionID(sid, cwd)
	AppendLine(proj, "asked", cmd)

	runModResolve(t, modResolve{SessionID: sid, ToolUseID: "t1", Cwd: cwd, Command: cmd, Verdict: "allow-once"})
	if ContainsLine(proj, "asked", cmd) {
		t.Fatal("allow-once must take the command off the asked list")
	}
	if !ContainsLine(proj, "once", cmd) {
		t.Fatal("allow-once must leave a once marker for PostToolUse")
	}
	if e := modLookup(sid, "t1"); e == nil || e.Decision != "allow" || e.Layer != "human" {
		t.Fatalf("allow-once entry: %+v", e)
	}

	runModResolve(t, modResolve{SessionID: sid, ToolUseID: "t2", Cwd: cwd, Command: cmd, Verdict: "deny"})
	if !ContainsLine(proj, "denied", cmd) {
		t.Fatal("deny must add the command to the denied list")
	}
	if e := modLookup(sid, "t2"); e == nil || e.Decision != "deny" {
		t.Fatalf("deny entry: %+v", e)
	}

	runModResolve(t, modResolve{SessionID: sid, ToolUseID: "t3", Cwd: cwd, Command: cmd, Verdict: "allow-session"})
	if e := modLookup(sid, "t3"); e == nil || e.Decision != "allow" {
		t.Fatalf("allow-session entry: %+v", e)
	}
}

func TestModInstallAndUninstallKeepOtherPluginDirs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, ".claude"), 0755)
	os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{"env":{"CLAUDE_CODE_PLUGIN_DIRS":"/opt/other"}}`), 0644)

	dir, err := modInstall("/usr/local/bin/yolonot")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := os.ReadFile(filepath.Join(dir, "hooks", "register.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reg), `const BIN = "/usr/local/bin/yolonot"`) || strings.Contains(string(reg), "__YOLONOT_") {
		t.Fatal("register.tsx must carry the binary path and no placeholder")
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude-plugin", "plugin.json")); err != nil {
		t.Fatal(err)
	}
	env := loadSettings()["env"].(map[string]interface{})
	if env[pluginDirsKey] != "/opt/other:"+dir {
		t.Fatalf("plugin dirs: %v", env[pluginDirsKey])
	}
	if _, err := modInstall("/usr/local/bin/yolonot"); err != nil {
		t.Fatal(err)
	}
	if env := loadSettings()["env"].(map[string]interface{}); env[pluginDirsKey] != "/opt/other:"+dir {
		t.Fatalf("second install must not duplicate the dir: %v", env[pluginDirsKey])
	}

	modUninstall()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("mod dir must be removed")
	}
	if env := loadSettings()["env"].(map[string]interface{}); env[pluginDirsKey] != "/opt/other" {
		t.Fatalf("other plugin dirs must survive: %v", env[pluginDirsKey])
	}
}

func TestModInstallQuotesBinaryPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	os.MkdirAll(filepath.Join(home, ".claude"), 0755)
	bin := `/Users/o'neil/My Tools\bin/yolonot`
	dir, err := modInstall(bin)
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := os.ReadFile(filepath.Join(dir, "hooks", "register.tsx"))
	quoted, _ := json.Marshal(bin)
	if !strings.Contains(string(reg), "const BIN = "+string(quoted)) {
		t.Fatalf("binary path not quoted as a string literal:\n%s", reg)
	}
}
