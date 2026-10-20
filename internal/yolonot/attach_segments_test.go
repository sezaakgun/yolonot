package yolonot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The incident shapes: a worktree reached through one literal cd, a gate
// script piped and chained, and a heredoc writing over a script.
func TestAttachProvenAcrossSegments(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, ".git"), 0755)
	wt := filepath.Join(repo, "wt")
	os.MkdirAll(filepath.Join(wt, ".local-ci", "checks"), 0755)
	os.WriteFile(filepath.Join(wt, ".local-ci", "run-gates.sh"), []byte("echo gates in worktree\n"), 0755)
	os.WriteFile(filepath.Join(wt, ".local-ci", "checks", "go-version.sh"), []byte("echo go version check\n"), 0755)
	os.WriteFile(filepath.Join(repo, ".local-ci", "run-gates.sh"), []byte("echo DECOY at session cwd\n"), 0755)
	os.MkdirAll(filepath.Join(repo, ".local-ci"), 0755)
	os.WriteFile(filepath.Join(repo, ".local-ci", "run-gates.sh"), []byte("echo DECOY at session cwd\n"), 0755)

	cases := map[string][]string{
		// leading literal cd, pipe and redirect after the script, a second run after `;`
		"cd wt && .local-ci/run-gates.sh --stage pre-commit 2>&1 | sed -n 5p; .local-ci/run-gates.sh --stage pre-push": {"echo gates in worktree", "Contents of the file this command executes: .local-ci/run-gates.sh"},
		// env assignment and a plain command before a script, no cd
		"GOTOOLCHAIN=local go version && sh wt/.local-ci/checks/go-version.sh 1.26": {"echo go version check"},
		// a cd that is not the first segment never rebases
		"GOTOOLCHAIN=local go version && cd wt && sh .local-ci/checks/go-version.sh 1.26": {"not provably"},
		// braces are not inert: nothing is proven, the note explains
		"{ cd wt && .local-ci/run-gates.sh; }": {"not provably"},
	}
	for cmd, wants := range cases {
		prompt := BuildAnalyzePrompt(cmd, repo)
		if strings.Contains(prompt, "DECOY") {
			t.Errorf("%q attached the session-cwd decoy", cmd)
		}
		for _, w := range wants {
			if !strings.Contains(prompt, w) {
				t.Errorf("%q: prompt lacks %q", cmd, w)
			}
		}
	}

	// A second cd, `||`, a pipe-terminated cd or a cwd builtin end the proof.
	for _, cmd := range []string{
		"cd wt && cd .local-ci && sh run-gates.sh",
		"cd wt || .local-ci/run-gates.sh",
		"cd wt | .local-ci/run-gates.sh",
		"cd wt & .local-ci/run-gates.sh",
		"source env.sh && .local-ci/run-gates.sh",
		"eval ls && .local-ci/run-gates.sh",
		"if cd wt; then .local-ci/run-gates.sh; fi",
		// the environment or an alias could steer a later cd
		"CDPATH=/tmp; cd wt && .local-ci/run-gates.sh",
		"CDPATH=/tmp cd wt && .local-ci/run-gates.sh",
		"HOME=/tmp; cd ~/wt && .local-ci/run-gates.sh",
		"shopt -s expand_aliases\nalias cd=:\ncd wt && .local-ci/run-gates.sh",
		"export CDPATH=/tmp && cd wt && .local-ci/run-gates.sh",
		// shell + flags and file-mutating segments before a script forfeit the proof
		"bash +x wt/.local-ci/run-gates.sh",
		"cp wt/.local-ci/checks/go-version.sh wt/.local-ci/run-gates.sh && wt/.local-ci/run-gates.sh",
		"python3 -m evil_mod && wt/.local-ci/run-gates.sh",
		"echo hi > wt/.local-ci/run-gates.sh && wt/.local-ci/run-gates.sh",
	} {
		if prompt := BuildAnalyzePrompt(cmd, repo); strings.Contains(prompt, "Contents of") {
			t.Errorf("%q must not attach anything, got:\n%s", cmd, prompt)
		}
	}
}

func TestAttachSkipsRedirectTargetAndHeredocBody(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "old.sh"), []byte("echo stale contents\n"), 0755)
	os.WriteFile(filepath.Join(dir, "evil.py"), []byte("print('DECOY')\n"), 0644)
	abs := filepath.Join(dir, "old.sh")
	for _, cmd := range []string{
		"cat > old.sh <<'EOF'\npython evil.py\nEOF",
		"cat > " + abs + " <<'EOF'\n#!/bin/sh\nEOF",
		"printf 'x' >> " + abs,
		"echo hi >" + abs + " && echo done",
		"echo hi &> " + abs,
		"echo hi >| " + abs,
	} {
		prompt := BuildAnalyzePrompt(cmd, dir)
		if strings.Contains(prompt, "stale contents") || strings.Contains(prompt, "DECOY") {
			t.Errorf("%q attached a redirect target or heredoc token:\n%s", cmd, prompt)
		}
	}
}

func TestAttachRelativeCdRefusedUnderCDPATH(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "wt"), 0755)
	os.WriteFile(filepath.Join(repo, "wt", "run.sh"), []byte("echo in wt\n"), 0755)
	t.Setenv("CDPATH", "/tmp")
	if prompt := BuildAnalyzePrompt("cd wt && ./run.sh", repo); strings.Contains(prompt, "echo in wt") {
		t.Error("a relative cd must not rebase while CDPATH is set")
	}
	if prompt := BuildAnalyzePrompt("cd "+filepath.Join(repo, "wt")+" && ./run.sh", repo); !strings.Contains(prompt, "echo in wt") {
		t.Error("an absolute cd is unaffected by CDPATH")
	}
}

func TestAttachLiteralCdExpandsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	wt := filepath.Join(home, "wt")
	os.MkdirAll(filepath.Join(wt, ".git"), 0755)
	os.WriteFile(filepath.Join(wt, "run.sh"), []byte("echo under home\n"), 0755)
	attachOutsideRoot = true
	t.Cleanup(func() { attachOutsideRoot = false })
	prompt := BuildAnalyzePrompt("cd ~/wt && ./run.sh", t.TempDir())
	if !strings.Contains(prompt, "echo under home") {
		t.Errorf("~ in a literal cd should expand:\n%s", prompt)
	}
	attachOutsideRoot = false
	if prompt := BuildAnalyzePrompt("cd ~/wt && ./run.sh", t.TempDir()); strings.Contains(prompt, "echo under home") {
		t.Error("the attach root is the session's; a cd elsewhere stays outside without attach_outside_root")
	}
}

func TestScriptHashCoversSegmentProvenScripts(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.sh"), []byte("echo a\n"), 0755)
	h1 := scriptHash("./a.sh && echo done", dir)
	if h1 == "" {
		t.Fatal("a proven script in a list should be cacheable")
	}
	os.WriteFile(filepath.Join(dir, "a.sh"), []byte("echo changed\n"), 0755)
	if scriptHash("./a.sh && echo done", dir) == h1 {
		t.Error("editing the attached script must change the cache key")
	}
}

func TestAttachTargetSpecificTaintHomeHeredocAndVars(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	repo := filepath.Join(home, "repo")
	os.MkdirAll(filepath.Join(repo, ".git"), 0755)
	os.MkdirAll(filepath.Join(repo, "scripts"), 0755)
	os.WriteFile(filepath.Join(repo, "scripts", "run.sh"), []byte("echo safe script body\n"), 0755)

	shouldAttach := []string{
		// 1a: metadata-only, read-only git, and unrelated file mutations/redirects
		"chmod +x ./scripts/run.sh && ./scripts/run.sh",
		"touch /tmp/marker && ./scripts/run.sh",
		"git status && ./scripts/run.sh",
		"git -C . diff --quiet && ./scripts/run.sh",
		"echo start > /tmp/build.log && ./scripts/run.sh",
		"cp /tmp/a.txt /tmp/b.txt && ./scripts/run.sh",
		"rm -f /tmp/out.log && ./scripts/run.sh",
		// 1b: ~ and $HOME in provenScriptToken
		"~/repo/scripts/run.sh",
		"bash ~/repo/scripts/run.sh",
		"sh $HOME/repo/scripts/run.sh",
		`bash "$HOME/repo/scripts/run.sh"`,
		// 1c: heredoc before script segment
		"cat <<'EOF' > /tmp/msg.txt\npython evil.py\nEOF\n./scripts/run.sh",
		// 1d: simple literal variable assignment across segments
		"D=scripts && sh $D/run.sh",
		`D=scripts; bash "$D/run.sh"`,
		"S=" + filepath.Join(repo, "scripts", "run.sh") + " && bash ${S}",
	}
	for _, cmd := range shouldAttach {
		prompt := BuildAnalyzePrompt(cmd, repo)
		if !strings.Contains(prompt, "echo safe script body") {
			t.Errorf("%q should attach scripts/run.sh, got:\n%s", cmd, prompt)
		}
	}

	// Tainted script must STILL be withheld when overwritten by cp/mv/rm or redirect.
	mustWithhold := []string{
		"cp /tmp/evil.sh ./scripts/run.sh && ./scripts/run.sh",
		"mv /tmp/evil.sh scripts/run.sh && ./scripts/run.sh",
		"rm -rf scripts && ./scripts/run.sh",
		"echo evil > scripts/run.sh && ./scripts/run.sh",
	}
	for _, cmd := range mustWithhold {
		prompt := BuildAnalyzePrompt(cmd, repo)
		if strings.Contains(prompt, "echo safe script body") {
			t.Errorf("%q must NOT attach tainted scripts/run.sh, got:\n%s", cmd, prompt)
		}
	}
}

func TestAttachWorktreeBoundary(t *testing.T) {
	tmp := t.TempDir()
	mainRepo := filepath.Join(tmp, "main")
	os.MkdirAll(filepath.Join(mainRepo, ".git", "worktrees", "wt1"), 0755)
	os.MkdirAll(filepath.Join(mainRepo, ".git", "worktrees", "wt2"), 0755)
	os.MkdirAll(filepath.Join(mainRepo, "scripts"), 0755)
	mainScript := filepath.Join(mainRepo, "scripts", "main-gate.sh")
	os.WriteFile(mainScript, []byte("echo main repo script\n"), 0755)

	wt1 := filepath.Join(tmp, "wt1")
	os.MkdirAll(wt1, 0755)
	os.WriteFile(filepath.Join(wt1, ".git"), []byte("gitdir: "+filepath.Join(mainRepo, ".git", "worktrees", "wt1")+"\n"), 0644)

	wt2 := filepath.Join(tmp, "wt2")
	os.MkdirAll(filepath.Join(wt2, "scripts"), 0755)
	os.WriteFile(filepath.Join(wt2, ".git"), []byte("gitdir: "+filepath.Join(mainRepo, ".git", "worktrees", "wt2")+"\n"), 0644)
	sibScript := filepath.Join(wt2, "scripts", "sib-gate.sh")
	os.WriteFile(sibScript, []byte("echo sibling worktree script\n"), 0755)

	other := filepath.Join(tmp, "unrelated")
	os.MkdirAll(other, 0755)
	otherScript := filepath.Join(other, "outside.sh")
	os.WriteFile(otherScript, []byte("echo outside script\n"), 0755)

	// From wt1, scripts in mainRepo and sibling wt2 are within the attach boundary.
	if prompt := BuildAnalyzePrompt("bash "+mainScript, wt1); !strings.Contains(prompt, "echo main repo script") {
		t.Errorf("worktree should attach main-repo script:\n%s", prompt)
	}
	if prompt := BuildAnalyzePrompt("bash "+sibScript, wt1); !strings.Contains(prompt, "echo sibling worktree script") {
		t.Errorf("worktree should attach sibling-worktree script:\n%s", prompt)
	}
	// Unrelated directory stays outside when attachOutsideRoot is false.
	if prompt := BuildAnalyzePrompt("bash "+otherScript, wt1); strings.Contains(prompt, "echo outside script") {
		t.Errorf("unrelated script outside repo family must be withheld:\n%s", prompt)
	}
}
