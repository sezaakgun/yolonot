package yolonot

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPendingAskNeverInfersHumanDenial(t *testing.T) {
	home := securityHookHome(t)
	cwd, command := t.TempDir(), "touch pending-approval.marker"
	writeGlobalRules(t, home, "ask-cmd touch *\n")
	pre := makePrePayload("pending-approval", command, cwd)
	for _, id := range []string{"first", "first", "second", ""} {
		pre.ToolUseID = id
		if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != "ask" {
			t.Fatalf("tool %q: got %s, want ask", id, got)
		}
	}
	if ContainsLine(ProjectSessionID(pre.SessionID, cwd), "denied", command) {
		t.Fatal("unanswered ask fabricated a session rejection")
	}
	if labels := humanLabelEntries(t); len(labels) != 0 {
		t.Fatalf("unanswered ask fabricated human labels: %+v", labels)
	}
}

func TestAbsoluteNativeExecutableModGrant(t *testing.T) {
	binary, err := exec.LookPath("touch")
	if err != nil {
		t.Skip("touch unavailable")
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, verdict := range []string{"allow-once", "allow-session"} {
		t.Run(verdict, func(t *testing.T) {
			home := securityHookHome(t)
			cwd := t.TempDir()
			command := binary + " " + filepath.Join(cwd, "ASK-MOD-ABS.marker")
			writeGlobalRules(t, home, "ask-cmd "+binary+" *\n")
			pre := makePrePayload("absolute-native-grant", command, cwd)
			pre.ToolUseID = "original"
			t.Setenv("YOLONOT_MOD", "1")
			if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != "ask" {
				t.Fatal(got)
			}
			runModResolve(t, modResolve{SessionID: pre.SessionID, ToolUseID: pre.ToolUseID, Command: command, Cwd: cwd, Verdict: verdict})
			t.Setenv("YOLONOT_MOD", "")
			for i := 0; i < 2; i++ {
				if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != "allow" {
					t.Fatalf("classic callback %d=%s, want allow", i, got)
				}
			}
			post := pre
			post.HookEventName = "PostToolUse"
			for i := 0; i < 2; i++ {
				runHookWithStruct(t, post)
			}
			project := ProjectSessionID(pre.SessionID, cwd)
			if ContainsLine(project, "denied", command) {
				t.Fatal("human allow became a denial")
			}
			pre.ToolUseID = "next"
			want := "ask"
			if verdict == "allow-session" {
				want = "allow"
			}
			if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != want {
				t.Fatalf("next call=%s, want %s", got, want)
			}
		})
	}
}

func copyNativeFixture(t *testing.T, dst string) {
	t.Helper()
	src, err := exec.LookPath("touch")
	if err != nil {
		t.Skip("touch unavailable")
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0755); err != nil {
		t.Fatal(err)
	}
}

func TestNativeExecutableApprovalInvalidation(t *testing.T) {
	for _, change := range []string{"content", "symlink", "to-script", "removed", "not-executable"} {
		t.Run(change, func(t *testing.T) {
			securityHookHome(t)
			outside := t.TempDir()
			target := filepath.Join(outside, "native")
			copyNativeFixture(t, target)
			path := target
			if change == "symlink" {
				path = filepath.Join(outside, "link")
				if err := os.Symlink(target, path); err != nil {
					t.Skip(err)
				}
			}
			cwd := t.TempDir()
			command := path + " marker"
			binding, hashes := modCommandSnapshot(command, cwd)
			if binding == "" {
				t.Fatal("native executable has no binding")
			}
			saveApprovedSnapshot("native-snapshot", command, hashes)
			if !sessionContentOK("native-snapshot", command, cwd) {
				t.Fatal("unchanged native snapshot rejected")
			}
			switch change {
			case "content":
				b, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				b[len(b)-1] ^= 1
				if err := os.WriteFile(target, b, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				other := filepath.Join(outside, "other")
				copyNativeFixture(t, other)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, path); err != nil {
					t.Fatal(err)
				}
			case "to-script":
				if err := os.WriteFile(target, []byte("#!/bin/sh\necho replaced\n"), 0755); err != nil {
					t.Fatal(err)
				}
			case "removed":
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			case "not-executable":
				if err := os.Chmod(target, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if got := modCommandBinding(command, cwd); got == binding {
				t.Fatal("changed executable retained its binding")
			}
			if sessionContentOK("native-snapshot", command, cwd) {
				t.Fatal("changed executable retained session approval")
			}
		})
	}
}

func TestNativeExecutableDoesNotMakeWithheldScriptReplayable(t *testing.T) {
	securityHookHome(t)
	outside := t.TempDir()
	native := filepath.Join(outside, "native")
	copyNativeFixture(t, native)
	script := filepath.Join(outside, "hidden.sh")
	if err := os.WriteFile(script, []byte("echo hidden\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	for _, command := range []string{script, native + " " + script} {
		if binding := modCommandBinding(command, cwd); binding != "" {
			t.Fatalf("withheld script became replayable: %s", command)
		}
	}
}

func TestCompletedModCallCannotReuseOneTimeGrant(t *testing.T) {
	home := securityHookHome(t)
	cwd := t.TempDir()
	command := "touch completion.marker"
	writeGlobalRules(t, home, "ask-cmd touch *\n")
	pre := makePrePayload("completed-mod", command, cwd)
	pre.ToolUseID = "one-call"
	t.Setenv("YOLONOT_MOD", "1")
	runHookWithStruct(t, pre)
	runModResolve(t, modResolve{SessionID: pre.SessionID, ToolUseID: pre.ToolUseID, Command: command, Cwd: cwd, Verdict: "allow-once"})
	t.Setenv("YOLONOT_MOD", "")
	if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != "allow" {
		t.Fatal(got)
	}
	post := pre
	post.HookEventName = "PostToolUse"
	runHookWithStruct(t, post)
	if got := parseResponse(t, runHookWithStruct(t, pre)).HookSpecificOutput.PermissionDecision; got != "ask" {
		t.Fatalf("completed tool ID replayed: %s", got)
	}
}

func TestNativeExecutableApprovalInvalidationThroughWrapper(t *testing.T) {
	securityHookHome(t)
	target := filepath.Join(t.TempDir(), "native")
	copyNativeFixture(t, target)
	cwd := t.TempDir()
	plain := target + " marker"
	wrapped := "timeout 5 " + plain
	for _, approved := range []string{plain, wrapped} {
		_, hashes := modCommandSnapshot(approved, cwd)
		saveApprovedSnapshot("native-wrapped", approved, hashes)
	}
	if !sessionContentOK("native-wrapped", wrapped, cwd) {
		t.Fatal("unchanged wrapped native snapshot rejected")
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err := os.WriteFile(target, b, 0755); err != nil {
		t.Fatal(err)
	}
	if sessionContentOK("native-wrapped", wrapped, cwd) {
		t.Fatal("changed executable retained approval through a wrapper")
	}
}
