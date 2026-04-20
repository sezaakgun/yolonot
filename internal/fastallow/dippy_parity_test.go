package fastallow

// Ported from https://github.com/ldayton/Dippy (MIT). Each row in
// testdata/dippy_parity.jsonl is a verbatim test case from Dippy's
// tests/cli/test_*.py TESTS tables. `want` mirrors Dippy's boolean:
// true = allow, false = ask/fall-through.

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type dippyCase struct {
	Category string `json:"category"`
	Cmd      string `json:"cmd"`
	Want     bool   `json:"want"`
}

func loadDippyParityCases(t *testing.T) []dippyCase {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "dippy_parity.jsonl"))
	if err != nil {
		t.Fatalf("open testdata: %v", err)
	}
	defer f.Close()

	var cases []dippyCase
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var c dippyCase
		if err := json.Unmarshal(line, &c); err != nil {
			t.Fatalf("parse line: %v (%s)", err, string(line))
		}
		cases = append(cases, c)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return cases
}

// parityFallthroughOK enumerates Dippy cases we deliberately don't match.
// These fall through to the LLM classifier (safe default) rather than fast-
// allow. Each entry documents why we skip. Currently limited to Athena SQL
// analysis (Dippy implements via a 200-line SQL parser; out of scope for
// yolonot) and a handful of multiplex-flag edge cases where yolonot is
// strictly stricter than Dippy.
var parityFallthroughOK = map[string]bool{}

func init() {
	for _, cmd := range []string{
		"aws athena start-query-execution --query-string 'SELECT * FROM tbl' --work-group primary",
		"aws athena start-query-execution --query-string 'SELECT 1' --result-configuration OutputLocation=s3://bucket/",
		"aws athena start-query-execution --query-string 'select * from foo'",
		"aws athena start-query-execution --query-string 'SHOW DATABASES'",
		"aws athena start-query-execution --query-string 'SHOW TABLES'",
		"aws athena start-query-execution --query-string 'SHOW PARTITIONS tbl'",
		"aws athena start-query-execution --query-string 'DESCRIBE tbl'",
		"aws athena start-query-execution --query-string 'DESCRIBE FORMATTED tbl'",
		"aws athena start-query-execution --query-string 'EXPLAIN SELECT 1'",
		"aws athena start-query-execution --query-string 'EXPLAIN ANALYZE SELECT 1'",
		"aws athena start-query-execution --query-string 'WITH cte AS (SELECT 1) SELECT * FROM cte'",
		"aws athena start-query-execution --query-string '  WITH x AS (SELECT 1) SELECT * FROM x'",
		"aws athena start-query-execution --query-string '-- comment\nSELECT 1'",
		"aws athena start-query-execution --query-string '/* block */ SELECT 1'",
		"aws athena start-query-execution --query-string '  -- comment\n  /* block */  SELECT 1'",
		"aws athena start-query-execution --query-string=SELECT * FROM tbl --work-group primary",
		// git -c — Dippy approves, yolonot rejects. Rationale: `-c` can set
		// config keys that execute shell commands (alias.*=!…, core.editor,
		// core.pager, core.sshCommand, gpg.program, credential.helper,
		// diff/merge external). Dippy skips `-c key=value` and classifies
		// the action as if no override were present. yolonot refuses all
		// `-c` invocations and hands them to the LLM — strictly safer.
		"git -c core.editor=vim log",
		// docker --config, kubectl --kubeconfig, helm --kubeconfig/--kube-*,
		// aws --ca-bundle, npm --user/globalconfig — Dippy approves, yolonot
		// rejects. Same rationale as git -c: these flags repoint the tool
		// at an attacker-controllable config that can trigger shell
		// execution (docker credHelpers, kubeconfig exec plugins, malicious
		// .npmrc). yolonot refuses; LLM layer still gets a shot.
		"docker --config /path/to/config ps",
		// Additional multiplex-flag rejections (safer than Dippy):
		//   - aws --endpoint-url: attacker-server cred capture.
		//   - docker --host / -H / --context: remote daemon redirection.
		//   - docker --host tcp://evil is RCE-adjacent.
		"aws --endpoint-url http://localhost:4566 s3 ls",
		"docker --host tcp://localhost:2375 ps",
		"docker -H tcp://localhost:2375 ps",
		"docker --context mycontext ps",
		// `security` subcommands that read credentials from the macOS
		// Keychain — Dippy classifies these read-only, but `-g` / `-d`
		// prints passwords/keys in cleartext. yolonot intentionally
		// escalates every find-*/dump-* / get-identity-preference invocation
		// to the LLM/user layer. See security-audit F-20.
		"security show-keychain-info login.keychain",
		"security dump-keychain login.keychain",
		"security find-generic-password -s service",
		"security find-generic-password -a account -s service",
		"security find-internet-password -s server",
		"security find-key -t public",
		"security find-certificate -a",
		"security find-certificate -c CommonName",
		"security find-identity -v",
		"security find-identity -p codesigning",
		"security get-identity-preference -s https://example.com",
		"security dump-trust-settings",
		"security dump-trust-settings -d",
		// `bash -lc` / `bash -cl` / `zsh -lc` — Dippy allows, yolonot
		// rejects because -l makes the shell a login shell and sources
		// rc files before the -c string runs, giving the rc file an
		// execution vector. See security-audit F-06.
		"bash -lc 'ls'",
		"bash -cl 'ls'",
		"zsh -lc 'ls'",
	} {
		parityFallthroughOK[cmd] = true
	}
}

func TestDippyParity(t *testing.T) {
	for _, c := range loadDippyParityCases(t) {
		name := c.Category + "/" + c.Cmd
		t.Run(name, func(t *testing.T) {
			got, _ := IsLocallySafe(c.Cmd)
			if got != c.Want {
				if c.Want && parityFallthroughOK[c.Cmd] {
					t.Skipf("known fallthrough to LLM: %s", c.Cmd)
					return
				}
				verb := "reject"
				if c.Want {
					verb = "allow"
				}
				t.Errorf("IsLocallySafe(%q) = %v, want %v (%s)", c.Cmd, got, c.Want, verb)
			}
		})
	}
}
