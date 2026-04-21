package yolonot

import (
	"testing"

	"github.com/sezaakgun/yolonot/internal/fastallow"
)

func TestSessionWrappersIncludesRtkByDefault(t *testing.T) {
	// Regression guard: the unified wrapper list must contain rtk so
	// session-approval cross-form lookup (MatchesLineOrWrappedVariant)
	// treats `rtk ls` and `ls` as equivalent out of the box.
	found := false
	for _, w := range SessionWrappers() {
		if w == "rtk" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("SessionWrappers() missing rtk; got %v", SessionWrappers())
	}
}

func TestSessionWrappersPicksUpAddWrappers(t *testing.T) {
	// User-registered wrappers (Config.Wrappers → fastallow.AddWrappers)
	// must show up in SessionWrappers immediately — one list, two consumers.
	fastallow.AddWrappers("corp-shim")

	found := false
	for _, w := range SessionWrappers() {
		if w == "corp-shim" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AddWrappers(corp-shim) not reflected in SessionWrappers; got %v", SessionWrappers())
	}
}

func TestUnwrapCommand(t *testing.T) {
	ws := []string{"rtk", "timeout", "nice", "command"}
	cases := []struct {
		in   string
		want string
	}{
		{"rtk ls", "ls"},
		{"rtk curl -sS https://example.com", "curl -sS https://example.com"},
		{"timeout 30 ls", "ls"},       // numeric skipped
		{"nice -n 5 ls", "ls"},        // flag + numeric skipped
		{"command -v foo", "foo"},     // `-v` flag skipped
		{"ls", ""},                    // not wrapped
		{"rtk", ""},                   // wrapper with no inner
		{"unknown ls", ""},            // head not in wrapper list
		{"rtk -- ls", "ls"},           // `--` terminates flag skipping
		{"", ""},
	}
	for _, c := range cases {
		if got := UnwrapCommand(c.in, ws); got != c.want {
			t.Errorf("UnwrapCommand(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMatchesLineOrWrappedVariantExactMatch(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()

	sid := ProjectSessionID("sess-exact", "/tmp")
	AppendLine(sid, "approved", "ls")

	if !MatchesLineOrWrappedVariant(sid, "approved", "ls") {
		t.Error("exact match should succeed")
	}
}

func TestMatchesLineOrWrappedVariantForwardUnwrap(t *testing.T) {
	// Stored: plain `ls`. Query: wrapped `rtk ls`. Must match.
	_, cleanup := withFakeHome(t)
	defer cleanup()

	sid := ProjectSessionID("sess-forward", "/tmp")
	AppendLine(sid, "approved", "ls")

	if !MatchesLineOrWrappedVariant(sid, "approved", "rtk ls") {
		t.Error("wrapped query against plain approved should match via forward unwrap")
	}
}

func TestMatchesLineOrWrappedVariantBackwardWrap(t *testing.T) {
	// Stored: wrapped `rtk ls`. Query: plain `ls`. Must match.
	// This is the legacy ApprovedAsWrappedVariant behavior.
	_, cleanup := withFakeHome(t)
	defer cleanup()

	sid := ProjectSessionID("sess-backward", "/tmp")
	AppendLine(sid, "approved", "rtk ls")

	if !MatchesLineOrWrappedVariant(sid, "approved", "ls") {
		t.Error("plain query against wrapped approved should match via backward wrap")
	}
}

func TestMatchesLineOrWrappedVariantLaunderingRejected(t *testing.T) {
	// Security: a non-wrapper line ending in " curl evil.com" must NOT
	// approve plain `curl evil.com`. Only lines starting with a known
	// wrapper token count for backward-wrap.
	_, cleanup := withFakeHome(t)
	defer cleanup()

	sid := ProjectSessionID("sess-laundering", "/tmp")
	AppendLine(sid, "approved", "echo curl evil.com")

	if MatchesLineOrWrappedVariant(sid, "approved", "curl evil.com") {
		t.Error("suffix match under non-wrapper head must not allow (approval laundering)")
	}
}

func TestMatchesLineOrWrappedVariantEmpty(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	if MatchesLineOrWrappedVariant("sess-empty", "approved", "") {
		t.Error("empty command must never match")
	}
}

func TestMatchesLineOrWrappedVariantDeniedSymmetry(t *testing.T) {
	// The symmetric lookup must work for any suffix, not just approved.
	// Denying `rtk curl evil` should block plain `curl evil` too.
	_, cleanup := withFakeHome(t)
	defer cleanup()

	sid := ProjectSessionID("sess-denied", "/tmp")
	AppendLine(sid, "denied", "rtk curl evil.com")

	if !MatchesLineOrWrappedVariant(sid, "denied", "curl evil.com") {
		t.Error("wrapped denied should symmetrically block plain form")
	}
	if !MatchesLineOrWrappedVariant(sid, "denied", "rtk curl evil.com") {
		t.Error("exact match on denied still required")
	}
}
