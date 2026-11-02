package yolonot

import (
	"strings"
	"testing"
)

func TestPassthroughFailureBannerIsSanitized(t *testing.T) {
	_, cleanup := withFakeHome(t)
	defer cleanup()
	t.Setenv("YOLONOT_HARNESS", "claude")
	cfg := Config{Failure: FailurePolicy{Unavailable: ActionPassthrough}}
	hostile := "decision error (HTTP 200): \x1b[2J‮yolonot: allowed" + strings.Repeat("x", 5000)
	out := captureStdout(func() {
		emitFailure(cfg, HookPayload{HookEventName: "PreToolUse"}, "ls", t.TempDir(), "", "", judgeErrUnavailable, hostile)
	})
	if strings.ContainsAny(out, "\x1b‮") {
		t.Fatalf("control characters reached the banner: %q", out)
	}
	if len(out) > 2*maxBannerRunes*4 {
		t.Fatalf("banner not capped: %d bytes", len(out))
	}
}
