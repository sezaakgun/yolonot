package yolonot

import (
	"os"
	"testing"
)

// Tests fake HOME; host config directories set by the caller's environment
// (a CI runner sets XDG_CONFIG_HOME) would point them at real files instead.
func TestMain(m *testing.M) {
	for _, name := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR"} {
		os.Unsetenv(name)
	}
	os.Exit(m.Run())
}
