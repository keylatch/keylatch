package cli_test

import (
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
)

// Managed Claude Code settings point at an empty directory so a machine
// policy never changes doctor results. Some tests here open the file backend
// through the default config paths; pointing them at a scratch directory keeps
// them away from a developer's real vault and vault key. Tests that are not
// about presence or policy run with a human approving every request and a
// policy that allows everything; the ones that are swap in their own.
func TestMain(m *testing.M) {
	// A helper process a test launches inherits its parent's directory.
	dir := ""
	if os.Getenv("KEYLATCH_CONFIG_DIR") == "" {
		var err error
		if dir, err = os.MkdirTemp("", "keylatch-cli-test-*"); err != nil {
			panic(err)
		}
		if err := os.Setenv("KEYLATCH_CONFIG_DIR", dir); err != nil {
			panic(err)
		}
	}
	managed, err := os.MkdirTemp("", "managed-settings")
	if err != nil {
		panic(err)
	}
	doctor.OverrideManagedSettingsDir(managed)
	presence.SetDefault(presencetest.Approver())
	enforce.SetDefault(enforce.AllowAll())
	code := m.Run()
	_ = os.RemoveAll(managed)
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}
