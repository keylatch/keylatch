package cli_test

import (
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/doctor"
)

// Managed Claude Code settings point at an empty directory so a machine
// policy never changes doctor results. Some tests here open the file backend through the default config paths;
// the opt-in keeps them from moving a developer's real vault key into the
// OS keyring.
func TestMain(m *testing.M) {
	if err := os.Setenv(kek.InsecureFileKEKEnv, "1"); err != nil {
		panic(err)
	}
	managed, err := os.MkdirTemp("", "managed-settings")
	if err != nil {
		panic(err)
	}
	doctor.OverrideManagedSettingsDir(managed)
	code := m.Run()
	_ = os.RemoveAll(managed)
	os.Exit(code)
}
