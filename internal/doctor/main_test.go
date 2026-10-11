package doctor_test

import (
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/doctor"
)

// Managed Claude Code settings point at an empty directory so a machine
// policy never changes doctor results.
func TestMain(m *testing.M) {
	managed, err := os.MkdirTemp("", "managed-settings")
	if err != nil {
		panic(err)
	}
	doctor.OverrideManagedSettingsDir(managed)
	code := m.Run()
	_ = os.RemoveAll(managed)
	os.Exit(code)
}
