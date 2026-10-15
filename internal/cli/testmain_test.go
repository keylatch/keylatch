package cli_test

import (
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
)

// Some tests here open the file backend through the default config paths;
// the opt-in keeps them from moving a developer's real vault key into the
// OS keyring. Tests that are not about presence run with a human approving
// every request; the ones that are swap in their own with presencetest.
func TestMain(m *testing.M) {
	if err := os.Setenv(kek.InsecureFileKEKEnv, "1"); err != nil {
		panic(err)
	}
	presence.SetDefault(presencetest.Approver())
	os.Exit(m.Run())
}
