package cli_test

import (
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/kek"
)

// Some tests here open the file backend through the default config paths;
// the opt-in keeps them from moving a developer's real vault key into the
// OS keyring.
func TestMain(m *testing.M) {
	if err := os.Setenv(kek.InsecureFileKEKEnv, "1"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
