package dispatch_test

import (
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

// Some tests here open the file backend through the default config paths;
// pointing them at a scratch directory keeps them away from a developer's
// real vault and vault key.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "keylatch-dispatch-test-*")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("KEYLATCH_CONFIG_DIR", dir); err != nil {
		panic(err)
	}
	if err := os.Setenv(backend.AllowUnsupportedEnv, "file,keychain"); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
