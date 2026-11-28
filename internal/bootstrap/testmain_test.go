package bootstrap_test

import (
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

// The file backend is the fixture most tests here bootstrap; it needs the
// explicit opt-in like any other unsupported backend.
func TestMain(m *testing.M) {
	if err := os.Setenv(backend.AllowUnsupportedEnv, "file"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
