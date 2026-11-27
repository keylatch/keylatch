package audit_test

import (
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

// The file backend is the test fixture; it opens only with the explicit opt-in.
func TestMain(m *testing.M) {
	if err := os.Setenv(backend.AllowUnsupportedEnv, "file"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
