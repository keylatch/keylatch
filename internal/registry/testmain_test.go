package registry

import (
	"context"
	"fmt"
	"os"
	"testing"
)

// TestMain initialises the global registry from embedded YAML templates before
// any test in this package runs. Without this, tests that call List() / Get()
// would see an empty catalog after providers_core_v1.go was deleted.
func TestMain(m *testing.M) {
	if err := InitFromConfig(context.Background(), func(key string) string {
		return os.Getenv(key)
	}); err != nil {
		fmt.Fprintf(os.Stderr, "registry TestMain: InitFromConfig: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
