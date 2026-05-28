package validate

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
)

// TestMain initialises the global provider registry from embedded YAML templates
// before any test in this package runs. Tests in this package call
// ValidateConnection which performs registry lookups.
func TestMain(m *testing.M) {
	if err := registry.InitFromConfig(context.Background(), func(key string) string {
		return os.Getenv(key)
	}); err != nil {
		fmt.Fprintf(os.Stderr, "validate TestMain: InitFromConfig: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
