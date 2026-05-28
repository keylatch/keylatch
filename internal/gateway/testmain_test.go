package gateway_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
)

func TestMain(m *testing.M) {
	if err := registry.InitFromConfig(context.Background(), func(key string) string {
		return os.Getenv(key)
	}); err != nil {
		fmt.Fprintf(os.Stderr, "gateway TestMain: InitFromConfig: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
