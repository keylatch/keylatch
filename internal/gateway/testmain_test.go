package gateway_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/registry"
)

func TestMain(m *testing.M) {
	if err := registry.InitFromConfig(context.Background(), func(key string) string {
		return os.Getenv(key)
	}); err != nil {
		fmt.Fprintf(os.Stderr, "gateway TestMain: InitFromConfig: %v\n", err)
		os.Exit(1)
	}
	// Tests that are not about policy run without one; with none configured
	// the real default denies every request. Tests of policy pass a
	// PolicyPath or their own Enforcer.
	enforce.SetDefault(enforce.AllowAll())
	os.Exit(m.Run())
}
