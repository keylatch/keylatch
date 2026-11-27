package keeper_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	_ "github.com/keylatch/keylatch/internal/backend/keeper" // trigger init()
	"github.com/keylatch/keylatch/internal/config"
)

// TestSecurityRegression_KeeperUnselectable verifies the keeper backend cannot be opened
// through dispatch (the path every CLI/API/MCP entry point uses) without the
// explicit opt-in, regardless of config.
func TestSecurityRegression_KeeperUnselectable(t *testing.T) {
	if _, ok := backend.Default.Get("keeper"); !ok {
		t.Fatal("keeper backend not registered; import side-effect missing")
	}

	t.Setenv(backend.AllowUnsupportedEnv, "keeper") // naming it must not enable it
	_, err := dispatch.Open(context.Background(), config.Config{Backend: "keeper"}, func(string) string { return "" })
	if !errors.Is(err, backend.ErrUnsupportedBackend) {
		t.Errorf("expected ErrUnsupportedBackend, got: %v", err)
	}
}
