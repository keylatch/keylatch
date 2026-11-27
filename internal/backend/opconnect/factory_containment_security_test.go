package opconnect_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	_ "github.com/keylatch/keylatch/internal/backend/opconnect" // trigger init()
	"github.com/keylatch/keylatch/internal/config"
)

// TestSecurityRegression_ConnectUnselectable verifies the op-connect backend cannot be opened
// through dispatch (the path every CLI/API/MCP entry point uses) without the
// explicit opt-in, regardless of config.
func TestSecurityRegression_ConnectUnselectable(t *testing.T) {
	if _, ok := backend.Default.Get("op-connect"); !ok {
		t.Fatal("op-connect backend not registered; import side-effect missing")
	}

	_, err := dispatch.Open(context.Background(), config.Config{Backend: "op-connect"}, func(string) string { return "" })
	if !errors.Is(err, backend.ErrUnsupportedBackend) {
		t.Errorf("expected ErrUnsupportedBackend, got: %v", err)
	}
}
