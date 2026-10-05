package opconnect_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	_ "github.com/keylatch/keylatch/internal/backend/opconnect" // trigger init()
)

// TestSecurityRegression_ConnectUnselectable verifies the op-connect
// backend cannot be instantiated through the registered factory (the path
// every CLI/API/MCP entry point uses), so the duplicate-creating write path
// is unreachable. The upsert defect itself is tracked
// separately by TestSecurityRegression_ConnectUpsert (securitysuite).
func TestSecurityRegression_ConnectUnselectable(t *testing.T) {
	factory, ok := backend.Default.Get("op-connect")
	if !ok {
		t.Fatal("op-connect backend not registered; import side-effect missing")
	}

	_, err := factory(context.Background(), backend.BackendConfig{Name: "op-connect"})
	if err == nil {
		t.Fatal("expected op-connect factory to refuse instantiation, got nil error")
	}
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("expected ErrUnavailable, got: %v", err)
	}
}
