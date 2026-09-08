package opconnect_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	_ "github.com/keylatch/keylatch/internal/backend/opconnect" // trigger init()
)

// TestSecurityRegression_F44_ConnectUnselectableInM1 verifies the op-connect
// backend cannot be instantiated through the registered factory (the path
// every CLI/API/MCP entry point uses), so the duplicate-creating write path
// (F44) is unreachable in M1. The upsert defect itself is tracked
// separately by TestSecurityRegression_F44_ConnectUpsert (securitysuite).
func TestSecurityRegression_F44_ConnectUnselectableInM1(t *testing.T) {
	factory, ok := backend.Default.Get("op-connect")
	if !ok {
		t.Fatal("op-connect backend not registered; import side-effect missing")
	}

	_, err := factory(context.Background(), backend.BackendConfig{Name: "op-connect"})
	if err == nil {
		t.Fatal("expected op-connect factory to refuse instantiation in M1, got nil error")
	}
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("expected ErrUnavailable, got: %v", err)
	}
}
