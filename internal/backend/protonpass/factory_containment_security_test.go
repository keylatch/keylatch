package protonpass_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	_ "github.com/keylatch/keylatch/internal/backend/protonpass" // trigger init()
)

// TestSecurityRegression_ProtonPassUnselectable verifies the
// proton-pass backend cannot be instantiated through the registered factory
// (the path every CLI/API/MCP entry point uses), regardless of config.
// Closes the "unsupported managers unavailable" containment claim; the
// cache-ownership defect itself is tracked separately in
// internal/backend/securitysuite.
func TestSecurityRegression_ProtonPassUnselectable(t *testing.T) {
	factory, ok := backend.Default.Get("proton-pass")
	if !ok {
		t.Fatal("proton-pass backend not registered; import side-effect missing")
	}

	_, err := factory(context.Background(), backend.BackendConfig{Name: "proton-pass"})
	if err == nil {
		t.Fatal("expected proton-pass factory to refuse instantiation, got nil error")
	}
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("expected ErrUnavailable, got: %v", err)
	}
}
