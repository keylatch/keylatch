package protonpass_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	_ "github.com/keylatch/keylatch/internal/backend/protonpass" // trigger init()
	"github.com/keylatch/keylatch/internal/config"
)

// TestSecurityRegression_ProtonPassUnselectable verifies the proton-pass backend cannot be opened
// through dispatch (the path every CLI/API/MCP entry point uses) without the
// explicit opt-in, regardless of config.
func TestSecurityRegression_ProtonPassUnselectable(t *testing.T) {
	if _, ok := backend.Default.Get("proton-pass"); !ok {
		t.Fatal("proton-pass backend not registered; import side-effect missing")
	}

	_, err := dispatch.Open(context.Background(), config.Config{Backend: "proton-pass"}, func(string) string { return "" })
	if !errors.Is(err, backend.ErrUnsupportedBackend) {
		t.Errorf("expected ErrUnsupportedBackend, got: %v", err)
	}
}
