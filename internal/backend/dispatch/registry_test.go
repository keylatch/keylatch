package dispatch_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
)

// TestSelect_UnknownBackend_KnownList verifies that ErrUnknownBackend includes
// a non-empty Known list after the four built-in backends are registered.
// (backends_test.go imports internal/backend/all to populate the registry.)
func TestSelect_UnknownBackend_KnownList(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := config.Default()
	cfg.Backend = "nonexistent-backend"

	_, err := dispatch.Select(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for unregistered backend, got nil")
	}

	var unknownErr dispatch.ErrUnknownBackend
	if !errors.As(err, &unknownErr) {
		t.Fatalf("expected ErrUnknownBackend, got %T: %v", err, err)
	}

	if len(unknownErr.Known) == 0 {
		t.Errorf("ErrUnknownBackend.Known is empty; expected registered backend names (file, keychain, op, bw)")
	}

	// Verify at least "file" is in the Known list (always registered).
	hasFile := false
	for _, k := range unknownErr.Known {
		if k == "file" {
			hasFile = true
			break
		}
	}
	if !hasFile {
		t.Errorf("ErrUnknownBackend.Known %v does not contain %q", unknownErr.Known, "file")
	}
}
