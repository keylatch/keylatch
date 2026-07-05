package file_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	_ "github.com/keylatch/keylatch/internal/backend/file" // trigger init()
)

func TestFileFactory_UnknownKey_ReturnsError(t *testing.T) {
	factory, ok := backend.Default.Get("file")
	if !ok {
		t.Fatal("file backend not registered; import side-effect missing")
	}

	cfg := backend.BackendConfig{
		Name: "file",
		Settings: map[string]interface{}{
			"data_dir":    t.TempDir(),
			"unknown_key": "should-cause-error",
		},
	}

	_, err := factory(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for unknown settings key, got nil")
	}
}

// TestFileFactory_NoKeyring_ReturnsBootstrapRequired verifies that the factory
// fails closed (ErrBootstrapRequired) when no keyring.json is present.
// This is the core invariant: OpenWithKeyring is the only production path.
func TestFileFactory_NoKeyring_ReturnsBootstrapRequired(t *testing.T) {
	factory, ok := backend.Default.Get("file")
	if !ok {
		t.Fatal("file backend not registered")
	}

	// Use an explicit keyring_path pointing to a non-existent file.
	cfg := backend.BackendConfig{
		Name: "file",
		Settings: map[string]interface{}{
			"data_dir":     t.TempDir(),
			"keyring_path": t.TempDir() + "/nonexistent/keyring.json",
		},
	}

	_, err := factory(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected ErrBootstrapRequired when keyring is absent, got nil")
	}
	if !errors.Is(err, backend.ErrBootstrapRequired) {
		t.Errorf("expected ErrBootstrapRequired, got: %v", err)
	}
}
