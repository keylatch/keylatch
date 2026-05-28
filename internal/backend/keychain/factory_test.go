package keychain_test

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	_ "github.com/keylatch/keylatch/internal/backend/keychain" // trigger init()
)

func TestKeychainFactory_UnknownKey_ReturnsError(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("keychain factory unknown-key test is darwin-only")
	}

	factory, ok := backend.Default.Get("keychain")
	if !ok {
		t.Fatal("keychain backend not registered; import side-effect missing")
	}

	cfg := backend.BackendConfig{
		Name: "keychain",
		Settings: map[string]interface{}{
			"keychain_path": "/tmp/test.keychain-db",
			"unknown_key":   "should-cause-error",
		},
	}

	_, err := factory(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for unknown settings key, got nil")
	}
}

func TestKeychainFactory_NonDarwin_ReturnsUnavailable(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this test is for non-darwin platforms only")
	}

	factory, ok := backend.Default.Get("keychain")
	if !ok {
		t.Fatal("keychain backend not registered")
	}

	_, err := factory(context.Background(), backend.BackendConfig{Name: "keychain"})
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("expected ErrUnavailable on non-darwin, got: %v", err)
	}
}
