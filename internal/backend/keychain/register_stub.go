//go:build !darwin

// Package keychain implements the macOS Keychain backend.
// register_stub.go self-registers the keychain backend on non-darwin platforms.
// The factory always returns ErrUnavailable.
package keychain

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/backend"
)

func init() {
	if err := backend.Default.Register("keychain", keychainFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/keychain: %w", err))
	}
}

func keychainFactory(_ context.Context, _ backend.BackendConfig) (backend.Backend, error) {
	return nil, fmt.Errorf("%w: keychain backend requires macOS; use file, op, or bw instead", backend.ErrUnavailable)
}
