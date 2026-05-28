//go:build !darwin

// Package keychain provides the macOS Keychain backend. On non-darwin platforms,
// all methods return backend.ErrUnavailable.
package keychain

// acquireFlock is a no-op stub on non-darwin platforms.
// Returns a no-op release function and nil error so the code compiles.
func acquireFlock(_ string) (func(), error) { //nolint:unused // stub satisfies call sites compiled only on darwin
	return func() {}, nil
}
