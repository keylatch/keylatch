package keychain

import (
	"fmt"
	"os"
)

// DefaultDBPath returns the canonical path of the dedicated keychain DB
// (~/.keylatch/keylatch.keychain-db), matching Open's default resolution.
// Available on all platforms so callers (e.g. doctor checks) compile
// everywhere; the keychain itself only operates on darwin.
func DefaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("keychain: resolve home: %w", err)
	}
	return home + "/.keylatch/keylatch.keychain-db", nil
}
