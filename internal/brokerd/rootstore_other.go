//go:build !darwin

package brokerd

import (
	"path/filepath"

	"github.com/keylatch/keylatch/internal/brokerd/keys"
)

// defaultRootStore is the root file fallback; only macOS has the System
// keychain and the Windows broker supplies its CNG sealer.
func defaultRootStore(stateDir, _ string, own func(string) error) keys.RootStore {
	return keys.SealedFile{Path: filepath.Join(stateDir, "keys", "root.key"), Own: own}
}
