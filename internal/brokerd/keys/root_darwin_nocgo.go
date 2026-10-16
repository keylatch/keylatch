//go:build darwin && !cgo

package keys

import "path/filepath"

// DefaultRootStore returns a root file in the state directory, mode 0400 and
// owned by the daemon account. A build without cgo cannot reach the Security
// framework, so the keychain's per-binary access list is not available; the
// broker reports the root file as its key custody.
func DefaultRootStore(stateDir, _ string, own func(string) error) RootStore {
	return SealedFile{Path: filepath.Join(stateDir, "keys", "root.key"), Own: own}
}
