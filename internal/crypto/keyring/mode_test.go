package keyring

import (
	"os"
	"testing"
)

func assertPrivateFileMode(t *testing.T, path string) {
	t.Helper()
	if !enforcePrivateFileMode {
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("keyring file mode = %04o, want 0600 (S5-19)", info.Mode().Perm())
	}
}
