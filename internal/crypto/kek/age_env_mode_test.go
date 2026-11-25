package kek_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/crypto/kek"
)

// systemd delivers credentials as 0400 files, so owner-only modes must load
// while anything group- or world-accessible, or unreadable, must not.
func TestAgeIdentityKEKFromPath_OwnerOnlyModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix permission bits")
	}
	for mode, wantOK := range map[os.FileMode]bool{0o600: true, 0o400: true, 0o640: false, 0o604: false, 0o200: false} {
		identityPath := filepath.Join(t.TempDir(), "identity")
		require.NoError(t, os.WriteFile(identityPath, []byte("identity-bytes"), 0o600))
		require.NoError(t, os.Chmod(identityPath, mode))

		_, err := kek.AgeIdentityKEKFromPath(identityPath, testSalt)
		if wantOK {
			assert.NoError(t, err, "mode %04o", mode)
		} else {
			assert.ErrorIs(t, err, kek.ErrKEKUnavailable, "mode %04o", mode)
		}
	}
}
