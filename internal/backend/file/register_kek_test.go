package file

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/testutil"
)

func legacyIdentity(t *testing.T, store kek.IdentityStore) kek.VaultIdentity {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity")
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{7}, 32), 0o600))
	return kek.VaultIdentity{Path: path, Store: store}
}

func noEnv(string) string { return "" }

func resetWarnOnce(t *testing.T) {
	t.Helper()
	plaintextIdentityWarned = sync.Once{}
	t.Cleanup(func() { plaintextIdentityWarned = sync.Once{} })
}

func TestSecureVaultIdentity_MigratesOnOpen(t *testing.T) {
	resetWarnOnce(t)
	store := testutil.NewMemoryIdentityStore()
	vi := legacyIdentity(t, store)
	var out bytes.Buffer

	secureVaultIdentity(vi, noEnv, &out)

	loc, onDisk, err := vi.Location()
	require.NoError(t, err)
	assert.Equal(t, kek.IdentityInKeyring, loc)
	assert.False(t, onDisk)
	assert.Contains(t, out.String(), "moved the vault key")
}

func TestSecureVaultIdentity_WarnsOnceWithoutKeyring(t *testing.T) {
	resetWarnOnce(t)
	vi := legacyIdentity(t, nil)
	var out bytes.Buffer

	secureVaultIdentity(vi, noEnv, &out)
	secureVaultIdentity(vi, noEnv, &out)

	assert.Equal(t, 1, bytes.Count(out.Bytes(), []byte("WARNING")))
	_, err := os.Stat(vi.Path)
	assert.NoError(t, err, "the file stays usable when it cannot be moved")
}

func TestSecureVaultIdentity_RespectsOptIn(t *testing.T) {
	resetWarnOnce(t)
	store := testutil.NewMemoryIdentityStore()

	acked := legacyIdentity(t, store)
	require.NoError(t, acked.Acknowledge())
	var out bytes.Buffer
	secureVaultIdentity(acked, noEnv, &out)

	viaEnv := legacyIdentity(t, store)
	secureVaultIdentity(viaEnv, func(k string) string {
		if k == kek.InsecureFileKEKEnv {
			return "1"
		}
		return ""
	}, &out)

	assert.Zero(t, store.Len())
	assert.Empty(t, out.String())
}
