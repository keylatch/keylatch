package bootstrap_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/testutil"
)

func TestBootstrap_SuppliedIdentityNeedsNoKeyringOrPlaintextFile(t *testing.T) {
	supplied := filepath.Join(t.TempDir(), "kek")
	require.NoError(t, os.WriteFile(supplied, []byte("0123456789abcdef0123456789abcdef"), 0o400))
	env := makeEnv(t.TempDir(), map[string]string{"KEYLATCH_AGE_IDENTITY": supplied})
	store := testutil.NewMemoryIdentityStore()
	store.StoreErr = testutil.ErrKeyringLocked

	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store})
	require.NoError(t, err)

	assert.Empty(t, plan.Warnings)
	_, statErr := os.Stat(paths.KeyringIdentityPath(env))
	assert.True(t, os.IsNotExist(statErr), "no identity file may be written")
	assert.Zero(t, store.Len())

	krPath := paths.KeyringPath(env)
	kf, err := keyring.ReadHeader(krPath)
	require.NoError(t, err)
	k, err := kek.AgeIdentityKEKFromPath(supplied, kf.Salt)
	require.NoError(t, err)
	_, err = keyring.Open(krPath, k)
	require.NoError(t, err)
}
