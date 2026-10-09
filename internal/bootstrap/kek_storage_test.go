package bootstrap_test

import (
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/testutil"
)

func identityState(t *testing.T, env func(string) string, store kek.IdentityStore) (kek.IdentityLocation, bool) {
	t.Helper()
	loc, onDisk, err := kek.VaultIdentity{Path: paths.KeyringIdentityPath(env), Store: store}.Location()
	require.NoError(t, err)
	return loc, onDisk
}

func openKeyring(t *testing.T, env func(string) string, store kek.IdentityStore) {
	t.Helper()
	krPath := paths.KeyringPath(env)
	kf, err := keyring.ReadHeader(krPath)
	require.NoError(t, err)
	k, err := kek.VaultIdentity{Path: paths.KeyringIdentityPath(env), Store: store}.KEK(kf.Salt)
	require.NoError(t, err)
	_, err = keyring.Open(krPath, k)
	require.NoError(t, err)
}

func TestBootstrapNeverWritesPlaintextKEK(t *testing.T) {
	env := makeEnv(t.TempDir(), nil)
	store := testutil.NewMemoryIdentityStore()

	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store})
	require.NoError(t, err)

	loc, onDisk := identityState(t, env, store)
	assert.Equal(t, kek.IdentityInKeyring, loc)
	assert.False(t, onDisk)
	assert.Equal(t, 1, store.Len())
	assert.Empty(t, plan.Warnings)
	openKeyring(t, env, store)
}

func TestBootstrap_NoKeyringRequiresOptIn(t *testing.T) {
	env := makeEnv(t.TempDir(), nil)
	store := testutil.NewMemoryIdentityStore()
	store.StoreErr = testutil.ErrKeyringLocked

	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store})
	require.ErrorIs(t, err, kek.ErrNoOSKeyring)
	assert.Contains(t, err.Error(), "--insecure-file-kek")

	_, statErr := os.Stat(paths.KeyringIdentityPath(env))
	assert.True(t, os.IsNotExist(statErr))
	_, statErr = os.Stat(paths.KeyringPath(env))
	assert.True(t, os.IsNotExist(statErr), "no keyring may be created without a KEK")
}

func TestBootstrap_InsecureFileKEKOptIn(t *testing.T) {
	for name, opts := range map[string]func(string) bootstrap.Options{
		"flag": func(home string) bootstrap.Options {
			return bootstrap.Options{Env: makeEnv(home, nil), InsecureFileKEK: true}
		},
		"env": func(home string) bootstrap.Options {
			return bootstrap.Options{Env: makeEnv(home, map[string]string{kek.InsecureFileKEKEnv: "1"})}
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := testutil.NewMemoryIdentityStore()
			o := opts(t.TempDir())
			o.IdentityStore = store

			plan, err := bootstrap.Run(context.Background(), o)
			require.NoError(t, err)

			loc, onDisk := identityState(t, o.Env, store)
			assert.Equal(t, kek.IdentityInFileAcknowledged, loc)
			assert.True(t, onDisk)
			assert.Zero(t, store.Len())
			require.Len(t, plan.Warnings, 1)
			assert.True(t, strings.HasPrefix(plan.Warnings[0], "INSECURE:"))
			openKeyring(t, o.Env, store)
		})
	}
}

func legacyInstall(t *testing.T) func(string) string {
	t.Helper()
	env := makeEnv(t.TempDir(), nil)
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, InsecureFileKEK: true, IdentityStore: testutil.NewMemoryIdentityStore()})
	require.NoError(t, err)
	require.NoError(t, os.Remove(paths.KeyringIdentityPath(env)+".insecure"))
	return env
}

func TestBootstrap_MigratesLegacyPlaintextIdentity(t *testing.T) {
	env := legacyInstall(t)
	store := testutil.NewMemoryIdentityStore()

	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store})
	require.NoError(t, err)
	assert.Empty(t, plan.Warnings)

	loc, onDisk := identityState(t, env, store)
	assert.Equal(t, kek.IdentityInKeyring, loc)
	assert.False(t, onDisk, "plaintext identity must be removed")
	openKeyring(t, env, store)
}

func TestBootstrap_LegacyWithoutKeyringWarnsAndKeepsWorking(t *testing.T) {
	env := legacyInstall(t)
	store := testutil.NewMemoryIdentityStore()
	store.StoreErr = testutil.ErrKeyringLocked

	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store})
	require.NoError(t, err)
	require.NotEmpty(t, plan.Warnings)
	assert.Contains(t, plan.Warnings[0], "plaintext")

	loc, _ := identityState(t, env, store)
	assert.Equal(t, kek.IdentityInFileUnacknowledged, loc)
	openKeyring(t, env, store)
}

func TestBootstrap_InsecureFlagAcknowledgesLegacyIdentity(t *testing.T) {
	env := legacyInstall(t)
	store := testutil.NewMemoryIdentityStore()

	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store, InsecureFileKEK: true})
	require.NoError(t, err)
	require.Len(t, plan.Warnings, 1)

	loc, _ := identityState(t, env, store)
	assert.Equal(t, kek.IdentityInFileAcknowledged, loc)
	assert.Zero(t, store.Len())
}

func TestBootstrap_DryRunLeavesKeyringUntouched(t *testing.T) {
	env := legacyInstall(t)
	store := testutil.NewMemoryIdentityStore()

	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store, DryRun: true})
	require.NoError(t, err)
	assert.Zero(t, store.Len())
	loc, _ := identityState(t, env, store)
	assert.Equal(t, kek.IdentityInFileUnacknowledged, loc)
}

func TestBootstrap_ForceReplacesKeyringItem(t *testing.T) {
	env := makeEnv(t.TempDir(), nil)
	store := testutil.NewMemoryIdentityStore()
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store})
	require.NoError(t, err)

	_, err = bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store, Force: true, Confirm: true})
	require.NoError(t, err)
	assert.Equal(t, 1, store.Len(), "the old keyring item must be deleted")
	openKeyring(t, env, store)
}

func TestBootstrap_PlantedFileIgnoredOnceInKeyring(t *testing.T) {
	env := makeEnv(t.TempDir(), nil)
	store := testutil.NewMemoryIdentityStore()
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store})
	require.NoError(t, err)

	planted := make([]byte, 32)
	_, err = rand.Read(planted)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.KeyringIdentityPath(env), planted, 0o600))

	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store})
	require.NoError(t, err)
	require.NotEmpty(t, plan.Warnings)
	openKeyring(t, env, store)
}
