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
	"github.com/keylatch/keylatch/internal/crypto/argon2"
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

// Neither a keyring nor a terminal: fail with a way forward instead of
// falling back to a plaintext file.
func TestBootstrap_NoKeyringAndNoTerminalFails(t *testing.T) {
	env := makeEnv(t.TempDir(), nil)
	store := testutil.NewMemoryIdentityStore()
	store.StoreErr = testutil.ErrKeyringLocked

	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store})
	require.ErrorIs(t, err, kek.ErrNoOSKeyring)
	assert.Contains(t, err.Error(), "terminal")
	assert.Contains(t, err.Error(), "passphrase")
	assert.NotContains(t, err.Error(), "--insecure-file-kek", "the error must not point at a flag")

	_, statErr := os.Stat(paths.KeyringIdentityPath(env))
	assert.True(t, os.IsNotExist(statErr))
	_, statErr = os.Stat(paths.KeyringPath(env))
	assert.True(t, os.IsNotExist(statErr), "no keyring may be created without a KEK")
}

// The old environment opt-in grants nothing.
func TestBootstrap_EnvironmentCannotOptIntoPlaintext(t *testing.T) {
	env := makeEnv(t.TempDir(), map[string]string{"KEYLATCH_INSECURE_FILE_KEK": "1"})
	store := testutil.NewMemoryIdentityStore()
	store.StoreErr = testutil.ErrKeyringLocked

	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, IdentityStore: store})
	require.ErrorIs(t, err, kek.ErrNoOSKeyring)
	_, statErr := os.Stat(paths.KeyringIdentityPath(env))
	assert.True(t, os.IsNotExist(statErr))
}

func TestBootstrap_InsecureFileKEKOptIn(t *testing.T) {
	home := t.TempDir()
	store := testutil.NewMemoryIdentityStore()
	o := bootstrap.Options{Env: makeEnv(home, nil), InsecureFileKEK: true, IdentityStore: store}

	plan, err := bootstrap.Run(context.Background(), o)
	require.NoError(t, err)

	loc, onDisk := identityState(t, o.Env, store)
	assert.Equal(t, kek.IdentityInFileAcknowledged, loc)
	assert.True(t, onDisk)
	assert.Zero(t, store.Len())
	require.Len(t, plan.Warnings, 1)
	assert.True(t, strings.HasPrefix(plan.Warnings[0], "INSECURE:"))
	openKeyring(t, o.Env, store)
}

func openPassphraseKeyring(t *testing.T, env func(string) string, pass string) {
	t.Helper()
	krPath := paths.KeyringPath(env)
	kf, err := keyring.ReadHeader(krPath)
	require.NoError(t, err)
	assert.Equal(t, "passphrase", kf.KEKType)
	k, err := kek.PassphraseKEK([]byte(pass), kf.Salt, argon2.Recommended2026)
	require.NoError(t, err)
	_, err = keyring.Open(krPath, k)
	require.NoError(t, err)
}

// With no keyring but a human at a terminal, the key is wrapped under a
// passphrase and no identity file is written.
func TestBootstrap_PassphraseWhenNoKeyringButATerminal(t *testing.T) {
	env := makeEnv(t.TempDir(), nil)
	store := testutil.NewMemoryIdentityStore()
	store.StoreErr = testutil.ErrKeyringLocked
	asked := 0

	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{
		Env: env, IdentityStore: store,
		Passphrase: func() ([]byte, error) { asked++; return []byte("a long enough passphrase"), nil },
	})
	require.NoError(t, err)
	assert.Equal(t, 1, asked)
	require.NotEmpty(t, plan.Warnings)

	_, statErr := os.Stat(paths.KeyringIdentityPath(env))
	assert.True(t, os.IsNotExist(statErr), "no plaintext identity")
	openPassphraseKeyring(t, env, "a long enough passphrase")

	// Running again is a no-op and does not ask again.
	_, err = bootstrap.Run(context.Background(), bootstrap.Options{
		Env: env, IdentityStore: store,
		Passphrase: func() ([]byte, error) { asked++; return nil, nil },
	})
	require.NoError(t, err)
	assert.Equal(t, 1, asked)
}

func TestBootstrap_PassphraseModeIsExplicit(t *testing.T) {
	env := makeEnv(t.TempDir(), nil)
	store := testutil.NewMemoryIdentityStore() // a keyring is available but not wanted

	_, err := bootstrap.Run(context.Background(), bootstrap.Options{
		Env: env, IdentityStore: store, KEKMode: bootstrap.KEKModePassphrase,
		Passphrase: func() ([]byte, error) { return []byte("another long passphrase"), nil },
	})
	require.NoError(t, err)
	assert.Zero(t, store.Len(), "the keyring must not be used in passphrase mode")
	openPassphraseKeyring(t, env, "another long passphrase")

	_, err = bootstrap.Run(context.Background(), bootstrap.Options{Env: makeEnv(t.TempDir(), nil), IdentityStore: store, KEKMode: bootstrap.KEKModePassphrase})
	require.Error(t, err, "passphrase mode without a terminal must fail")
	_, err = bootstrap.Run(context.Background(), bootstrap.Options{Env: makeEnv(t.TempDir(), nil), KEKMode: "carrier-pigeon"})
	require.Error(t, err)
}

func TestBootstrap_KeystoreModeNeverFallsBackToAPassphrase(t *testing.T) {
	env := makeEnv(t.TempDir(), nil)
	store := testutil.NewMemoryIdentityStore()
	store.StoreErr = testutil.ErrKeyringLocked

	_, err := bootstrap.Run(context.Background(), bootstrap.Options{
		Env: env, IdentityStore: store, KEKMode: bootstrap.KEKModeKeystore,
		Passphrase: func() ([]byte, error) { return []byte("never used passphrase"), nil },
	})
	require.ErrorIs(t, err, kek.ErrNoOSKeyring)
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
