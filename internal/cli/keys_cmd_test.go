package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
	"github.com/keylatch/keylatch/internal/testutil"
)

const keysTestSecret = "default/ai/openai/api_key"

type keysFixture struct {
	store *testutil.MemoryIdentityStore
	vi    kek.VaultIdentity
}

// plaintextInstall bootstraps a vault whose key is in a plaintext identity file
// and stores one secret in it.
func plaintextInstall(t *testing.T) *keysFixture {
	t.Helper()
	presenceTestEnv(t)
	store := testutil.NewMemoryIdentityStore()
	prev := keysIdentityStore
	keysIdentityStore = func() kek.IdentityStore { return store }
	t.Cleanup(func() { keysIdentityStore = prev })

	env := llmcontext.DefaultLookup
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env, InsecureFileKEK: true, IdentityStore: store})
	require.NoError(t, err)

	f := &keysFixture{store: store, vi: kek.VaultIdentity{Path: paths.KeyringIdentityPath(env), Store: store}}
	f.openBackend(t, func(fb *file.FileBackend) {
		require.NoError(t, fb.Set(context.Background(), keysTestSecret, []byte("sk-test-secret-value"), backend.Meta{}))
	})
	return f
}

func (f *keysFixture) header(t *testing.T) keyring.KeyringFile {
	t.Helper()
	h, err := keyring.ReadHeader(paths.ResolveKeyringPath(llmcontext.DefaultLookup))
	require.NoError(t, err)
	return h
}

// openBackend opens the vault with whatever key currently opens it.
func (f *keysFixture) openBackend(t *testing.T, use func(*file.FileBackend)) {
	t.Helper()
	h := f.header(t)
	k, err := f.vi.KEK(h.Salt)
	require.NoError(t, err)
	f.openWith(t, k, use)
}

func (f *keysFixture) openWith(t *testing.T, k kek.KEK, use func(*file.FileBackend)) {
	t.Helper()
	kr, err := keyring.Open(paths.ResolveKeyringPath(llmcontext.DefaultLookup), k)
	require.NoError(t, err)
	defer kr.Zero()
	fb, err := file.OpenWithKeyring(file.Options{Dir: paths.Vault(llmcontext.DefaultLookup)}, kr)
	require.NoError(t, err)
	use(fb)
}

func (f *keysFixture) readSecret(t *testing.T, k kek.KEK) string {
	t.Helper()
	var got string
	f.openWith(t, k, func(fb *file.FileBackend) {
		v, _, err := fb.Get(context.Background(), keysTestSecret)
		require.NoError(t, err)
		got = string(v)
	})
	return got
}

func TestKeysStatusJSON(t *testing.T) {
	plaintextInstall(t)

	out, err := runCLI(t, "keys", "status", "--json")
	require.NoError(t, err)
	var st keysStatus
	require.NoError(t, json.Unmarshal([]byte(out), &st), out)
	assert.Equal(t, "age-env", st.KEKType)
	assert.Equal(t, "plaintext-file", st.Held)
	assert.True(t, st.PlaintextKEK)
	assert.NotContains(t, out, "sk-test", "status must not show secrets")
}

// A passphrase keyring opens only with a passphrase typed on a terminal.
func TestPassphraseKEKRequiresTTY(t *testing.T) {
	presenceTestEnv(t)
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{
		Env:        llmcontext.DefaultLookup,
		KEKMode:    bootstrap.KEKModePassphrase,
		Passphrase: func() ([]byte, error) { return []byte("a sufficiently long passphrase"), nil },
	})
	require.NoError(t, err)
	krPath := paths.ResolveKeyringPath(llmcontext.DefaultLookup)

	withInteractiveStdin(t, false)
	_, err = file.LoadKeyringKEK(krPath)
	require.ErrorIs(t, err, file.ErrPassphraseNeedsTerminal, "a pipe or file must not supply the passphrase")

	withInteractiveStdin(t, true)
	prev := promptHiddenFn
	promptHiddenFn = func() ([]byte, error) { return []byte("a sufficiently long passphrase"), nil }
	t.Cleanup(func() { promptHiddenFn = prev })
	k, err := file.LoadKeyringKEK(krPath)
	require.NoError(t, err)
	kr, err := keyring.Open(krPath, k)
	require.NoError(t, err)
	kr.Zero()

	promptHiddenFn = func() ([]byte, error) { return []byte("the wrong passphrase!"), nil }
	k, err = file.LoadKeyringKEK(krPath)
	require.NoError(t, err)
	_, err = keyring.Open(krPath, k)
	assert.ErrorIs(t, err, keyring.ErrKEKMismatch)
}

func TestKeysStatusWithoutAKeyring(t *testing.T) {
	presenceTestEnv(t)
	_, err := runCLI(t, "keys", "status", "--json")
	requireExitCode(t, err, exitcode.UserError)
}

func TestRewrapRemovesIdentityFile(t *testing.T) {
	f := plaintextInstall(t)
	_, err := os.Stat(f.vi.Path)
	require.NoError(t, err, "setup: the plaintext identity should exist")

	out, err := runCLI(t, "keys", "rewrap", "--to", "keystore")
	require.NoError(t, err)
	assert.Contains(t, out, "1 secret(s) verified")

	_, err = os.Stat(f.vi.Path)
	assert.True(t, os.IsNotExist(err), "the plaintext identity must be gone")
	_, err = os.Stat(f.vi.InsecureMarkerPath())
	assert.True(t, os.IsNotExist(err), "the opt-in marker must be gone")
	assert.Equal(t, 1, f.store.Len(), "the new key must be in the keyring")

	loc, onDisk, err := f.vi.Location()
	require.NoError(t, err)
	assert.Equal(t, kek.IdentityInKeyring, loc)
	assert.False(t, onDisk)

	k, err := f.vi.KEK(f.header(t).Salt)
	require.NoError(t, err)
	assert.Equal(t, "sk-test-secret-value", f.readSecret(t, k), "every secret still reads")

	statusOut, err := runCLI(t, "keys", "status", "--json")
	require.NoError(t, err)
	var st keysStatus
	require.NoError(t, json.Unmarshal([]byte(statusOut), &st))
	assert.Equal(t, "os-keyring", st.Held)
	assert.False(t, st.PlaintextKEK)
}

func TestRewrapUsesAFreshKey(t *testing.T) {
	f := plaintextInstall(t)
	old, err := os.ReadFile(f.vi.Path)
	require.NoError(t, err)
	oldKEK, err := kek.IdentityKEK(old, f.header(t).Salt)
	require.NoError(t, err)

	_, err = runCLI(t, "keys", "rewrap", "--to", "keystore")
	require.NoError(t, err)

	_, err = keyring.Open(paths.ResolveKeyringPath(llmcontext.DefaultLookup), oldKEK)
	assert.ErrorIs(t, err, keyring.ErrKEKMismatch, "a copy of the old identity must open nothing")
}

func TestRewrapToPassphrase(t *testing.T) {
	f := plaintextInstall(t)
	withInteractiveStdin(t, true)
	prev := promptHiddenFn
	promptHiddenFn = func() ([]byte, error) { return []byte("a sufficiently long passphrase"), nil }
	t.Cleanup(func() { promptHiddenFn = prev })

	out, err := runCLI(t, "keys", "rewrap", "--to", "passphrase")
	require.NoError(t, err)
	assert.Contains(t, out, "passphrase")

	_, err = os.Stat(f.vi.Path)
	assert.True(t, os.IsNotExist(err), "the plaintext identity must be gone")
	h := f.header(t)
	assert.Equal(t, "passphrase", h.KEKType)
	k, err := kek.PassphraseKEK([]byte("a sufficiently long passphrase"), h.Salt, argon2.Recommended2026)
	require.NoError(t, err)
	assert.Equal(t, "sk-test-secret-value", f.readSecret(t, k))
}

// Nothing is deleted until the new key has been proven: a vault file that
// cannot be read keeps the old key material in place.
func TestRewrapVerifiesBeforeDelete(t *testing.T) {
	f := plaintextInstall(t)
	value := filepath.Join(paths.Vault(llmcontext.DefaultLookup), filepath.FromSlash(keysTestSecret), "value.enc")
	data, err := os.ReadFile(value)
	require.NoError(t, err)
	data[0] ^= 0xff
	require.NoError(t, os.WriteFile(value, data, 0o600))

	_, err = runCLI(t, "keys", "rewrap", "--to", "keystore")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be read")

	_, statErr := os.Stat(f.vi.Path)
	assert.NoError(t, statErr, "the plaintext identity must survive an unverified rewrap")
}

func TestRewrapNeedsPresence(t *testing.T) {
	f := plaintextInstall(t)
	presencetest.NoTerminal(t)

	_, err := runCLI(t, "keys", "rewrap", "--to", "keystore")
	requireExitCode(t, err, exitcode.SecurityBlock)
	_, statErr := os.Stat(f.vi.Path)
	assert.NoError(t, statErr)
	assert.Zero(t, f.store.Len())
}

func TestRewrapToKeystoreNeedsAKeystore(t *testing.T) {
	f := plaintextInstall(t)
	keysIdentityStore = func() kek.IdentityStore { return nil }

	_, err := runCLI(t, "keys", "rewrap", "--to", "keystore")
	requireExitCode(t, err, exitcode.UserError)
	_, statErr := os.Stat(f.vi.Path)
	assert.NoError(t, statErr)
}

func TestRewrapRejectsUnknownTarget(t *testing.T) {
	plaintextInstall(t)
	_, err := runCLI(t, "keys", "rewrap", "--to", "carrier-pigeon")
	requireExitCode(t, err, exitcode.UserError)
	_, err = runCLI(t, "keys", "rewrap")
	require.Error(t, err)
}

func TestRewrapOfAKeyAlreadyInTheKeyringClearsAPlaintextCopy(t *testing.T) {
	f := plaintextInstall(t)
	// An older install left a copy next to the keyring item: same key in both.
	identity, err := os.ReadFile(f.vi.Path)
	require.NoError(t, err)
	_, err = runCLI(t, "keys", "rewrap", "--to", "keystore")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.vi.Path, identity, 0o600)) // a stale, different copy
	_, onDisk, err := f.vi.Location()
	require.NoError(t, err)
	require.True(t, onDisk)

	_, err = runCLI(t, "keys", "rewrap", "--to", "keystore")
	// The stale copy differs from the keyring item, so it is not silently
	// trusted and not silently deleted either.
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "differs"), err.Error())
}
