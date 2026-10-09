//go:build !fips

package kek

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeStore struct {
	items    map[string][]byte
	storeErr error
	// corrupt makes Load return different bytes than were stored.
	corrupt bool
}

func newFakeStore() *fakeStore { return &fakeStore{items: map[string][]byte{}} }

func (f *fakeStore) Name() string { return "fake" }

func (f *fakeStore) Load(account string) ([]byte, error) {
	v, ok := f.items[account]
	if !ok {
		return nil, ErrIdentityNotFound
	}
	out := append([]byte(nil), v...)
	if f.corrupt {
		out[0] ^= 0xff
	}
	return out, nil
}

func (f *fakeStore) Store(account string, identity []byte) error {
	if f.storeErr != nil {
		return f.storeErr
	}
	f.items[account] = append([]byte(nil), identity...)
	return nil
}

func (f *fakeStore) Delete(account string) error {
	if _, ok := f.items[account]; !ok {
		return ErrIdentityNotFound
	}
	delete(f.items, account)
	return nil
}

func writeLegacyIdentity(t *testing.T, path string) []byte {
	t.Helper()
	id := make([]byte, identitySize)
	_, err := rand.Read(id)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, id, 0o600))
	return id
}

func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func roundTrip(t *testing.T, a, b KEK) {
	t.Helper()
	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := a.Wrap(dek)
	require.NoError(t, err)
	got, err := b.Unwrap(wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

func TestVaultIdentity_ProvisionKeyringWritesNoPlaintext(t *testing.T) {
	store := newFakeStore()
	vi := VaultIdentity{Path: filepath.Join(t.TempDir(), "identity"), Store: store}

	require.NoError(t, vi.Provision(false))

	_, err := os.Stat(vi.Path)
	assert.True(t, os.IsNotExist(err), "no plaintext identity file may be written")
	assert.Len(t, store.items, 1)
	loc, onDisk, err := vi.Location()
	require.NoError(t, err)
	assert.Equal(t, IdentityInKeyring, loc)
	assert.False(t, onDisk)

	ref, err := os.ReadFile(vi.RefPath())
	require.NoError(t, err)
	for _, v := range store.items {
		assert.NotContains(t, string(ref), hex.EncodeToString(v), "reference must not contain the secret")
	}
	assertOwnerOnly(t, vi.RefPath())

	salt := []byte("salt-salt-salt-salt-salt-salt-32")
	k1, err := vi.KEK(salt)
	require.NoError(t, err)
	k2, err := vi.KEK(salt)
	require.NoError(t, err)
	roundTrip(t, k1, k2)
}

func TestVaultIdentity_ProvisionWithoutKeyringFails(t *testing.T) {
	vi := VaultIdentity{Path: filepath.Join(t.TempDir(), "identity")}
	err := vi.Provision(false)
	require.ErrorIs(t, err, ErrNoOSKeyring)
	_, statErr := os.Stat(vi.Path)
	assert.True(t, os.IsNotExist(statErr))
}

func TestVaultIdentity_ProvisionKeyringStoreErrorIsNoOSKeyring(t *testing.T) {
	store := newFakeStore()
	store.storeErr = errors.New("collection locked")
	vi := VaultIdentity{Path: filepath.Join(t.TempDir(), "identity"), Store: store}
	require.ErrorIs(t, vi.Provision(false), ErrNoOSKeyring)
	_, err := os.Stat(vi.RefPath())
	assert.True(t, os.IsNotExist(err))
}

func TestVaultIdentity_ProvisionReadBackMismatchRollsBack(t *testing.T) {
	store := newFakeStore()
	store.corrupt = true
	vi := VaultIdentity{Path: filepath.Join(t.TempDir(), "identity"), Store: store}
	require.ErrorIs(t, vi.Provision(false), ErrNoOSKeyring)
	assert.Empty(t, store.items, "a mismatching item must be deleted")
	_, err := os.Stat(vi.RefPath())
	assert.True(t, os.IsNotExist(err))
}

func TestVaultIdentity_ProvisionInsecureWritesFileAndMarker(t *testing.T) {
	store := newFakeStore()
	vi := VaultIdentity{Path: filepath.Join(t.TempDir(), "identity"), Store: store}
	require.NoError(t, vi.Provision(true))

	assert.Empty(t, store.items)
	loc, onDisk, err := vi.Location()
	require.NoError(t, err)
	assert.Equal(t, IdentityInFileAcknowledged, loc)
	assert.True(t, onDisk)
	assertOwnerOnly(t, vi.Path)
}

func TestVaultIdentity_MigrateMovesIdentityAndKeepsKEK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	writeLegacyIdentity(t, path)
	salt := []byte("salt-salt-salt-salt-salt-salt-32")
	legacy, err := AgeIdentityKEKFromPath(path, salt)
	require.NoError(t, err)

	store := newFakeStore()
	vi := VaultIdentity{Path: path, Store: store}
	loc, _, err := vi.Location()
	require.NoError(t, err)
	assert.Equal(t, IdentityInFileUnacknowledged, loc)

	moved, err := vi.MigrateToKeyring()
	require.NoError(t, err)
	assert.True(t, moved)
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "plaintext identity must be removed after migration")

	migrated, err := vi.KEK(salt)
	require.NoError(t, err)
	roundTrip(t, legacy, migrated)
}

func TestVaultIdentity_MigrateRemovesInsecureMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	writeLegacyIdentity(t, path)
	vi := VaultIdentity{Path: path, Store: newFakeStore()}
	require.NoError(t, vi.Acknowledge())

	moved, err := vi.MigrateToKeyring()
	require.NoError(t, err)
	assert.True(t, moved)
	_, err = os.Stat(vi.InsecureMarkerPath())
	assert.True(t, os.IsNotExist(err))
}

func TestVaultIdentity_MigrateWithoutKeyringKeepsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	writeLegacyIdentity(t, path)
	vi := VaultIdentity{Path: path}

	moved, err := vi.MigrateToKeyring()
	require.ErrorIs(t, err, ErrNoOSKeyring)
	assert.False(t, moved)
	_, err = os.Stat(path)
	assert.NoError(t, err)
}

func TestVaultIdentity_MigrateStoreFailureKeepsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	writeLegacyIdentity(t, path)
	store := newFakeStore()
	store.storeErr = errors.New("locked")
	vi := VaultIdentity{Path: path, Store: store}

	moved, err := vi.MigrateToKeyring()
	require.Error(t, err)
	assert.False(t, moved)
	_, err = os.Stat(path)
	assert.NoError(t, err)
	_, err = os.Stat(vi.RefPath())
	assert.True(t, os.IsNotExist(err))
}

func TestVaultIdentity_MigrateFinishesInterruptedRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	id := writeLegacyIdentity(t, path)
	store := newFakeStore()
	vi := VaultIdentity{Path: path, Store: store}
	require.NoError(t, vi.storeInKeyring(id))

	moved, err := vi.MigrateToKeyring()
	require.NoError(t, err)
	assert.True(t, moved)
	assert.Len(t, store.items, 1, "no second item may be created")
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestVaultIdentity_MigrateRefusesDifferingLeftover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	store := newFakeStore()
	vi := VaultIdentity{Path: path, Store: store}
	require.NoError(t, vi.Provision(false))
	writeLegacyIdentity(t, path)

	moved, err := vi.MigrateToKeyring()
	require.Error(t, err)
	assert.False(t, moved)
	_, err = os.Stat(path)
	assert.NoError(t, err, "a differing file must be left for the user to inspect")
}

func TestVaultIdentity_KeyringReferenceWinsOverPlantedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	store := newFakeStore()
	vi := VaultIdentity{Path: path, Store: store}
	require.NoError(t, vi.Provision(false))
	salt := []byte("salt-salt-salt-salt-salt-salt-32")
	want, err := vi.KEK(salt)
	require.NoError(t, err)

	writeLegacyIdentity(t, path)
	got, err := vi.KEK(salt)
	require.NoError(t, err)
	roundTrip(t, want, got)
}

func TestVaultIdentity_LoadFailsClosedWhenKeyringUnreachable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	vi := VaultIdentity{Path: path, Store: newFakeStore()}
	require.NoError(t, vi.Provision(false))
	writeLegacyIdentity(t, path)

	_, err := VaultIdentity{Path: path}.KEK([]byte("salt"))
	require.ErrorIs(t, err, ErrKEKUnavailable)
}

func TestVaultIdentity_MalformedReferenceRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	vi := VaultIdentity{Path: path, Store: newFakeStore()}
	require.NoError(t, os.WriteFile(vi.RefPath(), []byte(`{"store":"fake","account":"x; rm -rf"}`), 0o600))
	_, err := vi.Load()
	require.ErrorIs(t, err, ErrKEKUnavailable)
}

func TestVaultIdentity_RemoveDeletesKeyringItem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	store := newFakeStore()
	vi := VaultIdentity{Path: path, Store: store}
	require.NoError(t, vi.Provision(false))

	require.NoError(t, vi.Remove())
	assert.Empty(t, store.items)
	loc, _, err := vi.Location()
	require.NoError(t, err)
	assert.Equal(t, IdentityMissing, loc)
}

func TestInsecureFileKEKRequested(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "true": true, "YES": true, "": false, "0": false, "no": false} {
		got := InsecureFileKEKRequested(func(k string) string {
			if k == InsecureFileKEKEnv {
				return v
			}
			return ""
		})
		assert.Equal(t, want, got, "value %q", v)
	}
}

type runnerCall struct {
	stdin []byte
	name  string
	args  []string
}

type exitErr int

func (e exitErr) Error() string { return "exit status" }
func (e exitErr) ExitCode() int { return int(e) }

func recordingRunner(calls *[]runnerCall, out []byte, stderr []byte, err error) identityRunner {
	return func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, []byte, error) {
		*calls = append(*calls, runnerCall{stdin: append([]byte(nil), stdin...), name: name, args: args})
		return out, stderr, err
	}
}

func TestSecretServiceStore_SecretTravelsOnStdin(t *testing.T) {
	var calls []runnerCall
	s := &secretServiceIdentityStore{bin: "secret-tool", run: recordingRunner(&calls, nil, nil, nil)}
	id := bytes.Repeat([]byte{0xab}, identitySize)

	require.NoError(t, s.Store("vault-0011223344556677", id))
	require.Len(t, calls, 1)
	assert.Equal(t, hex.EncodeToString(id), string(calls[0].stdin))
	assert.NotContains(t, strings.Join(calls[0].args, " "), hex.EncodeToString(id))
	assert.Equal(t, []string{"store", "--label=" + itemLabel, "application", "keylatch", "purpose", "kek", "account", "vault-0011223344556677"}, calls[0].args)
}

func TestSecretServiceStore_Load(t *testing.T) {
	id := bytes.Repeat([]byte{0x01}, identitySize)
	var calls []runnerCall
	s := &secretServiceIdentityStore{bin: "secret-tool", run: recordingRunner(&calls, []byte(hex.EncodeToString(id)), nil, nil)}
	got, err := s.Load("vault-01")
	require.NoError(t, err)
	assert.Equal(t, id, got)
	assert.Equal(t, []string{"lookup", "application", "keylatch", "purpose", "kek", "account", "vault-01"}, calls[0].args)

	s.run = recordingRunner(&calls, nil, nil, exitErr(1))
	_, err = s.Load("vault-01")
	require.ErrorIs(t, err, ErrIdentityNotFound)

	s.run = recordingRunner(&calls, nil, []byte("Cannot autolaunch D-Bus"), exitErr(1))
	_, err = s.Load("vault-01")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrIdentityNotFound)

	s.run = recordingRunner(&calls, []byte("not-hex"), nil, nil)
	_, err = s.Load("vault-01")
	require.Error(t, err)
}

func TestKeychainStore_SecretNotOnArgv(t *testing.T) {
	var calls []runnerCall
	s := &keychainIdentityStore{bin: "/usr/bin/security", run: recordingRunner(&calls, nil, nil, nil)}
	id := bytes.Repeat([]byte{0xcd}, identitySize)

	require.NoError(t, s.Store("vault-aa", id))
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"-i"}, calls[0].args)
	assert.Equal(t, "add-generic-password -U -s keylatch-vault-kek -a vault-aa -w "+hex.EncodeToString(id)+"\n", string(calls[0].stdin))
}

func TestKeychainStore_LoadNotFound(t *testing.T) {
	var calls []runnerCall
	s := &keychainIdentityStore{bin: "/usr/bin/security", run: recordingRunner(&calls, nil, nil, exitErr(keychainItemNotFoundExit))}
	_, err := s.Load("vault-aa")
	require.ErrorIs(t, err, ErrIdentityNotFound)
	assert.Equal(t, []string{"find-generic-password", "-s", "keylatch-vault-kek", "-a", "vault-aa", "-w"}, calls[0].args)
}

func TestIdentityStores_RejectUnsafeAccounts(t *testing.T) {
	var calls []runnerCall
	run := recordingRunner(&calls, nil, nil, nil)
	for _, s := range []IdentityStore{
		&keychainIdentityStore{bin: "security", run: run},
		&secretServiceIdentityStore{bin: "secret-tool", run: run},
	} {
		require.Error(t, s.Store("a -w leak\nadd", make([]byte, identitySize)), s.Name())
		_, err := s.Load("A B")
		require.Error(t, err, s.Name())
		require.Error(t, s.Delete(""), s.Name())
	}
	assert.Empty(t, calls)
}

func TestSessionBusConfigured(t *testing.T) {
	dir := t.TempDir()
	lookup := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	assert.True(t, sessionBusConfigured(lookup(map[string]string{"DBUS_SESSION_BUS_ADDRESS": "unix:path=/x"})))
	assert.False(t, sessionBusConfigured(lookup(map[string]string{"XDG_RUNTIME_DIR": dir})))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bus"), nil, 0o600))
	assert.True(t, sessionBusConfigured(lookup(map[string]string{"XDG_RUNTIME_DIR": dir})))
	assert.False(t, sessionBusConfigured(lookup(nil)))
}

func TestShredFileRemovesFileAndToleratesMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(p, bytes.Repeat([]byte{1}, identitySize), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := shredFile(p); err != nil {
		t.Fatalf("shred: %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file still present: %v", err)
	}
	if err := shredFile(p); err != nil {
		t.Fatalf("shred missing: %v", err)
	}
}
