package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateCipherValidatesInput(t *testing.T) {
	caNewEnv(t)

	_, _, err := caRun(t, nil, "migrate", "cipher")
	require.Error(t, err, "--to is required")

	_, _, err = caRun(t, nil, "migrate", "cipher", "--to", "rot13")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown algorithm "rot13"`)

	_, _, err = caRun(t, nil, "migrate", "cipher", "--to", string(envelope.AES256GCM))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "migrate cipher: open keyring")
}

func TestMigrateCipherSameAlgorithmIsNoop(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	before, err := os.ReadFile(f.krPath)
	require.NoError(t, err)

	out, _, err := caRun(t, nil, "migrate", "cipher", "--to", string(envelope.XChaCha20Poly1305))
	require.NoError(t, err)
	assert.Contains(t, out, `vault is already using algorithm "xchacha20-poly1305" — nothing to do`)
	after, err := os.ReadFile(f.krPath)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestMigrateCipherEmptyVaultSwitchesAlgorithm(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)

	out, _, err := caRun(t, nil, "migrate", "cipher", "--to", string(envelope.AES256GCM))
	require.NoError(t, err)
	assert.Contains(t, out, `migrating vault from "xchacha20-poly1305" to "aes-256-gcm"`)
	assert.Contains(t, out, "no values to migrate; keyring algorithm updated")

	kf := caReadKeyringFile(t, f.krPath)
	assert.Equal(t, envelope.AES256GCM, kf.Algorithm)
	require.NotNil(t, kf.GCMState)
	assert.Equal(t, uint64(1024), kf.GCMState.LeaseSize)
	_, ok := kf.GCMState.PerTerm[kf.ActiveTerm]
	assert.True(t, ok)
	info, err := os.Stat(f.krPath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	out, _, err = caRun(t, nil, "migrate", "cipher", "--to", string(envelope.XChaCha20Poly1305))
	require.NoError(t, err)
	assert.Contains(t, out, "keyring algorithm updated")
	assert.Equal(t, envelope.XChaCha20Poly1305, caReadKeyringFile(t, f.krPath).Algorithm)
}

func TestMigrateCipherMetadataWithoutVersions(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	fb, err := file.Open(file.Options{Dir: f.vaultDir})
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, fb.SetMeta(context.Background(), caPath, vmeta.Meta{
		SchemaVersion: vmeta.CurrentSchemaVersion,
		Path:          caPath,
		Accessor:      vmeta.NewAccessor(),
		Backend:       "file",
		MaxVersions:   vmeta.DefaultMaxVersions,
		CreatedAt:     now,
		UpdatedAt:     now,
	}))

	out, _, err := caRun(t, nil, "migrate", "cipher", "--to", string(envelope.AES256GCM))
	require.NoError(t, err)
	assert.Contains(t, out, `created new DEK term 2 for target algorithm "aes-256-gcm"`)
	assert.Contains(t, out, `migration complete: 0 value(s) re-encrypted under "aes-256-gcm"`)

	kf := caReadKeyringFile(t, f.krPath)
	assert.Equal(t, envelope.AES256GCM, kf.Algorithm)
	assert.Equal(t, 2, kf.ActiveTerm)
	m, err := fb.GetMeta(context.Background(), caPath)
	require.NoError(t, err)
	assert.True(t, m.UpdatedAt.After(now) || m.UpdatedAt.Equal(now))
}

// A failed migration must leave every stored value readable.
func TestMigrateCipherKeepsValuesReadable(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secret := caSecret("migrate")
	f.rotate(t, caPath, []byte(secret))

	out, errOut, err := caRun(t, nil, "migrate", "cipher", "--to", string(envelope.AES256GCM))
	assert.NotContains(t, out+errOut, secret)
	if err != nil {
		assert.Contains(t, errOut, "rolling back")
		assert.Contains(t, err.Error(), "migrate cipher:")
	}

	dispatch.ClearCached()
	got, _, getErr := vault.GetVersion(context.Background(), caPath, 1, f.cfg, f.env)
	require.NoError(t, getErr)
	assert.Equal(t, secret, string(got))
}

func TestMigrateRollbackRestoresBackups(t *testing.T) {
	f := caNewEnv(t)
	p := valuePath(f.vaultDir, caPath, 3)
	assert.Equal(t, filepath.Join(f.vaultDir, "values", "default", "ai", "openrouter", "api_key", "3"), p)
	require.NoError(t, atomicWriteCLI(p, []byte("new-ct")))
	require.NoError(t, atomicWriteCLI(p+".nonce", []byte("new-nonce")))

	cmd := &cobra.Command{}
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)
	origErr := assert.AnError
	err := rollback(cmd, nil, context.Background(),
		[]migrateBackup{{ctPath: p, ct: []byte("old-ct"), nonce: []byte("old-nonce")}}, nil, origErr)
	assert.ErrorIs(t, err, origErr)
	assert.Contains(t, errOut.String(), "rolling back 1 value(s)")

	ct, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "old-ct", string(ct))
	nonce, err := os.ReadFile(p + ".nonce")
	require.NoError(t, err)
	assert.Equal(t, "old-nonce", string(nonce))
	info, err := os.Stat(p)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestMigrateFileHelpersReportErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	assert.Error(t, atomicWriteCLI(filepath.Join(blocker, "x", "y"), []byte("v")))

	assert.ErrorContains(t, updateKeyringAlgorithm(filepath.Join(dir, "missing.json"), envelope.AES256GCM), "read keyring")
	bad := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("{"), 0o600))
	assert.ErrorContains(t, updateKeyringAlgorithm(bad, envelope.AES256GCM), "parse keyring")
}
