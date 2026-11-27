//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// caFakeTools writes each script as an executable into a fresh
// directory that becomes the whole PATH.
func caFakeTools(t *testing.T, scripts map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700))
	}
	t.Setenv("PATH", dir)
}

func caSkipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
}

func TestKeyringInitAndRotateWithPasswordManagerKEKs(t *testing.T) {
	f := caNewEnv(t)
	opKey := strings.Repeat("a1", 32)
	bwKey := strings.Repeat("c3", 32)
	caFakeTools(t, map[string]string{
		"op": `[ "$1" = read ] && [ "$2" = "op://Private/keylatch/kek" ] && echo ` + opKey + ` && exit 0
exit 1`,
		"bw": `[ "$1" = get ] && [ "$3" = item-1 ] && echo '{"fields":[{"name":"kek","value":"` + bwKey + `"}]}' && exit 0
exit 1`,
	})
	t.Setenv("BW_SESSION", "session")

	out, _, err := caRun(t, nil, "keyring", "init", "--kek", "op:Private/keylatch/kek")
	require.NoError(t, err)
	assert.Contains(t, out, "keyring initialized at "+f.krPath)
	before := caReadKeyringFile(t, f.krPath)
	require.NotEmpty(t, before.Terms)

	_, _, err = caRun(t, nil, "keyring", "init", "--kek", "op:Private/other/kek")
	require.NoError(t, err, "existing keyring short-circuits before the KEK is built")

	// rotate-kek needs to unlock the current keyring first: no age identity
	// exists and stdin is empty, so it must refuse.
	caSwapStdin(t, "")
	_, _, err = caRun(t, nil, "keyring", "rotate-kek", "--to", "bw:item-1/kek")
	require.Error(t, err)
	assert.Equal(t, before.Terms, caReadKeyringFile(t, f.krPath).Terms)
}

func TestKeyringRotateKEKToBitwarden(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	before := caReadKeyringFile(t, f.krPath)
	bwKey := strings.Repeat("d4", 32)
	caFakeTools(t, map[string]string{
		"bw": `echo '{"fields":[{"name":"kek","value":"` + bwKey + `"}]}'`,
	})
	t.Setenv("BW_SESSION", "session")

	out, _, err := caRun(t, nil, "keyring", "rotate-kek", "--to", "bw:item-1/kek")
	require.NoError(t, err)
	assert.Contains(t, out, "KEK rotated successfully")
	assert.NotEqual(t, before.Terms[0].WrappedDEK, caReadKeyringFile(t, f.krPath).Terms[0].WrappedDEK)
}

func TestKeyringPasswordManagerKEKFailures(t *testing.T) {
	caNewEnv(t)
	caFakeTools(t, map[string]string{"op": "exit 1", "bw": "exit 1"})
	t.Setenv("BW_SESSION", "session")

	_, _, err := caRun(t, nil, "keyring", "init", "--kek", "op:v/i/f")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "op read failed")

	_, _, err = caRun(t, nil, "keyring", "init", "--kek", "bw:item/field")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bw get item failed")

	_, _, err = caRun(t, nil, "keyring", "init", "--kek", "keychain")
	require.Error(t, err)
}

func TestKeyringWritesFailOnReadOnlyDir(t *testing.T) {
	caSkipIfRoot(t)
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	krDir := filepath.Dir(f.krPath)
	require.NoError(t, os.Chmod(krDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(krDir, 0o700) })
	before, err := os.ReadFile(f.krPath)
	require.NoError(t, err)

	_, _, err = caRun(t, nil, "keyring", "rotate-term")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotate-term:")

	newIdentity := filepath.Join(f.root, "identity-2")
	caWriteIdentity(t, newIdentity)
	t.Setenv("KEYLATCH_AGE_IDENTITY", newIdentity)
	_, _, err = caRun(t, nil, "keyring", "rotate-kek", "--to", "age-env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotate-kek:")

	after, err := os.ReadFile(f.krPath)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestKeyringInitFailsOnReadOnlyKeyringDir(t *testing.T) {
	caSkipIfRoot(t)
	f := caNewEnv(t)
	caWriteIdentity(t, f.identity)
	krDir := filepath.Dir(f.krPath)
	require.NoError(t, os.MkdirAll(krDir, 0o700))
	require.NoError(t, os.Chmod(krDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(krDir, 0o700) })

	_, _, err := caRun(t, nil, "keyring", "init", "--kek", "age-env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keyring init:")
	_, statErr := os.Stat(f.krPath)
	assert.True(t, os.IsNotExist(statErr))
}

func TestSetCmdUnreadableStdin(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	dirFile, err := os.Open(f.root)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dirFile.Close() })
	_, _, err = caRun(t, dirFile, "set", caPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading stdin")
}

func TestAuditOpenFailsWhenLogPathIsADirectory(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	logDir := filepath.Join(f.root, "audit-as-dir")
	require.NoError(t, os.MkdirAll(logDir, 0o700))
	t.Setenv("KEYLATCH_AUDIT_PATH", logDir)
	_, _, err := caRun(t, nil, "audit")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit: open")
}
