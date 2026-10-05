package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func caReadKeyringFile(t *testing.T, path string) keyring.KeyringFile {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var kf keyring.KeyringFile
	require.NoError(t, json.Unmarshal(data, &kf))
	return kf
}

func TestKeyringInitAgeEnvIsIdempotent(t *testing.T) {
	f := caNewEnv(t)
	caWriteIdentity(t, f.identity)

	out, _, err := caRun(t, nil, "keyring", "init", "--kek", "age-env")
	require.NoError(t, err)
	assert.Contains(t, out, "keyring initialized at "+f.krPath+" (algorithm: xchacha20-poly1305)")

	info, err := os.Stat(f.krPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	before, err := os.ReadFile(f.krPath)
	require.NoError(t, err)
	kf := caReadKeyringFile(t, f.krPath)
	assert.Len(t, kf.Salt, 32)
	assert.Equal(t, 1, kf.ActiveTerm)

	out, _, err = caRun(t, nil, "keyring", "init", "--kek", "age-env")
	require.NoError(t, err)
	assert.Contains(t, out, "keyring already initialized at "+f.krPath)
	after, err := os.ReadFile(f.krPath)
	require.NoError(t, err)
	assert.Equal(t, before, after, "second init must not rewrite the keyring")
}

func TestKeyringInitFIPSUsesAESGCM(t *testing.T) {
	f := caNewEnv(t)
	caWriteIdentity(t, f.identity)

	out, _, err := caRun(t, nil, "keyring", "init", "--kek", "age-env", "--fips")
	require.NoError(t, err)
	assert.Contains(t, out, "(algorithm: aes-256-gcm)")
	kf := caReadKeyringFile(t, f.krPath)
	assert.Equal(t, envelope.AES256GCM, kf.Algorithm)
	require.NotNil(t, kf.GCMState)

	out, _, err = caRun(t, nil, "keyring", "status")
	require.NoError(t, err)
	assert.Contains(t, out, "algorithm: aes-256-gcm")
	assert.Contains(t, out, "gcm_nonce_counters:")
}

func TestKeyringInitRejectsBadKEKSpecs(t *testing.T) {
	tests := []struct {
		spec string
		want string
	}{
		{"hsm", `unsupported KEK spec: "hsm"`},
		{"op:vault-only", "op KEK spec must be op:<vault>/<item>/<field>"},
		{"bw:item-only", "bw KEK spec must be bw:<itemID>/<field>"},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			f := caNewEnv(t)
			_, _, err := caRun(t, nil, "keyring", "init", "--kek", tc.spec)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			_, statErr := os.Stat(f.krPath)
			assert.True(t, os.IsNotExist(statErr), "failed init must not leave a keyring behind")
		})
	}
}

func TestKeyringInitAgeEnvWithoutIdentityFails(t *testing.T) {
	f := caNewEnv(t)
	_, _, err := caRun(t, nil, "keyring", "init", "--kek", "age-env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keyring init:")
	_, statErr := os.Stat(f.krPath)
	assert.True(t, os.IsNotExist(statErr))
}

func TestKeyringInitMkdirFailure(t *testing.T) {
	f := caNewEnv(t)
	require.NoError(t, os.WriteFile(f.vaultDir, []byte("not a dir"), 0o600))
	_, _, err := caRun(t, nil, "keyring", "init", "--kek", "age-env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keyring init: mkdir")
}

func TestKeyringPassphraseInitAndReopen(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2id derivation is slow")
	}
	f := caNewEnv(t)
	pass := "correct horse " + strings.Repeat("b", 8)

	caSwapStdin(t, pass+"\n")
	out, _, err := caRun(t, nil, "keyring", "init")
	require.NoError(t, err)
	assert.Contains(t, out, "keyring initialized at")
	assert.NotContains(t, out, pass)

	// No identity file exists, so status falls back to the passphrase on stdin.
	caSwapStdin(t, pass+"\n")
	out, _, err = caRun(t, nil, "keyring", "status")
	require.NoError(t, err)
	assert.Contains(t, out, "keyring: "+f.krPath)
	assert.Contains(t, out, "active_term: 1")

	caSwapStdin(t, "wrong passphrase\n")
	_, _, err = caRun(t, nil, "keyring", "status")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status: open keyring")
}

func TestKeyringStatusRotateAndDestroyTerm(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)

	out, _, err := caRun(t, nil, "keyring", "status")
	require.NoError(t, err)
	assert.Contains(t, out, "keyring: "+f.krPath)
	assert.Contains(t, out, "algorithm: xchacha20-poly1305")
	assert.Contains(t, out, "active_term: 1")
	assert.Contains(t, out, "  term 1: active")
	assert.NotContains(t, out, "gcm_nonce_counters")

	out, _, err = caRun(t, nil, "keyring", "rotate-term")
	require.NoError(t, err)
	assert.Contains(t, out, "rotated to term 2")
	assert.Equal(t, 2, caReadKeyringFile(t, f.krPath).ActiveTerm)

	_, _, err = caRun(t, nil, "keyring", "destroy-term", "two")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `destroy-term: invalid term "two"`)

	out, _, err = caRun(t, strings.NewReader("nope\n"), "keyring", "destroy-term", "1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destroy-term: aborted")
	assert.Contains(t, out, "This is irreversible.")

	_, _, err = caRun(t, strings.NewReader("destroy\n"), "keyring", "destroy-term", "2")
	require.Error(t, err, "the active term must not be destroyable")

	out, _, err = caRun(t, strings.NewReader("destroy\n"), "keyring", "destroy-term", "1")
	require.NoError(t, err)
	assert.Contains(t, out, "term 1 destroyed")
	kf := caReadKeyringFile(t, f.krPath)
	for _, tr := range kf.Terms {
		if tr.Term == 1 {
			assert.Equal(t, keyring.TermDestroyed, tr.Status)
		}
	}
}

func TestKeyringDestroyTermBlockedInLLMSession(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	_, _, err := caRun(t, nil, "keyring", "rotate-term")
	require.NoError(t, err)
	before, err := os.ReadFile(f.krPath)
	require.NoError(t, err)

	caSetLLMSession(t)
	_, _, err = caRun(t, strings.NewReader("destroy\n"), "keyring", "destroy-term", "1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked in LLM session")
	after, err := os.ReadFile(f.krPath)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestKeyringRotateKEKToNewIdentity(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	before := caReadKeyringFile(t, f.krPath)

	_, _, err := caRun(t, nil, "keyring", "rotate-kek")
	require.Error(t, err, "--to is required")

	_, _, err = caRun(t, nil, "keyring", "rotate-kek", "--to", "bogus")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotate-kek: build new KEK")

	newIdentity := filepath.Join(f.root, "identity-new")
	caWriteIdentity(t, newIdentity)
	t.Setenv("KEYLATCH_AGE_IDENTITY", newIdentity)
	out, _, err := caRun(t, nil, "keyring", "rotate-kek", "--to", "age-env")
	require.NoError(t, err)
	assert.Contains(t, out, "KEK rotated successfully")

	after := caReadKeyringFile(t, f.krPath)
	assert.Equal(t, before.ActiveTerm, after.ActiveTerm, "DEK terms are unchanged by a KEK rotation")
	assert.NotEqual(t, before.Terms[0].WrappedDEK, after.Terms[0].WrappedDEK)

	// The old identity can no longer unwrap the keyring; status must fail
	// closed (it then falls back to the passphrase prompt, which is empty).
	t.Setenv("KEYLATCH_AGE_IDENTITY", f.identity)
	caSwapStdin(t, "")
	_, _, err = caRun(t, nil, "keyring", "status")
	require.Error(t, err)

	require.NoError(t, os.Rename(newIdentity, f.identity))
	out, _, err = caRun(t, nil, "keyring", "status")
	require.NoError(t, err)
	assert.Contains(t, out, "active_term: 1")
}

func TestKeyringCommandsWithoutKeyring(t *testing.T) {
	caNewEnv(t)
	for _, args := range [][]string{
		{"keyring", "status"},
		{"keyring", "rotate-term"},
		{"keyring", "rotate-kek", "--to", "age-env"},
		{"keyring", "destroy-term", "1"},
	} {
		_, _, err := caRun(t, nil, args...)
		require.Error(t, err, args)
		assert.Contains(t, err.Error(), "open keyring", args)
	}
}

func TestKeyringStatusRejectsCorruptKeyring(t *testing.T) {
	f := caNewEnv(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(f.krPath), 0o700))
	require.NoError(t, os.WriteFile(f.krPath, []byte("{not json"), 0o600))
	caSwapStdin(t, "")
	_, _, err := caRun(t, nil, "keyring", "status")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "passphrase")
}

func TestBuildKEKPassphraseNeedsSaltedKeyring(t *testing.T) {
	f := caNewEnv(t)
	_, err := buildKEK(t.Context(), "passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read keyring for salt")

	require.NoError(t, os.MkdirAll(filepath.Dir(f.krPath), 0o700))
	require.NoError(t, os.WriteFile(f.krPath, []byte("{"), 0o600))
	_, err = buildKEK(t.Context(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse keyring")

	require.NoError(t, os.WriteFile(f.krPath, []byte(`{"schema_version":2}`), 0o600))
	_, err = buildKEK(t.Context(), "passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keyring file missing salt")

	caSwapStdin(t, "")
	_, err = buildKEKWithSalt(t.Context(), "passphrase", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read passphrase")

	caSwapStdin(t, "pw")
	_, err = buildKEKWithSalt(t.Context(), "passphrase", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "salt must not be empty")
}

func TestBuildKEKAgeEnvLoadsSaltFromKeyring(t *testing.T) {
	f := caNewEnv(t)
	_, err := buildKEK(t.Context(), "age-env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "age-env: read keyring for salt")

	require.NoError(t, os.MkdirAll(filepath.Dir(f.krPath), 0o700))
	require.NoError(t, os.WriteFile(f.krPath, []byte("["), 0o600))
	_, err = buildKEK(t.Context(), "age-env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "age-env: parse keyring")
}
