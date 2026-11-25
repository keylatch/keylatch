package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupHermeticConfig_RedirectsConfigDir(t *testing.T) {
	dir := SetupHermeticConfig(t)
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, dir, os.Getenv("KEYLATCH_CONFIG_DIR"))
	assert.Equal(t, dir, paths.ConfigDir(llmcontext.DefaultLookup))
}

func TestSetupTestKeyring_CreatesUsableKeyring(t *testing.T) {
	krPath := SetupTestKeyring(t)
	assert.Equal(t, krPath, os.Getenv("KEYLATCH_KEYRING_PATH"))

	identity := os.Getenv("KEYLATCH_AGE_IDENTITY")
	require.NotEmpty(t, identity)
	idBytes, err := os.ReadFile(identity) //nolint:gosec // path comes from the helper under test
	require.NoError(t, err)
	assert.Len(t, idBytes, 32)
	assert.NotEqual(t, filepath.Dir(identity), filepath.Dir(krPath), "identity and keyring live in separate dirs")

	if runtime.GOOS != "windows" {
		for _, p := range []string{identity, krPath} {
			info, statErr := os.Stat(p)
			require.NoError(t, statErr)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), p)
		}
	}

	raw, err := os.ReadFile(krPath) //nolint:gosec // path comes from the helper under test
	require.NoError(t, err)
	var kf keyring.KeyringFile
	require.NoError(t, json.Unmarshal(raw, &kf))
	require.Len(t, kf.Salt, 32)

	// The keyring must open with a KEK re-derived from the same identity + salt.
	k, err := kek.EnvAgeIdentityKEK(kf.Salt)
	require.NoError(t, err)
	kr, err := keyring.Open(krPath, k)
	require.NoError(t, err)
	defer kr.Zero()
	dek, _, err := kr.ActiveDEK()
	require.NoError(t, err)
	assert.Len(t, dek, 32)
}

func TestSetupTestKeyring_IndependentPerCall(t *testing.T) {
	first := SetupTestKeyring(t)
	second := SetupTestKeyring(t)
	assert.NotEqual(t, first, second)
	assert.Equal(t, second, os.Getenv("KEYLATCH_KEYRING_PATH"))
}

func TestClearLLMSessionEnv_BlanksSignals(t *testing.T) {
	require.NotEmpty(t, llmcontext.Signals)
	for _, sig := range llmcontext.Signals {
		t.Setenv(sig.EnvKey, "1")
	}
	t.Setenv(llmcontext.TicketEnv, "ticket")

	ClearLLMSessionEnv(t)

	for _, sig := range llmcontext.Signals {
		assert.Empty(t, os.Getenv(sig.EnvKey), sig.EnvKey)
	}
	assert.Empty(t, os.Getenv(llmcontext.TicketEnv))
	assert.False(t, llmcontext.IsLLMSession(llmcontext.DefaultLookup))
}
