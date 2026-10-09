package doctor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/testutil"
)

func kekCheckEnv(t *testing.T, extra map[string]string) func(string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "keyring"), 0o700))
	return func(k string) string {
		if v, ok := extra[k]; ok {
			return v
		}
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return ""
	}
}

func writeIdentity(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, make([]byte, 32), 0o600))
}

func TestCheckPlaintextKEK(t *testing.T) {
	ctx := context.Background()

	t.Run("keyring", func(t *testing.T) {
		env := kekCheckEnv(t, nil)
		vi := kek.VaultIdentity{Path: paths.KeyringIdentityPath(env), Store: testutil.NewMemoryIdentityStore()}
		require.NoError(t, vi.Provision(false))
		st := checkPlaintextKEK(env)(ctx)
		assert.True(t, st.OK)
		assert.False(t, st.Warn)
	})

	t.Run("unacknowledged file fails", func(t *testing.T) {
		env := kekCheckEnv(t, nil)
		writeIdentity(t, paths.KeyringIdentityPath(env))
		st := checkPlaintextKEK(env)(ctx)
		assert.False(t, st.OK)
		assert.Contains(t, st.Detail, "plaintext KEK on disk")
		assert.Contains(t, st.Fix, "--insecure-file-kek")
	})

	t.Run("acknowledged file warns", func(t *testing.T) {
		env := kekCheckEnv(t, nil)
		vi := kek.VaultIdentity{Path: paths.KeyringIdentityPath(env)}
		require.NoError(t, vi.Provision(true))
		st := checkPlaintextKEK(env)(ctx)
		assert.True(t, st.OK)
		assert.True(t, st.Warn)
		assert.Contains(t, st.Detail, "plaintext KEK on disk")
	})

	t.Run("leftover file beside keyring fails", func(t *testing.T) {
		env := kekCheckEnv(t, nil)
		vi := kek.VaultIdentity{Path: paths.KeyringIdentityPath(env), Store: testutil.NewMemoryIdentityStore()}
		require.NoError(t, vi.Provision(false))
		writeIdentity(t, vi.Path)
		st := checkPlaintextKEK(env)(ctx)
		assert.False(t, st.OK)
		assert.Contains(t, st.Detail, "plaintext KEK on disk")
	})

	t.Run("operator identity warns", func(t *testing.T) {
		env := kekCheckEnv(t, map[string]string{"KEYLATCH_AGE_IDENTITY": "/media/token/identity"})
		st := checkPlaintextKEK(env)(ctx)
		assert.True(t, st.OK)
		assert.True(t, st.Warn)
	})

	t.Run("other backend not applicable", func(t *testing.T) {
		env := kekCheckEnv(t, nil)
		writeIdentity(t, paths.KeyringIdentityPath(env))
		cfg := config.Default()
		cfg.Backend = "op"
		require.NoError(t, config.Save(paths.Config(env), cfg))
		st := checkPlaintextKEK(env)(ctx)
		assert.True(t, st.OK)
		assert.False(t, st.Warn)
	})
}
