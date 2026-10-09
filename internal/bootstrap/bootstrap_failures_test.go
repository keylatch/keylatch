package bootstrap_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mxEnv confines every path bootstrap touches to dir; overrides win.
func mxEnv(dir string, overrides map[string]string) func(string) string {
	return func(k string) string {
		if v, ok := overrides[k]; ok {
			return v
		}
		switch k {
		case "HOME":
			return dir
		case "KEYLATCH_CONFIG_DIR":
			return filepath.Join(dir, ".keylatch")
		}
		return ""
	}
}

func mxSkipDarwinKeychain(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		t.Skip("file-backend keyring creation would consult the macOS keychain")
	}
}

func mxFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plain")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	return p
}

func TestRun_ForceRequiresConfirm(t *testing.T) {
	dir := t.TempDir()
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{IdentityStore: testutil.NewMemoryIdentityStore(), Force: true, Env: mxEnv(dir, nil)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Confirm=true")
	_, statErr := os.Stat(filepath.Join(dir, ".keylatch"))
	assert.True(t, os.IsNotExist(statErr), "nothing may be created before confirmation")
}

func TestRun_UnknownBackend(t *testing.T) {
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{IdentityStore: testutil.NewMemoryIdentityStore(), Backend: "floppy", Env: mxEnv(t.TempDir(), nil)})
	var ub *bootstrap.UnknownBackend
	require.True(t, errors.As(err, &ub))
	assert.Equal(t, "floppy", ub.Backend)
	assert.Contains(t, err.Error(), `unknown backend "floppy": allowed values are`)
	assert.Contains(t, err.Error(), "file")
}

func TestRun_KeychainRejectedOffMacOS(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("keychain is valid on macOS")
	}
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{IdentityStore: testutil.NewMemoryIdentityStore(), Backend: "keychain", Env: mxEnv(t.TempDir(), nil)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "macOS-only")
}

func TestRun_DryRunTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	res, err := bootstrap.Run(context.Background(), bootstrap.Options{IdentityStore: testutil.NewMemoryIdentityStore(), DryRun: true, Env: mxEnv(dir, nil)})
	require.NoError(t, err)
	require.NotEmpty(t, res.Steps)
	for _, s := range res.Steps {
		assert.False(t, s.Done, s.Path)
		assert.NotEqual(t, "noop", s.Action, s.Path)
	}
	_, statErr := os.Stat(filepath.Join(dir, ".keylatch"))
	assert.True(t, os.IsNotExist(statErr))

	text := bootstrap.RenderText(res)
	assert.Contains(t, text, "[planned] mkdir")
	assert.Contains(t, text, "(mode 0700)")
	assert.NotContains(t, text, "Warnings:")
}

func TestRun_ExistingConfigIsNeverOverwritten(t *testing.T) {
	mxSkipDarwinKeychain(t)
	dir := t.TempDir()
	env := mxEnv(dir, nil)
	cfgDir := filepath.Join(dir, ".keylatch")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	cfgPath := filepath.Join(cfgDir, "config.json")

	cases := map[string]struct {
		body    string
		warning string
	}{
		"future version": {`{"version":2}`, "config version mismatch: got 2"},
		"unreadable":     {`{not json`, "is unreadable"},
	}
	for name, tc := range cases {
		require.NoError(t, os.WriteFile(cfgPath, []byte(tc.body), 0o600))
		res, err := bootstrap.Run(context.Background(), bootstrap.Options{IdentityStore: testutil.NewMemoryIdentityStore(), Env: env})
		require.NoError(t, err, name)
		require.Len(t, res.Warnings, 1, name)
		assert.Contains(t, res.Warnings[0], tc.warning)
		got, err := os.ReadFile(cfgPath) //nolint:gosec // temp path
		require.NoError(t, err)
		assert.Equal(t, tc.body, string(got), "existing config must be left untouched")

		text := bootstrap.RenderText(res)
		assert.Contains(t, text, "[skip]")
		assert.Contains(t, text, "Warnings:")
		assert.Contains(t, text, tc.warning)
	}
}

func TestRun_ForceRecreatesKeyMaterial(t *testing.T) {
	mxSkipDarwinKeychain(t)
	dir := t.TempDir()
	env := mxEnv(dir, nil)
	store := testutil.NewMemoryIdentityStore()
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{IdentityStore: store, Env: env})
	require.NoError(t, err)

	krDir := filepath.Join(dir, ".keylatch", "keyring")
	before, err := os.ReadFile(filepath.Join(krDir, "keyring.json"))
	require.NoError(t, err)

	res, err := bootstrap.Run(context.Background(), bootstrap.Options{IdentityStore: store, Env: env, Force: true, Confirm: true})
	require.NoError(t, err)
	after, err := os.ReadFile(filepath.Join(krDir, "keyring.json"))
	require.NoError(t, err)
	assert.NotEqual(t, before, after, "force must rotate the keyring")

	reasons := []string{}
	for _, s := range res.Steps {
		reasons = append(reasons, s.Reason)
	}
	joined := strings.Join(reasons, "\n")
	assert.Contains(t, joined, "force re-create")
	assert.Contains(t, joined, "force re-create keyring.json")
	if runtime.GOOS != "windows" {
		for _, p := range []string{filepath.Join(krDir, "keyring.json")} {
			info, err := os.Stat(p)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), p)
		}
	}

	b, err := bootstrap.RenderJSON(res)
	require.NoError(t, err)
	var decoded bootstrap.Plan
	require.NoError(t, json.Unmarshal(b, &decoded))
	assert.Equal(t, len(res.Steps), len(decoded.Steps))
}

func TestRun_FilesystemConflicts(t *testing.T) {
	cases := map[string]struct {
		overrides func(t *testing.T, dir string) map[string]string
		wantErr   string
	}{
		"config dir is a file": {func(t *testing.T, _ string) map[string]string {
			return map[string]string{"KEYLATCH_CONFIG_DIR": mxFile(t)}
		}, "config dir"},
		"vault under a file": {func(t *testing.T, _ string) map[string]string {
			return map[string]string{"KEYLATCH_VAULT_PATH": filepath.Join(mxFile(t), "vault")}
		}, "vault dir"},
		"audit path is a dir": {func(t *testing.T, _ string) map[string]string {
			return map[string]string{"KEYLATCH_AUDIT_PATH": t.TempDir()}
		}, "audit file"},
		"audit under a file": {func(t *testing.T, _ string) map[string]string {
			return map[string]string{"KEYLATCH_AUDIT_PATH": filepath.Join(mxFile(t), "audit.log")}
		}, "audit file"},
		"config under a file": {func(t *testing.T, _ string) map[string]string {
			return map[string]string{"KEYLATCH_CONFIG": filepath.Join(mxFile(t), "config.json")}
		}, "config file"},
		"keyring dir is a file": {func(t *testing.T, _ string) map[string]string {
			return map[string]string{"KEYLATCH_KEYRING_DIR": mxFile(t)}
		}, "keyring dir"},
		"identity under a file": {func(t *testing.T, _ string) map[string]string {
			return map[string]string{"KEYLATCH_KEYRING_IDENTITY_PATH": filepath.Join(mxFile(t), "id")}
		}, "vault identity"},
		"identity parent missing": {func(t *testing.T, _ string) map[string]string {
			return map[string]string{"KEYLATCH_KEYRING_IDENTITY_PATH": filepath.Join(t.TempDir(), "missing", "id")}
		}, "vault identity"},
		"keyring under a file": {func(t *testing.T, _ string) map[string]string {
			return map[string]string{"KEYLATCH_KEYRING_PATH": filepath.Join(mxFile(t), "keyring.json")}
		}, "keyring"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mxSkipDarwinKeychain(t)
			dir := t.TempDir()
			_, err := bootstrap.Run(context.Background(), bootstrap.Options{IdentityStore: testutil.NewMemoryIdentityStore(), Env: mxEnv(dir, tc.overrides(t, dir))})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestRun_CreatesMissingConfigDirectory(t *testing.T) {
	mxSkipDarwinKeychain(t)
	dir := t.TempDir()
	cfg := filepath.Join(t.TempDir(), "missing", "config.json")
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{IdentityStore: testutil.NewMemoryIdentityStore(), Env: mxEnv(dir, map[string]string{"KEYLATCH_CONFIG": cfg})})
	require.NoError(t, err)
	_, err = os.Stat(cfg)
	require.NoError(t, err)
}
