package bootstrap_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeEnv returns a Lookup that confines all default paths under home.
// KEYLATCH_CONFIG_DIR is set explicitly because os.UserHomeDir follows
// platform-specific variables such as USERPROFILE on Windows.
func makeEnv(home string, overrides map[string]string) llmcontext.Lookup {
	return func(k string) string {
		if v, ok := overrides[k]; ok {
			return v
		}
		switch k {
		case "HOME":
			return home
		case "KEYLATCH_CONFIG_DIR":
			return filepath.Join(home, ".keylatch")
		case "XDG_CONFIG_HOME":
			return ""
		}
		return os.Getenv(k)
	}
}

func TestBootstrap_FreshHome(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	env := makeEnv(tmp, nil)

	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{
		Env: env,
	})
	require.NoError(t, err)

	// All steps should be Done=true.
	for _, s := range plan.Steps {
		if s.Action == "noop" {
			continue
		}
		assert.True(t, s.Done, "step %q %q should be done", s.Action, s.Path)
	}

	// config dir must exist with mode 0o700.
	keylatchDir := paths.ConfigDir(env)
	assertMode(t, keylatchDir, 0o700, true)

	// vault dir must exist with mode 0o700.
	vaultDir := paths.Vault(env)
	assertMode(t, vaultDir, 0o700, true)

	// audit log must exist with mode 0o600.
	auditFile := paths.Audit(env)
	assertMode(t, auditFile, 0o600, false)

	// config.json must exist with mode 0o600.
	configFile := paths.Config(env)
	assertMode(t, configFile, 0o600, false)

	// Keyring files must exist with mode 0o600 (T-02-04).
	krPath := paths.KeyringPath(env)
	assertMode(t, krPath, 0o600, false)

	identityPath := paths.KeyringIdentityPath(env)
	assertMode(t, identityPath, 0o600, false)
}

func TestBootstrap_Idempotent(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	env := makeEnv(tmp, nil)

	// First run.
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env})
	require.NoError(t, err)

	// Second run — all steps should be noop.
	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env})
	require.NoError(t, err)

	for _, s := range plan.Steps {
		assert.Equal(t, "noop", s.Action, "second run step should be noop: %+v", s)
	}
}

func TestBootstrap_DryRun(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	env := makeEnv(tmp, nil)

	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{
		DryRun: true,
		Env:    env,
	})
	require.NoError(t, err)

	// No step should have Done=true (since DryRun=true).
	for _, s := range plan.Steps {
		if s.Action == "noop" {
			continue // noop steps are always Done=true
		}
		assert.False(t, s.Done, "dry-run step should not be done: %+v", s)
	}

	// No files should have been written.
	keylatchDir := paths.ConfigDir(env)
	_, err = os.Stat(keylatchDir)
	assert.True(t, os.IsNotExist(err), "dry-run should not create keylatch dir")
}

func TestBootstrap_UnknownBackend(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, err := bootstrap.Run(context.Background(), bootstrap.Options{
		Backend: "unknown",
		Env:     makeEnv(tmp, nil),
	})
	require.Error(t, err)
	var ub *bootstrap.UnknownBackend
	require.ErrorAs(t, err, &ub)
	assert.Equal(t, "unknown", ub.Backend)
}

func TestBootstrap_BackendPersisted(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	env := makeEnv(tmp, nil)

	_, err := bootstrap.Run(context.Background(), bootstrap.Options{
		Backend: "op",
		Env:     env,
	})
	require.NoError(t, err)

	configFile := paths.Config(env)
	info, err := os.Stat(configFile)
	require.NoError(t, err)
	assertPrivateMode(t, info, 0o600, configFile)
}

func TestBootstrap_RenderJSON(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{
		DryRun: true,
		Env:    makeEnv(tmp, nil),
	})
	require.NoError(t, err)

	b, err := bootstrap.RenderJSON(plan)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"Action"`)
	// Canary check: no canary string in output.
	assert.NotContains(t, string(b), "KEYLATCH_CANARY_DO_NOT_LEAK_0xDEADBEEF")
}

func TestBootstrap_RenderText(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{
		Env: makeEnv(tmp, nil),
	})
	require.NoError(t, err)

	text := bootstrap.RenderText(plan)
	assert.NotEmpty(t, text)
	// Canary check.
	assert.NotContains(t, text, "KEYLATCH_CANARY_DO_NOT_LEAK_0xDEADBEEF")
}

// TestBootstrap_ForceReinit verifies that --force destroys and recreates the keyring.
func TestBootstrap_ForceReinit(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	env := makeEnv(tmp, nil)

	// First run — creates keyring.
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env})
	require.NoError(t, err)

	krPath := paths.KeyringPath(env)
	content1, err := os.ReadFile(krPath)
	require.NoError(t, err)

	// Force re-init — must overwrite the keyring with fresh random material.
	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{
		Env:     env,
		Force:   true,
		Confirm: true,
	})
	require.NoError(t, err)

	// The keyring step must be a writeFile (not noop).
	var foundWrite bool
	for _, s := range plan.Steps {
		if s.Path == krPath && s.Action == "writeFile" {
			foundWrite = true
		}
	}
	assert.True(t, foundWrite, "force re-init must produce a writeFile step for keyring.json")

	content2, err := os.ReadFile(krPath)
	require.NoError(t, err)
	assert.NotEqual(t, content1, content2, "keyring bytes must change after --force re-init")

	info2, err := os.Stat(krPath)
	require.NoError(t, err)
	assertPrivateMode(t, info2, 0o600, krPath)
}

// TestBootstrap_PassphraseEnvIgnored verifies that KEYLATCH_PASSPHRASE has no
// effect on bootstrap. S-FIND-12: the passphrase env var must not be used.
func TestBootstrap_PassphraseEnvIgnored(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("KEYLATCH_PASSPHRASE", "should-not-affect-bootstrap-0xDEADBEEF")

	env := makeEnv(tmp, map[string]string{
		"KEYLATCH_PASSPHRASE": "should-not-affect-bootstrap-0xDEADBEEF",
	})

	// Bootstrap must succeed despite the passphrase env var being set.
	plan, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env})
	require.NoError(t, err, "bootstrap must not use KEYLATCH_PASSPHRASE")

	// The keyring must be created normally.
	krPath := paths.KeyringPath(env)
	assertMode(t, krPath, 0o600, false)

	// No step reason should reference the passphrase.
	for _, s := range plan.Steps {
		assert.NotContains(t, s.Reason, "passphrase",
			"bootstrap step must not reference passphrase: %+v", s)
	}
}

// assertMode checks file/dir mode.
func assertMode(t *testing.T, p string, wantPerm os.FileMode, isDir bool) {
	t.Helper()
	info, err := os.Stat(p)
	require.NoError(t, err, "expected path to exist: %s", p)
	assert.Equal(t, isDir, info.IsDir(), "is dir mismatch for %s", p)
	assertPrivateMode(t, info, wantPerm, p)
}

func assertPrivateMode(t *testing.T, info os.FileInfo, wantPerm os.FileMode, p string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	assert.Equal(t, wantPerm, info.Mode().Perm(), "mode mismatch for %s", p)
}
