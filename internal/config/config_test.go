package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	c := config.Default()
	assert.Equal(t, 1, c.Version)
	assert.Equal(t, "file", c.Backend)
	assert.Equal(t, "default", c.DefaultNamespace)
	assert.True(t, c.Audit.Enabled)
	assert.Equal(t, int64(5*1024*1024), c.Audit.MaxSize)
	assert.Equal(t, "127.0.0.1", c.UI.Bind)
}

// TestDefault_AllowUnverifiedSessionDefaultsFalse covers the raw-credential
// session gate's config-file escape hatch (docker-server-security hardening): it must default to false
// (fail closed) so a fresh install never silently opts out of session
// corroboration on raw-credential paths.
func TestDefault_AllowUnverifiedSessionDefaultsFalse(t *testing.T) {
	c := config.Default()
	assert.False(t, c.AllowUnverifiedSession)
}

// TestSaveAndLoad_RoundTrip_AllowUnverifiedSession verifies the new
// allow_unverified_session field round-trips through Save/Load, so a
// permanent operator opt-out actually persists.
func TestSaveAndLoad_RoundTrip_AllowUnverifiedSession(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "config.json")

	orig := config.Default()
	orig.AllowUnverifiedSession = true

	require.NoError(t, config.Save(p, orig))

	loaded, err := config.Load(p)
	require.NoError(t, err)
	assert.True(t, loaded.AllowUnverifiedSession)
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "config.json")

	orig := config.Default()
	orig.Backend = "op"
	orig.DefaultNamespace = "work"

	require.NoError(t, config.Save(p, orig))

	// Mode must be 0o600.
	info, err := os.Stat(p)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	loaded, err := config.Load(p)
	require.NoError(t, err)
	assert.Equal(t, orig, loaded)
}

func TestLoad_UnknownFieldsRejected(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "config.json")
	// Write a config with an unknown field (canary test for unknown-field rejection).
	data := `{"version":1,"backend":"file","default_namespace":"default","audit":{"enabled":true,"max_size_bytes":5242880},"ui":{"bind":"127.0.0.1"},"KEYLATCH_CANARY_DO_NOT_LEAK_0xDEADBEEF":"canary"}`
	require.NoError(t, os.WriteFile(p, []byte(data), 0o600))

	_, err := config.Load(p)
	require.Error(t, err, "unknown fields must be rejected")
	// The error should mention that there's an unknown field (not silently ignored).
	assert.Contains(t, err.Error(), "unknown field")
}

func TestLoad_VersionMismatch(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "config.json")
	data := `{"version":99,"backend":"file","default_namespace":"default","audit":{"enabled":true,"max_size_bytes":5242880},"ui":{"bind":"127.0.0.1"}}`
	require.NoError(t, os.WriteFile(p, []byte(data), 0o600))

	_, err := config.Load(p)
	require.Error(t, err)

	var vm *config.VersionMismatch
	require.ErrorAs(t, err, &vm)
	assert.Equal(t, 99, vm.Got)
	assert.Equal(t, 1, vm.Want)
}

func TestSave_AtomicWrite(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "config.json")

	c := config.Default()
	require.NoError(t, config.Save(p, c))

	// Second save overwrites without error.
	c.Backend = "bw"
	require.NoError(t, config.Save(p, c))

	loaded, err := config.Load(p)
	require.NoError(t, err)
	assert.Equal(t, "bw", loaded.Backend)
}

func TestAuditConfig_SweepIntervalHours_Negative(t *testing.T) {
	// Negative SweepIntervalHours must be rejected with an actionable error.
	a := config.AuditConfig{
		Enabled:            true,
		MaxSize:            5 * 1024 * 1024,
		RetentionDays:      30,
		SweepIntervalHours: -1,
	}
	err := a.Validate()
	require.Error(t, err, "SweepIntervalHours=-1 should be rejected")
	assert.Contains(t, err.Error(), "sweep_interval_hours")
}

func TestAuditConfig_SweepIntervalHours_Zero_IsValid(t *testing.T) {
	// Zero means "use the default" — must pass validation.
	a := config.AuditConfig{
		Enabled:            true,
		MaxSize:            5 * 1024 * 1024,
		RetentionDays:      30,
		SweepIntervalHours: 0,
	}
	require.NoError(t, a.Validate(), "SweepIntervalHours=0 should be valid (means use default)")
}

func TestValidateSetKey_Blocked(t *testing.T) {
	blocked := []string{
		"password", "PASSWORD", "my_password",
		"secret", "SECRET_TOKEN", "api_secret",
		"token", "TOKEN", "access_token",
		"key", "KEY", "api_key",
		"dek", "DEK", "data_dek",
		"wrap", "WRAP_KEY",
		"salt", "audit_salt",
		"nonce",
	}
	for _, k := range blocked {
		t.Run(k, func(t *testing.T) {
			err := config.ValidateSetKey(k)
			require.Error(t, err, "key %q should be blocked", k)
			var bck *config.BlockedConfigKey
			require.ErrorAs(t, err, &bck)
			assert.Equal(t, k, bck.Key)
		})
	}
}

func TestValidateSetKey_Allowed(t *testing.T) {
	allowed := []string{
		"backend", "default_namespace", "gateway_mode",
		"ui_bind", "audit_enabled",
	}
	for _, k := range allowed {
		t.Run(k, func(t *testing.T) {
			assert.NoError(t, config.ValidateSetKey(k), "key %q should be allowed", k)
		})
	}
}

func TestDetectCredentialShape(t *testing.T) {
	credentialValues := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"sk-proj-abcdefghijklmnopqrstuvwx",
		"ghp_abcdefghijklmnopqrstuvwxyz1234",
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	}
	for _, v := range credentialValues {
		t.Run(v[:min(len(v), 20)], func(t *testing.T) {
			assert.True(t, config.DetectCredentialShape(v), "should detect credential shape: %q", v)
		})
	}

	nonCredentials := []string{
		"file",
		"default",
		"127.0.0.1",
		"http://localhost:7878",
		"Keylatch",
	}
	for _, v := range nonCredentials {
		t.Run(v, func(t *testing.T) {
			assert.False(t, config.DetectCredentialShape(v), "should not detect credential shape: %q", v)
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
