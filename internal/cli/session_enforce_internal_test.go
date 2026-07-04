package cli

// session_enforce_internal_test.go — white-box tests for
// configAllowsUnverifiedSession, the config.json half of the
// raw-credential session gate's escape hatch (docker-server-security
// hardening). Package cli (not cli_test) because
// configAllowsUnverifiedSession is unexported.

import (
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigAllowsUnverifiedSession_MissingConfig_FailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	env := func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return ""
	}
	// No config.json written — Load errors — must fail closed (false).
	assert.False(t, configAllowsUnverifiedSession(env))
}

func TestConfigAllowsUnverifiedSession_FieldTrue_Allowed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cfg := config.Default()
	cfg.AllowUnverifiedSession = true
	require.NoError(t, config.Save(cfgPath, cfg))

	env := func(k string) string {
		if k == "KEYLATCH_CONFIG" {
			return cfgPath
		}
		return ""
	}
	assert.True(t, configAllowsUnverifiedSession(env))
}

func TestConfigAllowsUnverifiedSession_FieldFalse_NotAllowed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cfg := config.Default() // AllowUnverifiedSession defaults false
	require.NoError(t, config.Save(cfgPath, cfg))

	env := func(k string) string {
		if k == "KEYLATCH_CONFIG" {
			return cfgPath
		}
		return ""
	}
	assert.False(t, configAllowsUnverifiedSession(env))
}
