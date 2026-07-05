package paths_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/paths"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeEnv returns a Lookup that reads from the given map.
func makeEnv(m map[string]string) paths.Lookup {
	return func(k string) string { return m[k] }
}

// noEnv returns a Lookup that always returns empty string.
func noEnv() paths.Lookup {
	return func(k string) string { return "" }
}

// homeBoundEnv returns a Lookup that sets HOME to the given dir and returns
// empty for everything else.
func homeBoundEnv(home string) paths.Lookup {
	// We override HOME via os.Setenv in tests; this Lookup just acts as no-op.
	return noEnv()
}

// withHome sets HOME (and USERPROFILE on Windows) to tmp for the duration of the test.
// os.UserHomeDir() uses USERPROFILE on Windows, not HOME.
func withHome(t *testing.T, tmp string) {
	t.Helper()
	t.Setenv("HOME", tmp)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tmp)
	}
}

func TestConfigDir_Default(t *testing.T) {
	tmp := t.TempDir()
	withHome(t, tmp)

	dir := paths.ConfigDir(noEnv())

	// Must be absolute.
	assert.True(t, filepath.IsAbs(dir), "ConfigDir must be absolute")

	// Must not contain hardcoded /Users/ or /home/<name>/ fragments that
	// would be wrong on another machine — it should contain tmp.
	assert.Contains(t, dir, tmp, "ConfigDir should be under tmp home")

	// Must not be the raw HOME — should have a subdirectory.
	assert.NotEqual(t, tmp, dir)
}

func TestConfigDir_EnvOverride(t *testing.T) {
	tmp := t.TempDir()
	env := makeEnv(map[string]string{"KEYLATCH_CONFIG_DIR": tmp})
	assert.Equal(t, tmp, paths.ConfigDir(env))
}

func TestConfigDir_LinuxXDG(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG check is Linux-only")
	}
	xdg := t.TempDir()
	env := makeEnv(map[string]string{"XDG_CONFIG_HOME": xdg})
	got := paths.ConfigDir(env)
	assert.Equal(t, filepath.Join(xdg, "keylatch"), got)
}

func TestConfig_Default(t *testing.T) {
	tmp := t.TempDir()
	withHome(t, tmp)
	p := paths.Config(noEnv())
	assert.True(t, filepath.IsAbs(p))
	assert.True(t, strings.HasSuffix(p, "config.json"))
}

func TestConfig_EnvOverride(t *testing.T) {
	want := "/tmp/custom-config.json"
	env := makeEnv(map[string]string{"KEYLATCH_CONFIG": want})
	assert.Equal(t, want, paths.Config(env))
}

func TestVault_Default(t *testing.T) {
	tmp := t.TempDir()
	withHome(t, tmp)
	p := paths.Vault(noEnv())
	assert.True(t, filepath.IsAbs(p))
	assert.True(t, strings.HasSuffix(p, "vault"))
}

func TestVault_EnvOverride(t *testing.T) {
	want := "/tmp/custom-vault"
	env := makeEnv(map[string]string{"KEYLATCH_VAULT_PATH": want})
	assert.Equal(t, want, paths.Vault(env))
}

func TestAudit_Default(t *testing.T) {
	tmp := t.TempDir()
	withHome(t, tmp)
	p := paths.Audit(noEnv())
	assert.True(t, filepath.IsAbs(p))
	assert.True(t, strings.HasSuffix(p, "audit.log"))
}

func TestAudit_EnvOverride(t *testing.T) {
	want := "/tmp/custom-audit.log"
	env := makeEnv(map[string]string{"KEYLATCH_AUDIT_PATH": want})
	assert.Equal(t, want, paths.Audit(env))
}

func TestAuditSalt_Default(t *testing.T) {
	tmp := t.TempDir()
	withHome(t, tmp)
	p := paths.AuditSalt(noEnv())
	assert.True(t, filepath.IsAbs(p))
	assert.True(t, strings.HasSuffix(p, "audit-salt"))
}

func TestAuditSalt_EnvOverride(t *testing.T) {
	want := "/tmp/custom-salt"
	env := makeEnv(map[string]string{"KEYLATCH_AUDIT_SALT_PATH": want})
	assert.Equal(t, want, paths.AuditSalt(env))
}

func TestPolicy_Default(t *testing.T) {
	tmp := t.TempDir()
	withHome(t, tmp)
	p := paths.Policy(noEnv())
	assert.True(t, filepath.IsAbs(p))
	assert.True(t, strings.HasSuffix(p, "policy.json"))
}

func TestPolicy_EnvOverride(t *testing.T) {
	want := "/tmp/custom-policy.json"
	env := makeEnv(map[string]string{"KEYLATCH_POLICY_PATH": want})
	assert.Equal(t, want, paths.Policy(env))
}

func TestAssertSafeModes_File600(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "testfile")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	assert.NoError(t, paths.AssertSafeModes(p))
}

func TestAssertSafeModes_Dir700(t *testing.T) {
	tmp := t.TempDir()
	d := filepath.Join(tmp, "testdir")
	require.NoError(t, os.Mkdir(d, 0o700))
	assert.NoError(t, paths.AssertSafeModes(d))
}

func TestAssertSafeModes_File644_Error(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows NTFS does not enforce Unix permission bits")
	}
	tmp := t.TempDir()
	p := filepath.Join(tmp, "insecure")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o644))
	err := paths.AssertSafeModes(p)
	require.Error(t, err)
	var um *paths.UnsafeMode
	require.ErrorAs(t, err, &um)
	assert.Equal(t, p, um.Path)
}

func TestAssertSafeModes_Dir755_Error(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows NTFS does not enforce Unix permission bits")
	}
	tmp := t.TempDir()
	d := filepath.Join(tmp, "insecuredir")
	require.NoError(t, os.Mkdir(d, 0o755))
	err := paths.AssertSafeModes(d)
	require.Error(t, err)
	var um *paths.UnsafeMode
	require.ErrorAs(t, err, &um)
}

func TestAssertSafeModes_NotFound(t *testing.T) {
	err := paths.AssertSafeModes("/tmp/keylatch-nonexistent-path-xyzzy")
	require.Error(t, err)
	var pnf *paths.PathNotFound
	require.ErrorAs(t, err, &pnf)
}

func TestNoHardcodedPaths(t *testing.T) {
	// Resolved paths must not contain hardcoded /Users/ or /home/<name>.
	// We prove this by checking that when HOME=t.TempDir(), none of the
	// resolved paths contain the literal string "/Users/" from a test machine.
	tmp := t.TempDir()
	withHome(t, tmp)
	env := homeBoundEnv(tmp)

	allPaths := []string{
		paths.ConfigDir(env),
		paths.Config(env),
		paths.Vault(env),
		paths.Audit(env),
		paths.AuditSalt(env),
		paths.Policy(env),
	}
	for _, p := range allPaths {
		assert.NotContains(t, p, "/Users/patrikmichalicka",
			"resolved path must not contain hardcoded home: %s", p)
		assert.NotContains(t, p, "/home/patrikmichalicka",
			"resolved path must not contain hardcoded home: %s", p)
	}
}

func TestForwardCompatConstants(t *testing.T) {
	// Just ensure constants are non-empty.
	assert.NotEmpty(t, paths.EnvTrustAllowlistPath)
	assert.NotEmpty(t, paths.EnvTeamDir)
	assert.NotEmpty(t, paths.EnvOrgPolicyDir)
}
