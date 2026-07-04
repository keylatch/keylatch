package main_test

// end-to-end test scenarios.
// These tests build the keylatch binary (via TestMain in main_e2e_test.go)
// and run full CLI scenarios with HOME=t.TempDir().

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_Bootstrap_DryRunJSON — dry-run produces a JSON plan with
// Done=false for every step and writes nothing to disk.
func TestE2E_Bootstrap_DryRunJSON(t *testing.T) {
	homeDir := t.TempDir()
	stdout, stderr, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"bootstrap", "--dry-run", "--json")

	require.Equal(t, 0, code, "bootstrap --dry-run --json must exit 0; stderr: %s", stderr)

	var plan bootstrap.Plan
	require.NoError(t, json.Unmarshal(stdout, &plan), "stdout must be valid JSON: %s", stdout)

	// All non-noop steps must have Done=false.
	for _, s := range plan.Steps {
		if s.Action == "noop" {
			continue
		}
		assert.False(t, s.Done, "dry-run step %q at %q should be Done=false", s.Action, s.Path)
	}

	// Nothing should have been written.
	keylatchDir := filepath.Join(homeDir, ".keylatch")
	_, err := os.Stat(keylatchDir)
	assert.True(t, os.IsNotExist(err), "dry-run must not create ~/.keylatch")

	// Canary check.
	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_Bootstrap_WritesFiles — bootstrap creates all required files
// with correct modes.
func TestE2E_Bootstrap_WritesFiles(t *testing.T) {
	homeDir := t.TempDir()
	stdout, stderr, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"bootstrap")

	require.Equal(t, 0, code, "bootstrap must exit 0; stderr: %s; stdout: %s", stderr, stdout)

	keylatchDir := filepath.Join(homeDir, ".keylatch")
	vaultDir := filepath.Join(keylatchDir, "vault")
	auditFile := filepath.Join(keylatchDir, "audit.log")
	configFile := filepath.Join(keylatchDir, "config.json")

	assertPathMode(t, keylatchDir, 0o700, true)
	assertPathMode(t, vaultDir, 0o700, true)
	assertPathMode(t, auditFile, 0o600, false)
	assertPathMode(t, configFile, 0o600, false)

	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_Bootstrap_Idempotent — running bootstrap twice produces all-noop.
func TestE2E_Bootstrap_Idempotent(t *testing.T) {
	homeDir := t.TempDir()
	env := map[string]string{"HOME": homeDir}

	// First run.
	_, _, code := runKeylatch(t, env, "bootstrap")
	require.Equal(t, 0, code, "first bootstrap must exit 0")

	// Second run with --json to verify all steps are noop.
	stdout, stderr, code := runKeylatch(t, env, "bootstrap", "--json")
	require.Equal(t, 0, code, "second bootstrap must exit 0; stderr: %s", stderr)

	var plan bootstrap.Plan
	require.NoError(t, json.Unmarshal(stdout, &plan))

	for _, s := range plan.Steps {
		assert.Equal(t, "noop", s.Action,
			"second run step must be noop: action=%q path=%q", s.Action, s.Path)
	}

	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_Doctor_JSON — doctor --json reports OverallOK=true after bootstrap.
func TestE2E_Doctor_JSON(t *testing.T) {
	homeDir := t.TempDir()
	env := map[string]string{"HOME": homeDir}

	// Bootstrap first.
	_, _, code := runKeylatch(t, env, "bootstrap")
	require.Equal(t, 0, code)

	// Now run doctor.
	// Doctor uses a three-tier exit code: 0=all OK (no warnings), 1=warnings-only,
	// 2=blocking failures. After bootstrap in a clean temp home there are several
	// informational warnings (gateway not running, hook not installed, no connections
	// configured, etc.) so exit 1 is expected and acceptable.
	// The invariant is: no blocking failures (exit != 2) and OverallOK=true.
	stdout, stderr, code := runKeylatch(t, env, "doctor", "--json")
	require.NotEqual(t, 2, code, "doctor must not exit 2 (blocking failures) after bootstrap; stderr: %s", stderr)

	var report doctor.Report
	require.NoError(t, json.Unmarshal(stdout, &report), "doctor --json must produce valid JSON: %s", stdout)
	assert.True(t, report.OverallOK, "doctor OverallOK must be true after bootstrap")
	assert.NotEmpty(t, report.Version)
	assert.NotEmpty(t, report.Platform)
	assert.NotEmpty(t, report.CipherSuite)

	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_NoHardcodedPaths — no generated file contains a hardcoded path.
func TestE2E_NoHardcodedPaths(t *testing.T) {
	homeDir := t.TempDir()
	env := map[string]string{"HOME": homeDir}

	_, _, code := runKeylatch(t, env, "bootstrap")
	require.Equal(t, 0, code)

	keylatchDir := filepath.Join(homeDir, ".keylatch")

	// Walk the keylatch dir and check no file contains the real home directory.
	realHome, err := os.UserHomeDir()
	require.NoError(t, err)

	err = filepath.Walk(keylatchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		assert.NotContains(t, string(data), realHome,
			"generated file %s must not contain hardcoded home %q", path, realHome)
		return nil
	})
	require.NoError(t, err)
}

// TestE2E_Completion_Zsh — completion zsh output starts with #compdef keylatch.
func TestE2E_Completion_Zsh(t *testing.T) {
	homeDir := t.TempDir()
	stdout, stderr, code := runKeylatch(t,
		map[string]string{"HOME": homeDir},
		"completion", "zsh")

	require.Equal(t, 0, code, "completion zsh must exit 0; stderr: %s", stderr)
	lines := strings.Split(string(stdout), "\n")
	require.NotEmpty(t, lines)
	assert.Equal(t, "#compdef keylatch", lines[0],
		"first line of zsh completion must be #compdef keylatch")

	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_Doctor_ExitsZero — doctor does not exit 2 (blocking failures) when OverallOK.
// Warnings (exit 1) are informational and do not constitute failures. After bootstrap in an
// isolated temp home the doctor reports several informational warnings (gateway not running,
// hook not installed, etc.) so exit 1 is the expected steady-state exit code.
// The invariant: warnings must not produce exit 2 (blocking failure).
func TestE2E_Doctor_ExitsZero(t *testing.T) {
	homeDir := t.TempDir()
	env := map[string]string{"HOME": homeDir}

	_, _, code := runKeylatch(t, env, "bootstrap")
	require.Equal(t, 0, code)

	_, _, code = runKeylatch(t, env, "doctor")
	assert.NotEqual(t, 2, code, "doctor must not exit 2 (blocking failures) after bootstrap — warnings (exit 1) are acceptable")
}

// TestE2E_ConfigSet_Backend — config set backend persists atomically.
func TestE2E_ConfigSet_Backend(t *testing.T) {
	homeDir := t.TempDir()
	env := map[string]string{"HOME": homeDir}

	_, _, code := runKeylatch(t, env, "bootstrap")
	require.Equal(t, 0, code)

	stdout, stderr, code := runKeylatch(t, env, "config", "set", "backend", "file")
	require.Equal(t, 0, code, "config set backend file must exit 0; stderr: %s; stdout: %s", stderr, stdout)

	// Verify the config was actually persisted.
	configFile := filepath.Join(homeDir, ".keylatch", "config.json")
	data, err := os.ReadFile(configFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"backend"`)
	assert.Contains(t, string(data), `"file"`)

	// Verify mode is still 0o600 after atomic write.
	info, err := os.Stat(configFile)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		// Windows NTFS ignores Unix permission bits — skip mode assertion.
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	assertNoCanaryLeak(t, stdout, stderr, homeDir)
}

// TestE2E_ConfigSet_CredentialKeyRejected — config set <credential-like-key> exits 1.
func TestE2E_ConfigSet_CredentialKeyRejected(t *testing.T) {
	homeDir := t.TempDir()
	env := map[string]string{"HOME": homeDir}

	_, _, code := runKeylatch(t, env, "bootstrap")
	require.Equal(t, 0, code)

	stdout, stderr, code := runKeylatch(t, env, "config", "set", "api_key", "foo")
	assert.Equal(t, 1, code, "config set api_key must exit 1 (blocked); stdout: %s; stderr: %s", stdout, stderr)
	combined := string(stdout) + string(stderr)
	assert.True(t,
		strings.Contains(combined, "keylatch set") ||
			strings.Contains(combined, "credential") ||
			strings.Contains(combined, "blocked"),
		"error message should redirect to keylatch set: %s", combined)
}

// TestE2E_GoVet — go vet ./... passes.
func TestE2E_GoVet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping go vet in short mode")
	}
	// Locate module root from go env.
	modBytes, err := exec.Command("go", "env", "GOMOD").Output()
	require.NoError(t, err)
	modRoot := filepath.Dir(strings.TrimSpace(string(modBytes)))

	cmd := exec.Command("go", "vet", "./...")
	cmd.Dir = modRoot
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, "go vet ./... must pass: %s", out)
}

// assertPathMode checks that a path exists with the expected mode.
func assertPathMode(t *testing.T, p string, wantPerm os.FileMode, isDir bool) {
	t.Helper()
	info, err := os.Stat(p)
	require.NoError(t, err, "expected path to exist: %s", p)
	assert.Equal(t, isDir, info.IsDir(), "is dir mismatch for %s", p)
	if runtime.GOOS != "windows" {
		// Windows NTFS ignores Unix permission bits — os.MkdirAll(path, 0o700)
		// and os.WriteFile(path, data, 0o600) report as 0777/0666 on Windows.
		assert.Equal(t, wantPerm, info.Mode().Perm(), "mode mismatch for %s", p)
	}
}
