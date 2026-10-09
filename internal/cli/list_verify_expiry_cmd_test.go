package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func caStoreConnection(t *testing.T, f *caFixture, metaPath string, conn connections.Connection) {
	t.Helper()
	data, err := json.Marshal(conn)
	require.NoError(t, err)
	require.NoError(t, newDispatchedStore(f.cfg, f.env).Set(context.Background(), metaPath, data, backend.Meta{}))
}

func caListFixture(t *testing.T) (*caFixture, string) {
	t.Helper()
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secret := caSecret("list")
	tested := time.Now().Add(-2 * time.Hour)
	caStoreConnection(t, f, "default/ai/openrouter/meta", connections.Connection{
		Provider: "openrouter", Account: "default", Namespace: "default", Status: "connected",
		Fields: []string{"api_key"}, LastTested: &tested,
	})
	caStoreConnection(t, f, "default/custom/inhouse/meta", connections.Connection{
		Provider: "inhouse", Account: "default", Namespace: "default", Status: "untested",
	})
	require.NoError(t, newDispatchedStore(f.cfg, f.env).Set(context.Background(),
		"default/ai/openrouter/api_key", []byte(secret), backend.Meta{}))
	return f, secret
}

func TestListCmdTableShowsConnectionsWithoutValues(t *testing.T) {
	_, secret := caListFixture(t)

	out, errOut, err := caRun(t, nil, "list")
	require.NoError(t, err)
	assert.NotContains(t, errOut, "audit logger unavailable")
	assert.NotContains(t, out, secret)
	assert.Contains(t, out, "PROVIDER")
	assert.Contains(t, out, "USABLE")
	assert.Regexp(t, `openrouter\s+default\s+connected\s+\S.*\s+never\s+yes`, out)
	assert.Regexp(t, `inhouse\s+default\s+untested\s+.*no \(unknown-provider\)`, out)
	assert.Contains(t, out, "2 connections (file backend)")
	assert.Contains(t, out, "keylatch list --raw")
}

func TestListCmdJSONInLLMSession(t *testing.T) {
	_, secret := caListFixture(t)
	caSetLLMSession(t)

	out, _, err := caRun(t, nil, "list", "--json")
	require.NoError(t, err)
	assert.NotContains(t, out, secret)
	var rows []map[string]string
	require.NoError(t, json.Unmarshal([]byte(out), &rows))
	require.Len(t, rows, 2)
	byProvider := map[string]map[string]string{}
	for _, r := range rows {
		byProvider[r["provider"]] = r
	}
	assert.Equal(t, "yes", byProvider["openrouter"]["usable"], "gateway modes stay usable in LLM sessions")
	assert.Equal(t, "connected", byProvider["openrouter"]["status"])
	assert.Equal(t, "no", byProvider["inhouse"]["usable"])
	assert.Equal(t, "unknown-provider", byProvider["inhouse"]["reason"])
}

func TestListCmdRawShowsVaultPaths(t *testing.T) {
	_, secret := caListFixture(t)
	out, _, err := caRun(t, nil, "list", "--raw")
	require.NoError(t, err)
	assert.Contains(t, out, "file/default/ai/openrouter/api_key\n")
	assert.Contains(t, out, "file/default/ai/openrouter/meta\n")
	assert.NotContains(t, out, secret)
}

func TestListCmdWithoutKeyring(t *testing.T) {
	caNewEnv(t)
	out, _, err := caRun(t, nil, "list", "--json")
	require.NoError(t, err)
	assert.Equal(t, "[]\n", out)

	_, _, err = caRun(t, nil, "list", "--raw")
	require.Error(t, err)
	assert.ErrorContains(t, err, "audit log cannot be opened")
}

func TestCheckExpiryDefaultsAndNoExpired(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	f.rotate(t, caPath, []byte(caSecret("exp")))

	out, _, err := caRun(t, nil, "check-expiry", "--days", "0")
	require.NoError(t, err, "nothing is expired")
	assert.NotContains(t, out, caSecret("exp"))

	out, _, err = caRun(t, nil, "check-expiry", "--json")
	require.NoError(t, err)
	assert.True(t, json.Valid([]byte(out)), out)
}

func TestCheckExpiryWithoutKeyring(t *testing.T) {
	caNewEnv(t)
	_, _, err := caRun(t, nil, "check-expiry")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrBootstrapRequired)
}

func caFakeCosign(t *testing.T, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake cosign is a shell script")
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsFile + "'\necho fake-cosign-output\nexit " + string(rune('0'+exitCode)) + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cosign"), []byte(script), 0o700))
	t.Setenv("PATH", dir)
	return argsFile
}

func TestVerifyCmdRunsCosignWithPinnedIdentity(t *testing.T) {
	caNewEnv(t)
	argsFile := caFakeCosign(t, 0)
	bin := filepath.Join(t.TempDir(), "keylatch")
	require.NoError(t, os.WriteFile(bin, []byte("binary"), 0o600))

	out, _, err := caRun(t, nil, "verify", bin)
	require.NoError(t, err)
	assert.Contains(t, out, "fake-cosign-output")
	assert.Contains(t, out, "Verification OK")
	data, err := os.ReadFile(argsFile)
	require.NoError(t, err)
	args := strings.Split(strings.TrimSpace(string(data)), "\n")
	assert.Equal(t, []string{
		"verify-blob",
		"--certificate-identity-regexp", cosignIdentityRegexp,
		"--certificate-oidc-issuer", cosignOIDCIssuer,
		bin,
	}, args)

	c := newVerifyCmd()
	c.SetOut(&strings.Builder{})
	require.NoError(t, runVerify(c, bin, bin+".sig"))
	data, err = os.ReadFile(argsFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "--signature\n"+bin+".sig\n")
}

func TestVerifyCmdFailures(t *testing.T) {
	caNewEnv(t)
	caFakeCosign(t, 1)

	_, _, err := caRun(t, nil, "verify")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "specify a binary path or use --self")

	out, _, err := caRun(t, nil, "verify", "/some/binary")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cosign verify-blob failed")
	assert.NotContains(t, out, "Verification OK")

	t.Setenv("PATH", t.TempDir())
	_, _, err = caRun(t, nil, "verify", "/some/binary")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cosign verify-blob failed")
}

func TestVerifySelfUsesAdjacentSignature(t *testing.T) {
	caNewEnv(t)
	argsFile := caFakeCosign(t, 0)
	exe, err := os.Executable()
	require.NoError(t, err)
	exe, err = filepath.EvalSymlinks(exe)
	require.NoError(t, err)
	sig := exe + ".sig"
	if _, statErr := os.Stat(sig); statErr == nil {
		t.Skip("a signature file already sits next to the test binary")
	}
	if err := os.WriteFile(sig, []byte("sig"), 0o600); err != nil {
		t.Skipf("cannot write next to the test binary: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(sig) })

	origVersion := version.Version
	version.Version = "1.2.3"
	t.Cleanup(func() { version.Version = origVersion })

	out, _, err := caRun(t, nil, "verify", "--self")
	require.NoError(t, err)
	assert.Contains(t, out, "Verification OK")
	data, err := os.ReadFile(argsFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "--signature\n"+sig+"\n"+exe+"\n")
}
