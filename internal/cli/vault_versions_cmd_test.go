package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const caPath = "default/ai/openrouter/api_key"

func caSecret(tag string) string {
	return "kl" + "-test-" + tag + "-" + strings.Repeat("z", 12)
}

func TestSetCmdWritesPipedValueWithMetadata(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secret := caSecret("set")

	out, errOut, err := caRun(t, caStdinFile(t, secret+"\n"), "set", caPath,
		"--expires-at", "2030-01-02T03:04:05Z", "--issued-at", "2025-01-01T00:00:00Z",
		"--owner", "ops", "--scope", "production", "--max-versions", "4")
	require.NoError(t, err, errOut)
	assert.Contains(t, out, "[keylatch] set: "+caPath+" — version 1")
	assert.NotContains(t, out+errOut, secret)

	m := f.meta(t, caPath)
	assert.Equal(t, 1, m.CurrentVersion)
	assert.Equal(t, "ops", m.Owner)
	assert.Equal(t, "production", m.Scope)
	assert.Equal(t, 4, m.MaxVersions)
	require.NotNil(t, m.ExpiresAt)
	assert.True(t, m.ExpiresAt.Equal(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)))
	require.NotNil(t, m.IssuedAt)

	got, _, err := vault.GetVersion(context.Background(), caPath, 1, f.cfg, f.env)
	require.NoError(t, err)
	assert.Equal(t, secret, string(got), "trailing newline must be trimmed")

	out, _, err = caRun(t, caStdinFile(t, caSecret("second")), "set", caPath)
	require.NoError(t, err)
	assert.Contains(t, out, "version 2")
	assert.Equal(t, 2, f.meta(t, caPath).CurrentVersion)
}

func TestSetCmdRejectsBadInput(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)

	tests := []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"bad expires-at", "v", []string{"--expires-at", "tomorrow"}, "--expires-at must be RFC3339"},
		{"bad issued-at", "v", []string{"--issued-at", "2025-13-99"}, "--issued-at must be RFC3339"},
		{"empty value", "\n", nil, "value must not be empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"set", caPath}, tc.args...)
			_, _, err := caRun(t, caStdinFile(t, tc.stdin), args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.Equal(t, exitcode.UserError, caExitCode(err))
		})
	}
	_, err := vault.GetMeta(context.Background(), caPath, f.cfg, f.env)
	assert.Error(t, err, "rejected input must not create the credential")
}

func TestSetCmdNonFileStdinFallsBackToHiddenPrompt(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	caSwapStdin(t, "")
	_, _, err := caRun(t, bytes.NewBufferString("ignored"), "set", caPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading password")
}

func TestSetCmdBackendUnavailable(t *testing.T) {
	caNewEnv(t)
	_, _, err := caRun(t, caStdinFile(t, "value"), "set", caPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit log cannot be opened")
	assert.Equal(t, exitcode.SecurityBlock, caExitCode(err))
}

func TestRollbackCmdCreatesNewVersionWithOldValue(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	first, second := caSecret("one"), caSecret("two")
	f.rotate(t, caPath, []byte(first))
	f.rotate(t, caPath, []byte(second))

	out, errOut, err := caRunAudited(t, nil, "rollback", caPath, "1", "--force")
	require.NoError(t, err, errOut)
	assert.Contains(t, errOut, "Rolling back "+caPath+" to version 1")
	assert.Contains(t, out, "version 1 → new version 3 (rolled back from 1)")
	assert.NotContains(t, out+errOut, first)

	m := f.meta(t, caPath)
	assert.Equal(t, 3, m.CurrentVersion)
	got, _, err := vault.GetVersion(context.Background(), caPath, 3, f.cfg, f.env)
	require.NoError(t, err)
	assert.Equal(t, first, string(got))
}

func TestRollbackCmdConfirmation(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	f.rotate(t, caPath, []byte(caSecret("a")))
	f.rotate(t, caPath, []byte(caSecret("b")))

	_, errOut, err := caRunAudited(t, strings.NewReader("n\n"), "rollback", caPath, "1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aborted")
	assert.Contains(t, errOut, "Proceed? [y/N]: ")
	assert.Equal(t, 2, f.meta(t, caPath).CurrentVersion)

	_, _, err = caRunAudited(t, caStdinFile(t, "y\n"), "rollback", caPath, "1")
	require.Error(t, err, "non-terminal stdin can never confirm")
	assert.Equal(t, 2, f.meta(t, caPath).CurrentVersion)

	_, _, err = caRunAudited(t, strings.NewReader(""), "rollback", caPath, "1")
	require.Error(t, err, "EOF is not a confirmation")

	out, _, err := caRunAudited(t, strings.NewReader("YES\n"), "rollback", caPath, "1")
	require.NoError(t, err)
	assert.Contains(t, out, "new version 3")
}

func TestRollbackCmdVersionStates(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	for _, v := range []string{"a", "b", "c"} {
		f.rotate(t, caPath, []byte(caSecret(v)))
	}
	ctx := context.Background()
	require.NoError(t, vault.DestroyVersion(ctx, caPath, 1, f.cfg, f.env))
	m := f.meta(t, caPath)
	now := time.Now()
	m.Versions[1].DeletedAt = &now
	require.NoError(t, vault.SetMeta(ctx, caPath, m, f.cfg, f.env))

	tests := []struct {
		version string
		want    string
	}{
		{"1", "version 1 is destroyed and cannot be rolled back"},
		{"2", "version 2 is deleted and cannot be rolled back"},
		{"9", "version 9 not found"},
	}
	for _, tc := range tests {
		_, _, err := caRun(t, nil, "rollback", caPath, tc.version, "--force")
		require.Error(t, err)
		assert.Contains(t, err.Error(), tc.want)
	}

	_, _, err := caRun(t, nil, "rollback", "default/ai/nobody/api_key", "1", "--force")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret not found")
	assert.Equal(t, 3, f.meta(t, caPath).CurrentVersion)
}

func TestDestroyVersionCmd(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	f.rotate(t, caPath, []byte(caSecret("a")))
	f.rotate(t, caPath, []byte(caSecret("b")))

	_, _, err := caRun(t, nil, "destroy-version", caPath, "x", "--force")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `version must be an integer, got "x"`)

	_, errOut, err := caRun(t, strings.NewReader("no\n"), "destroy-version", caPath, "1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aborted")
	assert.Contains(t, errOut, "Destroy version 1 of "+caPath+"? This is irreversible.")
	assert.Nil(t, f.meta(t, caPath).Versions[0].DestroyedAt)

	_, _, err = caRun(t, nil, "destroy-version", caPath, "2", "--force")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot destroy the current version")

	out, _, err := caRun(t, strings.NewReader("y\n"), "destroy-version", caPath, "1")
	require.NoError(t, err)
	assert.Contains(t, out, "[keylatch] destroyed: "+caPath+" version 1")
	m := f.meta(t, caPath)
	assert.NotNil(t, m.Versions[0].DestroyedAt)
	assert.Contains(t, m.DestroyedVersions, 1)
	_, _, err = vault.GetVersion(context.Background(), caPath, 1, f.cfg, f.env)
	assert.ErrorIs(t, err, vault.ErrVersionDestroyed)

	_, _, err = caRun(t, nil, "destroy-version", caPath, "1", "--force")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version 1 is already destroyed")

	_, _, err = caRun(t, nil, "destroy-version", caPath, "7", "--force")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version not found")
}

func TestVersionAndDestroyCmdsBlockedInLLMSession(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	f.rotate(t, caPath, []byte(caSecret("a")))
	f.rotate(t, caPath, []byte(caSecret("b")))
	caSetLLMSession(t)

	for _, args := range [][]string{
		{"rollback", caPath, "1", "--force"},
		{"destroy-version", caPath, "1", "--force"},
	} {
		_, _, err := caRun(t, nil, args...)
		require.Error(t, err)
		assert.Equal(t, exitcode.SecurityBlock, caExitCode(err))
		assert.Contains(t, err.Error(), "human terminal")
	}
	m := f.meta(t, caPath)
	assert.Equal(t, 2, m.CurrentVersion)
	assert.Nil(t, m.Versions[0].DestroyedAt)
}

func TestVersionsCmdTableNeverIncludesValues(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secret := caSecret("versions")
	f.rotate(t, caPath, []byte(secret))
	f.rotate(t, caPath, []byte(caSecret("v2")))

	out, _, err := caRun(t, nil, "versions", caPath)
	require.NoError(t, err)
	assert.NotContains(t, out, secret)
	assert.Contains(t, out, "Current version: 2")
	assert.Contains(t, out, "Backend: file")
}
