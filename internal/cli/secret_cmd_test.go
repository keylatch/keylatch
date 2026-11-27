package cli

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/customsecret"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secretTestValue = "acme-live-0123456789abcdef"

// storedValue reads the value back through the vault layer the gateway uses.
func storedValue(t *testing.T, f *caFixture, name string) ([]byte, error) {
	t.Helper()
	ctx := audit.WithEmitter(context.Background(), discardAudit{})
	return vault.Get(ctx, customsecret.ValuePath(name), f.cfg, f.env)
}

// secretFixture is an isolated install whose owner has an approver passphrase
// and a terminal, so a human `secret add` takes effect at once.
func secretFixture(t *testing.T) *caFixture {
	t.Helper()
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	return f
}

func secretAddArgs(extra ...string) []string {
	return append([]string{"secret", "add", "acme", "--host", "api.acme.example", "--path", "/v1",
		"--method", "get", "--header", "Authorization: Bearer {value}"}, extra...)
}

func TestSecretAddStoresValueAndMetadataSeparately(t *testing.T) {
	f := secretFixture(t)

	out, errOut, err := caRun(t, caStdinFile(t, secretTestValue+"\n"), secretAddArgs("--value-stdin", "--base-url-env", "ACME_BASE_URL")...)
	require.NoError(t, err, errOut)
	assert.Contains(t, out, "secret added: acme -> api.acme.example")
	assert.NotContains(t, out+errOut, secretTestValue)

	got, err := storedValue(t, f, "acme")
	require.NoError(t, err)
	assert.Equal(t, secretTestValue, string(got), "the value is in the configured backend, newline trimmed")

	viaGateway, _, err := (&gatewayVaultReader{cfg: f.cfg, env: f.env}).Get(audit.WithEmitter(context.Background(), discardAudit{}), customsecret.ValuePath("acme"))
	require.NoError(t, err)
	assert.Equal(t, secretTestValue, string(viaGateway), "the gateway's vault reader resolves the stored value")

	file := paths.CustomSecrets(llmcontext.DefaultLookup)
	info, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), secretTestValue, "the metadata file never holds the value")

	s, err := customsecret.Find(file, "acme")
	require.NoError(t, err)
	assert.Equal(t, []string{"api.acme.example"}, s.Hosts)
	assert.Equal(t, []string{"/v1"}, s.Paths)
	assert.Equal(t, []string{"GET"}, s.Methods)
	assert.Equal(t, "ACME_BASE_URL", s.BaseURLEnv)
	assert.Empty(t, s.RefScheme)
}

func TestSecretAddWithReferenceStoresTheReferenceOnly(t *testing.T) {
	f := secretFixture(t)
	const ref = "op://Private/acme/key"

	out, errOut, err := caRun(t, nil, "secret", "add", "acme", "--ref", ref, "--host", "api.acme.example", "--query", "api_key")
	require.NoError(t, err, errOut)
	assert.Contains(t, out, "op reference")

	got, err := storedValue(t, f, "acme")
	require.NoError(t, err)
	assert.Equal(t, ref, string(got))

	s, err := customsecret.Find(paths.CustomSecrets(llmcontext.DefaultLookup), "acme")
	require.NoError(t, err)
	assert.Equal(t, "op", s.RefScheme)
	assert.Equal(t, []string{"/"}, s.Paths)
}

func TestSecretRmStaysRefusedInLLMSession(t *testing.T) {
	_ = secretFixture(t)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)
	caSetLLMSession(t)

	_, _, err = caRun(t, nil, "secret", "rm", "acme", "--force")
	require.Error(t, err)
	assert.Equal(t, exitcode.SecurityBlock, caExitCode(err))
	assert.Contains(t, err.Error(), "human terminal")
	_, err = customsecret.Find(paths.CustomSecrets(llmcontext.DefaultLookup), "acme")
	assert.NoError(t, err, "the secret is untouched")
}

func TestSecretReadOnlyCommandsWorkInLLMSession(t *testing.T) {
	_ = secretFixture(t)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)
	caSetLLMSession(t)

	out, _, err := caRun(t, nil, "secret", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "acme")
	out, _, err = caRun(t, nil, "secret", "show", "acme")
	require.NoError(t, err)
	assert.Contains(t, out, "api.acme.example")
}

func TestSecretAddRejectsBadInput(t *testing.T) {
	_ = secretFixture(t)
	file := paths.CustomSecrets(llmcontext.DefaultLookup)

	cases := []struct {
		name string
		args []string
	}{
		{"neither value nor ref", secretAddArgs()},
		{"both value and ref", secretAddArgs("--value-stdin", "--ref", "op://v/i/f")},
		{"no injection rule", []string{"secret", "add", "acme", "--value-stdin", "--host", "api.acme.example"}},
		{"two injection rules", []string{"secret", "add", "acme", "--value-stdin", "--host", "api.acme.example", "--query", "k", "--basic", "u"}},
		{"no host", []string{"secret", "add", "acme", "--value-stdin", "--query", "k"}},
		{"ip host", []string{"secret", "add", "acme", "--value-stdin", "--host", "127.0.0.1", "--query", "k"}},
		{"private suffix host", []string{"secret", "add", "acme", "--value-stdin", "--host", "db.internal", "--query", "k"}},
		{"ip as second host", []string{"secret", "add", "acme", "--value-stdin", "--host", "api.acme.example", "--host", "10.0.0.1", "--query", "k"}},
		{"wildcard host", []string{"secret", "add", "acme", "--value-stdin", "--host", "*.co.uk", "--query", "k"}},
		{"wildcard under a real domain", []string{"secret", "add", "acme", "--value-stdin", "--host", "*.acme.example", "--query", "k"}},
		{"bad name", []string{"secret", "add", "Acme_Prod", "--value-stdin", "--host", "api.acme.example", "--query", "k"}},
		{"name of a provider template", []string{"secret", "add", "openrouter", "--value-stdin", "--host", "api.acme.example", "--query", "k"}},
		{"header without placeholder", []string{"secret", "add", "acme", "--value-stdin", "--host", "api.acme.example", "--header", "Authorization: Bearer abc"}},
		{"bad base url env", secretAddArgs("--value-stdin", "--base-url-env", "PATH")},
	}
	for _, tc := range cases {
		_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), tc.args...)
		require.Error(t, err, tc.name)
		assert.NotContains(t, err.Error()+errOut, secretTestValue, tc.name)
	}
	_, statErr := os.Stat(file)
	assert.True(t, os.IsNotExist(statErr), "a rejected add leaves no metadata")
}

func TestSecretAddNeverEchoesAValuePassedAsRef(t *testing.T) {
	_ = secretFixture(t)
	_, errOut, err := caRun(t, nil, "secret", "add", "acme", "--ref", secretTestValue, "--host", "api.acme.example", "--query", "k")
	require.Error(t, err)
	assert.NotContains(t, err.Error()+errOut, secretTestValue)
}

func TestSecretAddRefusesDuplicateAndKeepsTheFirstValue(t *testing.T) {
	f := secretFixture(t)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)

	_, _, err = caRun(t, caStdinFile(t, "another-value-0123456789"), secretAddArgs("--value-stdin")...)
	require.Error(t, err)

	got, err := storedValue(t, f, "acme")
	require.NoError(t, err)
	assert.Equal(t, secretTestValue, string(got))
}

func TestSecretListShowAndStatusNeverContainTheValue(t *testing.T) {
	_ = secretFixture(t)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)
	_, errOut, err = caRun(t, nil, "secret", "add", "viaref", "--ref", "aws-sm://eu-west-1/acme-key",
		"--host", "api.other.example", "--basic", "svc")
	require.NoError(t, err, errOut)

	for _, args := range [][]string{
		{"secret", "list"}, {"secret", "list", "--json"}, {"secret", "show", "acme"}, {"secret", "show", "viaref", "--json"},
		{"status"}, {"status", "--json"},
	} {
		out, errOut, err := caRun(t, nil, args...)
		require.NoError(t, err, args)
		assert.NotContains(t, out+errOut, secretTestValue, args)
	}

	out, _, err := caRun(t, nil, "secret", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "acme")
	assert.Contains(t, out, "api.acme.example")
	assert.Contains(t, out, "header Authorization")
	assert.Contains(t, out, "stored")
	assert.Contains(t, out, "viaref")
	assert.Contains(t, out, "basic auth")
	assert.Contains(t, out, "aws-sm reference")

	out, _, err = caRun(t, nil, "status", "--json")
	require.NoError(t, err)
	var parsed struct {
		CustomSecrets []customsecret.Secret `json:"custom_secrets"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &parsed))
	require.Len(t, parsed.CustomSecrets, 2)

	out, _, err = caRun(t, nil, "status")
	require.NoError(t, err)
	assert.Contains(t, out, "Custom secrets")
	assert.Contains(t, out, "api.acme.example")

	_, _, err = caRun(t, nil, "secret", "show", "missing")
	assert.Error(t, err)
}

func TestSecretRmRemovesValueAndMetadata(t *testing.T) {
	f := secretFixture(t)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)

	out, errOut, err := caRun(t, nil, "secret", "rm", "acme", "--force")
	require.NoError(t, err, errOut)
	assert.Contains(t, out, "secret removed: acme")

	_, err = customsecret.Find(paths.CustomSecrets(llmcontext.DefaultLookup), "acme")
	assert.ErrorIs(t, err, customsecret.ErrNotFound)
	_, err = storedValue(t, f, "acme")
	assert.ErrorIs(t, err, backend.ErrNotFound, "the stored value is gone")

	_, _, err = caRun(t, nil, "secret", "rm", "acme", "--force")
	assert.Error(t, err)
}

func TestRegisterCustomSecretsMakesThemRoutable(t *testing.T) {
	_ = secretFixture(t)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin", "--base-url-env", "ACME_BASE_URL")...)
	require.NoError(t, err, errOut)

	// Any command re-initialises the registry; a later command must see the secret.
	_, _, err = caRun(t, nil, "secret", "list")
	require.NoError(t, err)
	got, err := registry.Get("acme")
	require.NoError(t, err)
	require.NotNil(t, got.Custom)
	assert.Equal(t, "ACME_BASE_URL", got.Custom.BaseURLEnv)
}

func TestSecretAddReplace(t *testing.T) {
	f := secretFixture(t)
	file := paths.CustomSecrets(llmcontext.DefaultLookup)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)
	before, err := customsecret.Find(file, "acme")
	require.NoError(t, err)

	// Without --replace a duplicate stays refused; --replace needs an existing secret.
	_, _, err = caRun(t, caStdinFile(t, "x-0123456789"), secretAddArgs("--value-stdin")...)
	require.Error(t, err)
	_, _, err = caRun(t, caStdinFile(t, "x-0123456789"), "secret", "add", "nope", "--replace", "--value-stdin",
		"--host", "api.acme.example", "--query", "k")
	require.Error(t, err)

	// Rules only: the stored value is kept.
	out, errOut, err := caRun(t, nil, "secret", "add", "acme", "--replace", "--host", "api.new.example",
		"--path", "/v2", "--query", "token")
	require.NoError(t, err, errOut)
	assert.Contains(t, out, "secret replaced")
	got, err := storedValue(t, f, "acme")
	require.NoError(t, err)
	assert.Equal(t, secretTestValue, string(got))
	after, err := customsecret.Find(file, "acme")
	require.NoError(t, err)
	assert.Equal(t, []string{"api.new.example"}, after.Hosts)
	assert.Equal(t, "query token", after.Kind())
	assert.True(t, after.CreatedAt.Equal(before.CreatedAt))

	// New value and a reference.
	const rotated = "acme-rotated-0123456789"
	_, errOut, err = caRun(t, caStdinFile(t, rotated), "secret", "add", "acme", "--replace", "--value-stdin",
		"--host", "api.new.example", "--query", "token")
	require.NoError(t, err, errOut)
	got, err = storedValue(t, f, "acme")
	require.NoError(t, err)
	assert.Equal(t, rotated, string(got))

	_, errOut, err = caRun(t, nil, "secret", "add", "acme", "--replace", "--ref", "op://Private/acme/key",
		"--host", "api.new.example", "--query", "token")
	require.NoError(t, err, errOut)
	after, _ = customsecret.Find(file, "acme")
	assert.Equal(t, "op", after.RefScheme)

	// Invalid replacement rules change nothing.
	_, _, err = caRun(t, nil, "secret", "add", "acme", "--replace", "--host", "127.0.0.1", "--query", "token")
	require.Error(t, err)
	again, _ := customsecret.Find(file, "acme")
	assert.Equal(t, after.Hosts, again.Hosts)
}
