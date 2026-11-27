package doctor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/customsecret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func customSecretsEnv(path string) func(string) string {
	return func(k string) string {
		if k == "KEYLATCH_CUSTOM_SECRETS_PATH" {
			return path
		}
		return ""
	}
}

func TestCheckCustomSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom-secrets.json")
	env := customSecretsEnv(path)

	st := checkCustomSecrets(env)(context.Background())
	assert.True(t, st.OK)
	assert.False(t, st.Warn)
	assert.Equal(t, "providers", st.Section)
	assert.Contains(t, st.Detail, "no custom secrets")

	good := customsecret.Secret{
		Name: "acme", Hosts: []string{"api.acme.example"}, Paths: []string{"/v1"},
		Injection: customsecret.Injection{Kind: customsecret.InjectHeader, Name: "X-Api-Key", Format: "{value}"},
		RefScheme: "op", CreatedAt: time.Now(),
	}
	require.NoError(t, good.Normalize())
	require.NoError(t, customsecret.Add(path, good))

	st = checkCustomSecrets(env)(context.Background())
	assert.True(t, st.OK)
	assert.False(t, st.Warn)
	for _, want := range []string{"1 custom secret(s)", "acme", "api.acme.example", "header X-Api-Key", "op reference"} {
		assert.Contains(t, st.Detail, want)
	}
	assert.NotContains(t, st.Detail, "{value}", "the injection format is not printed")

	bad := good
	bad.Name = "bad"
	bad.Hosts = []string{"127.0.0.1"}
	require.NoError(t, customsecret.Add(path, bad))
	st = checkCustomSecrets(env)(context.Background())
	assert.True(t, st.OK)
	assert.True(t, st.Warn, "an invalid entry is a warning")
	assert.Contains(t, st.Detail, "bad")
	assert.NotEmpty(t, st.Fix)
}
