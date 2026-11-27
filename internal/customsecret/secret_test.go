package customsecret

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetRegistry restores the embedded templates so custom entries do not leak between tests.
func resetRegistry(t *testing.T) {
	t.Helper()
	reload := func() {
		require.NoError(t, registry.InitFromConfig(context.Background(), llmcontext.DefaultLookup))
		for _, name := range []string{"acme", "broken", "other"} {
			delete(registry.AllowedProviderBaseURLs, name)
		}
	}
	reload()
	t.Cleanup(reload)
}

func newSecret(t *testing.T, name string) Secret {
	t.Helper()
	s := Secret{
		Name:      name,
		Hosts:     []string{"api.acme.example", "eu.acme.example"},
		Paths:     []string{"/v1"},
		Methods:   []string{"GET", "POST"},
		Injection: Injection{Kind: InjectHeader, Name: "Authorization", Format: "Bearer {value}"},
		CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, s.Normalize())
	return s
}

func TestCheckRejectsProviderTemplateNames(t *testing.T) {
	resetRegistry(t)
	require.NotEmpty(t, registry.List())
	for _, tmpl := range registry.List() {
		assert.Error(t, Check(tmpl.Provider), "name of template %q must be refused", tmpl.Provider)
	}
	assert.NoError(t, Check("acme-not-a-template"))
}

func TestTemplateShape(t *testing.T) {
	s := newSecret(t, "acme")
	tmpl := s.Template()

	assert.Equal(t, "acme", tmpl.Provider)
	assert.Equal(t, "custom", tmpl.Category)
	assert.Equal(t, registry.TrustLocalOnly, tmpl.TrustLevel)
	assert.Equal(t, registry.RuntimeGatewaySDK, tmpl.RuntimeSupport.Preferred)
	assert.Equal(t, []registry.RuntimeMode{registry.RuntimeGatewaySDK, registry.RuntimeGatewayProxy}, tmpl.RuntimeSupport.Supported)
	assert.Equal(t, registry.AuthPlacement{In: "header", Name: "Authorization", Format: "Bearer {value}"}, tmpl.AuthPlacement)
	require.NotNil(t, tmpl.Custom)
	assert.Equal(t, []string{"api.acme.example", "eu.acme.example"}, tmpl.Custom.Hosts)
	assert.Empty(t, tmpl.AllowedCommandPrefixes, "no command is allowed implicitly")
	assert.Equal(t, "default/custom/acme/value", ValuePath("acme"))
}

func TestRegisterAll(t *testing.T) {
	resetRegistry(t)

	good := newSecret(t, "acme")
	collides := newSecret(t, "openrouter")
	broken := newSecret(t, "broken")
	broken.Hosts = []string{"127.0.0.1"}

	errs := RegisterAll([]Secret{good, collides, broken})
	assert.Len(t, errs, 2, "the template-name collision and the invalid entry are reported, not fatal")

	got, err := registry.Get("acme")
	require.NoError(t, err)
	require.NotNil(t, got.Custom)
	assert.Equal(t, []string{"api.acme.example", "eu.acme.example"}, registry.AllowedProviderBaseURLs["acme"], "every listed host is allowed")

	or, err := registry.Get("openrouter")
	require.NoError(t, err)
	assert.Nil(t, or.Custom, "the shipped template is untouched")

	_, err = registry.Get("broken")
	assert.ErrorIs(t, err, registry.ErrProviderNotFound)

	assert.Empty(t, RegisterAll([]Secret{good}), "registering again is idempotent")
}

func TestFileRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg", "custom-secrets.json")

	got, err := Load(path)
	require.NoError(t, err)
	assert.Empty(t, got, "a missing file is an empty list")

	a, b := newSecret(t, "zeta"), newSecret(t, "acme")
	b.RefScheme = "op"
	require.NoError(t, Add(path, a))
	require.NoError(t, Add(path, b))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	got, err = Load(path)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "acme", got[0].Name, "stored sorted by name")
	assert.Equal(t, "op", got[0].RefScheme)
	assert.Equal(t, "op reference", got[0].Source())
	assert.Equal(t, "stored", got[1].Source())

	assert.ErrorIs(t, Add(path, a), ErrExists)

	found, err := Find(path, "zeta")
	require.NoError(t, err)
	assert.Equal(t, "header Authorization", found.Kind())
	_, err = Find(path, "missing")
	assert.ErrorIs(t, err, ErrNotFound)

	require.NoError(t, Remove(path, "zeta"))
	assert.ErrorIs(t, Remove(path, "zeta"), ErrNotFound)
	got, err = Load(path)
	require.NoError(t, err)
	assert.Len(t, got, 1)
	entries0, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.LessOrEqual(t, len(entries0), 2, "the data file and its lock file only")

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), ".custom-secrets-", "no temp files are left behind")
	}
}

func TestLoadRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom-secrets.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))
	_, err := Load(path)
	assert.Error(t, err)
}

func TestConcurrentAddsUnderTheLockKeepEveryEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom-secrets.json")
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := newSecret(t, fmt.Sprintf("svc-%02d", i))
			errs <- WithLock(path, func(tx Tx) error {
				if _, err := tx.Find(s.Name); !errors.Is(err, ErrNotFound) {
					return fmt.Errorf("unexpected %v", err)
				}
				return tx.Add(s)
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	got, err := Load(path)
	require.NoError(t, err)
	assert.Len(t, got, n, "no concurrent add lost another's entry")
}

func TestFindDistinguishesMissingFromUnreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom-secrets.json")
	_, err := Find(path, "acme")
	assert.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, os.WriteFile(path, []byte("{broken"), 0o600))
	_, err = Find(path, "acme")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
}
