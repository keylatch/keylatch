package mint_test

import (
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type providerCase struct {
	name   string
	caller mint.CallerKind
	mutate func()
	want   string
}

func TestCheckVault(t *testing.T) {
	p := &config.VaultMintPolicy{Path: "database/creds/readonly"}
	for _, tc := range []providerCase{
		{"service", mint.CallerService, func() {}, ""},
		{"human not listed", mint.CallerHuman, func() {}, "not allowed"},
		{"human listed", mint.CallerHuman, func() { p.Callers = []string{"human"} }, ""},
		{"agent", mint.CallerService, func() { p.Callers = []string{"agent"} }, "can never mint"},
		{"unknown caller kind", mint.CallerService, func() { p.Callers = []string{"robot"} }, "unknown caller kind"},
		{"no path", mint.CallerService, func() { p.Callers = nil; p.Path = "/" }, "path is required"},
		{"ttl over an hour", mint.CallerService, func() { p.Path = "a/b"; p.MaxTTL = 7200 }, "max_ttl"},
		{"negative ttl", mint.CallerService, func() { p.MaxTTL = -1 }, "max_ttl"},
		{"overflow ttl", mint.CallerService, func() { p.MaxTTL = int(^uint(0) >> 1) }, "max_ttl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.mutate()
			_, err := mint.CheckVault(p, tc.caller, "")
			assertErr(t, err, tc.want)
		})
	}

	p = &config.VaultMintPolicy{Path: "database/creds/readonly", MaxTTL: 600}
	lease, err := mint.CheckVault(p, mint.CallerHost, "/database/creds/readonly/")
	require.NoError(t, err)
	assert.Equal(t, 10*time.Minute, lease)
	_, err = mint.CheckVault(p, mint.CallerHost, "database/creds/admin")
	assert.ErrorIs(t, err, mint.ErrDenied)
	_, err = mint.CheckVault(p, mint.CallerAgent, "")
	assert.ErrorIs(t, err, mint.ErrDenied)
	_, err = mint.CheckVault(nil, mint.CallerHost, "")
	assert.ErrorIs(t, err, mint.ErrDenied)
}

func TestCheckGCP(t *testing.T) {
	p := &config.GCPMintPolicy{ServiceAccount: "sa@p.iam.gserviceaccount.com", Scopes: []string{"a", "b"}}
	scopes, life, err := mint.CheckGCP(p, mint.CallerService, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, scopes)
	assert.Equal(t, time.Hour, life)

	scopes, _, err = mint.CheckGCP(p, mint.CallerService, []string{"b"})
	require.NoError(t, err)
	assert.Equal(t, []string{"b"}, scopes)

	_, _, err = mint.CheckGCP(p, mint.CallerService, []string{"c"})
	assert.ErrorIs(t, err, mint.ErrDenied)
	_, _, err = mint.CheckGCP(p, mint.CallerAgent, nil)
	assert.ErrorIs(t, err, mint.ErrDenied)
	_, _, err = mint.CheckGCP(nil, mint.CallerService, nil)
	assert.ErrorIs(t, err, mint.ErrDenied)
	_, _, err = mint.CheckGCP(p, mint.CallerHuman, nil)
	assert.ErrorIs(t, err, mint.ErrDenied)

	for name, bad := range map[string]config.GCPMintPolicy{
		"no account":     {Scopes: []string{"a"}},
		"no scopes":      {ServiceAccount: "sa@p"},
		"empty scope":    {ServiceAccount: "sa@p", Scopes: []string{""}},
		"space in scope": {ServiceAccount: "sa@p", Scopes: []string{"a b"}},
		"long ttl":       {ServiceAccount: "sa@p", Scopes: []string{"a"}, MaxTTL: 5400},
		"bad callers":    {ServiceAccount: "sa@p", Scopes: []string{"a"}, Callers: []string{"agent"}},
	} {
		_, _, err := mint.CheckGCP(&bad, mint.CallerService, nil)
		assert.ErrorIs(t, err, mint.ErrInvalidProviderPolicy, name)
	}
}

func TestCheckAzure(t *testing.T) {
	p := &config.AzureMintPolicy{Resource: "api://r", MaxTTL: 5400}
	life, err := mint.CheckAzure(p, mint.CallerService, "")
	require.NoError(t, err)
	assert.Equal(t, 90*time.Minute, life)
	_, err = mint.CheckAzure(p, mint.CallerService, "api://r")
	require.NoError(t, err)
	_, err = mint.CheckAzure(p, mint.CallerService, "api://x")
	assert.ErrorIs(t, err, mint.ErrDenied)
	_, err = mint.CheckAzure(p, mint.CallerAgent, "")
	assert.ErrorIs(t, err, mint.ErrDenied)
	_, err = mint.CheckAzure(nil, mint.CallerService, "")
	assert.ErrorIs(t, err, mint.ErrDenied)
	_, err = mint.CheckAzure(p, mint.CallerHuman, "")
	assert.ErrorIs(t, err, mint.ErrDenied)

	life, err = mint.CheckAzure(&config.AzureMintPolicy{Resource: "api://r"}, mint.CallerService, "")
	require.NoError(t, err)
	assert.Equal(t, time.Hour, life)
	for name, bad := range map[string]config.AzureMintPolicy{
		"no resource":        {},
		"too long":           {Resource: "r", MaxTTL: 6000},
		"bad authentication": {Resource: "r", Authentication: "automatic"},
		"callers":            {Resource: "r", Callers: []string{"x"}},
	} {
		_, err := mint.CheckAzure(&bad, mint.CallerService, "")
		assert.ErrorIs(t, err, mint.ErrInvalidProviderPolicy, name)
	}
}

func TestCheckOAuth(t *testing.T) {
	p := &config.OAuthMintPolicy{TokenEndpoint: "https://idp.example.com/token", Scopes: []string{"a", "b"}}
	scopes, life, err := mint.CheckOAuth(p, mint.CallerHost, []string{"a"})
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, scopes)
	assert.Equal(t, time.Hour, life)
	_, _, err = mint.CheckOAuth(p, mint.CallerHost, []string{"z"})
	assert.ErrorIs(t, err, mint.ErrDenied)
	_, _, err = mint.CheckOAuth(p, mint.CallerAgent, nil)
	assert.ErrorIs(t, err, mint.ErrDenied)
	_, _, err = mint.CheckOAuth(nil, mint.CallerHost, nil)
	assert.ErrorIs(t, err, mint.ErrDenied)

	for name, bad := range map[string]config.OAuthMintPolicy{
		"plain http":  {TokenEndpoint: "http://idp.example.com/token", Scopes: []string{"a"}},
		"no scopes":   {TokenEndpoint: "https://idp.example.com/token"},
		"empty scope": {TokenEndpoint: "https://idp.example.com/token", Scopes: []string{""}},
		"too long":    {TokenEndpoint: "https://idp.example.com/token", Scopes: []string{"a"}, MaxTTL: 9000},
		"user in url": {TokenEndpoint: "https://u:p@idp.example.com/token", Scopes: []string{"a"}},
	} {
		_, _, err := mint.CheckOAuth(&bad, mint.CallerHost, nil)
		assert.ErrorIs(t, err, mint.ErrInvalidProviderPolicy, name)
	}
}

func TestValidHTTPSEndpoint(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://vault.example.com:8200": true,
		"http://127.0.0.1:8200":          true,
		"http://localhost:8200":          true,
		"http://[::1]:8200":              true,
		"http://vault.example.com":       false,
		"ftp://vault.example.com":        false,
		"https://":                       false,
		"vault.example.com":              false,
		"https://u@vault.example.com":    false,
		"%":                              false,
	} {
		assert.Equal(t, want, mint.ValidHTTPSEndpoint(raw), raw)
	}
}

func assertErr(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		require.NoError(t, err)
		return
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), want)
}
