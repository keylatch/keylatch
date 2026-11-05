package mintsession_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/mintsession"
	"github.com/keylatch/keylatch/internal/mintsession/mintsessiontest"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixture struct {
	stub  *mintsessiontest.Stub
	store *mintsessiontest.Store
	audit *testutil.AuditRecorder
	m     *mintsession.Minter
}

func policy() *config.GitHubAppMintPolicy {
	return &config.GitHubAppMintPolicy{
		PlaceholderCallers: []string{"agent"},
		AllowOwners:        []string{mintsessiontest.Owner},
		DenyOwners:         []string{"blocked"},
		PermissionCeiling:  map[string]string{"contents": "write", "pull_requests": "write"},
	}
}

func setup(t *testing.T, p *config.GitHubAppMintPolicy) *fixture {
	t.Helper()
	require.NoError(t, registry.InitFromConfig(context.Background(), os.Getenv))
	store, err := mintsessiontest.NewStore()
	require.NoError(t, err)
	f := &fixture{stub: mintsessiontest.NewStub(), store: store, audit: &testutil.AuditRecorder{}}
	t.Cleanup(f.stub.Close)
	cfg := config.Default()
	if p != nil {
		cfg.Connections = map[string]config.ConnectionPolicy{"github-app": {Mint: &config.MintPolicy{GitHubApp: p}}}
	}
	f.m = mintsession.New(mintsession.Config{
		Store: store, APIBase: f.stub.URL, Policy: func() (config.Config, error) { return cfg, nil }, Audit: f.audit,
	})
	return f
}

func req(repo string, perms ...string) mintsession.Request {
	return mintsession.Request{Connection: "github-app", Repository: repo, Permissions: perms, Caller: mint.CallerAgent}
}

func TestOpenMintsNothingAndReadsNoKey(t *testing.T) {
	f := setup(t, policy())
	cred, err := f.m.Open(context.Background(), req(mintsessiontest.Owner+"/app", "contents=write"))
	require.NoError(t, err)
	t.Cleanup(cred.Close)
	assert.Zero(t, f.store.Reads(), "opening a session must not read key material")
	assert.Empty(t, f.stub.Mints())
	assert.Empty(t, f.audit.Events())
}

func TestOpenRefusals(t *testing.T) {
	cases := []struct {
		name   string
		policy func() *config.GitHubAppMintPolicy
		req    mintsession.Request
		denied bool
		usage  bool
		text   string
	}{
		{"no policy", func() *config.GitHubAppMintPolicy { return nil }, req("patrikmichi/app", "contents=write"), true, false, "no mint.github_app policy"},
		{"agent not listed", func() *config.GitHubAppMintPolicy {
			p := policy()
			p.PlaceholderCallers = nil
			return p
		}, req("patrikmichi/app", "contents=write"), true, false, "not allowed to use minted tokens"},
		{"host not listed", policy, mintsession.Request{Connection: "github-app", Repository: "patrikmichi/app", Permissions: []string{"contents=write"}, Caller: mint.CallerHost}, true, false, `"host"`},
		{"denied owner", func() *config.GitHubAppMintPolicy {
			p := policy()
			p.AllowOwners = append(p.AllowOwners, "blocked")
			return p
		}, req("blocked/app", "contents=write"), true, false, "deny list"},
		{"owner not allowed", policy, req("other/app", "contents=write"), true, false, "not in allow_owners"},
		{"above ceiling", policy, req("patrikmichi/app", "contents=admin"), true, false, "above the ceiling"},
		{"permission not granted", policy, req("patrikmichi/app", "workflows=write"), true, false, "above the ceiling"},
		{"no repository", policy, req("", "contents=write"), false, true, "--repo"},
		{"bad repository", policy, req("nonsense", "contents=write"), false, true, "owner/name"},
		{"bad permission", policy, req("patrikmichi/app", "contents"), false, true, "permission"},
		{"duplicate permission", policy, req("patrikmichi/app", "contents=read", "contents=write"), false, true, "more than once"},
		{"not a minting connection", policy, mintsession.Request{Connection: "stripe", Repository: "patrikmichi/app", Caller: mint.CallerAgent}, false, true, "mints tokens"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, tc.policy())
			_, err := f.m.Open(context.Background(), tc.req)
			require.Error(t, err)
			assert.Equal(t, tc.denied, errors.Is(err, mint.ErrDenied), err.Error())
			assert.Equal(t, tc.usage, errors.Is(err, mintsession.ErrUsage), err.Error())
			assert.Contains(t, err.Error(), tc.text)
			assert.Zero(t, f.store.Reads())
			assert.Empty(t, f.stub.Mints())
		})
	}
}

func TestOpenDefaultsToTheOnlyAllowedRepoAndTheCeiling(t *testing.T) {
	p := policy()
	p.AllowOwners = nil
	p.AllowRepos = []string{"patrikmichi/only"}
	f := setup(t, p)
	cred, err := f.m.Open(context.Background(), req(""))
	require.NoError(t, err)
	t.Cleanup(cred.Close)
	_, err = cred.Value(context.Background(), mintsession.TokenField)
	require.NoError(t, err)
	mints := f.stub.Mints()
	require.Len(t, mints, 1)
	assert.Equal(t, []any{"only"}, mints[0]["repositories"])
	assert.Equal(t, map[string]any{"contents": "write", "pull_requests": "write"}, mints[0]["permissions"])
}

func TestOpenRefusesWithoutAuditLog(t *testing.T) {
	f := setup(t, policy())
	m := mintsession.New(mintsession.Config{Store: f.store, APIBase: f.stub.URL, Policy: func() (config.Config, error) {
		cfg := config.Default()
		cfg.Connections = map[string]config.ConnectionPolicy{"github-app": {Mint: &config.MintPolicy{GitHubApp: policy()}}}
		return cfg, nil
	}})
	_, err := m.Open(context.Background(), req("patrikmichi/app", "contents=write"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit")
}

func TestValueMintsLazilyCachesAndReturnsCopies(t *testing.T) {
	f := setup(t, policy())
	cred, err := f.m.Open(context.Background(), req("patrikmichi/app", "contents=write"))
	require.NoError(t, err)
	t.Cleanup(cred.Close)

	a, err := cred.Value(context.Background(), mintsession.TokenField)
	require.NoError(t, err)
	assert.Equal(t, mintsessiontest.Token(1), string(a))
	clear(a)
	b, err := cred.Value(context.Background(), mintsession.TokenField)
	require.NoError(t, err)
	assert.Equal(t, mintsessiontest.Token(1), string(b), "wiping a returned value must not touch the cache")
	assert.Len(t, f.stub.Mints(), 1, "the second read is served from memory")

	events := f.audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, audit.ActionMint, events[0].Action)
	assert.Equal(t, "placeholder", events[0].RuntimeMode)
	assert.Equal(t, "agent", events[0].Extra["caller_kind"])
	raw, _ := json.Marshal(events)
	assert.NotContains(t, string(raw), "ghs_")
}

func TestValueRefreshesShortlyBeforeExpiry(t *testing.T) {
	f := setup(t, policy())
	f.stub.Lifetime = 90 * time.Second
	cred, err := f.m.Open(context.Background(), req("patrikmichi/app", "contents=write"))
	require.NoError(t, err)
	t.Cleanup(cred.Close)

	first, err := cred.Value(context.Background(), mintsession.TokenField)
	require.NoError(t, err)
	second, err := cred.Value(context.Background(), mintsession.TokenField)
	require.NoError(t, err)
	assert.Equal(t, mintsessiontest.Token(1), string(first))
	assert.Equal(t, mintsessiontest.Token(2), string(second), "a token inside the refresh margin is replaced")
}

func TestValueRejectsOtherFieldsAndWidenedTokens(t *testing.T) {
	f := setup(t, policy())
	cred, err := f.m.Open(context.Background(), req("patrikmichi/app", "contents=write"))
	require.NoError(t, err)
	t.Cleanup(cred.Close)
	_, err = cred.Value(context.Background(), "private_key")
	require.Error(t, err)
	assert.Zero(t, f.store.Reads(), "a wrong field name must not read the store")

	f.stub.Widen = true
	_, err = cred.Value(context.Background(), mintsession.TokenField)
	require.Error(t, err)
	assert.Equal(t, []string{mintsessiontest.Token(1)}, f.stub.Revoked(), "a token wider than requested is revoked")
	events := f.audit.Events()
	require.Len(t, events, 1)
	assert.Equal(t, audit.OutcomeError, events[0].Outcome)
	assert.Equal(t, "scope_mismatch", events[0].Extra["reason"])
}

func TestCloseRevokesAndWipes(t *testing.T) {
	f := setup(t, policy())
	cred, err := f.m.Open(context.Background(), req("patrikmichi/app", "contents=write"))
	require.NoError(t, err)
	_, err = cred.Value(context.Background(), mintsession.TokenField)
	require.NoError(t, err)

	cred.Close()
	assert.Equal(t, []string{mintsessiontest.Token(1)}, f.stub.Revoked())
	_, err = cred.Value(context.Background(), mintsession.TokenField)
	require.Error(t, err)
	assert.Len(t, f.stub.Mints(), 1, "a closed session mints nothing")
	cred.Close()
	assert.Len(t, f.stub.Revoked(), 1)
}

func TestCloseBeforeFirstUseRevokesNothing(t *testing.T) {
	f := setup(t, policy())
	cred, err := f.m.Open(context.Background(), req("patrikmichi/app", "contents=write"))
	require.NoError(t, err)
	cred.Close()
	assert.Empty(t, f.stub.Revoked())
}

type failingAudit struct{ after int }

func (a *failingAudit) Emit(context.Context, audit.Event) error {
	if a.after > 0 {
		a.after--
		return nil
	}
	return errors.New("disk full")
}

func TestUnauditedTokenIsRevoked(t *testing.T) {
	f := setup(t, policy())
	cfg := config.Default()
	cfg.Connections = map[string]config.ConnectionPolicy{"github-app": {Mint: &config.MintPolicy{GitHubApp: policy()}}}
	m := mintsession.New(mintsession.Config{Store: f.store, APIBase: f.stub.URL, Policy: func() (config.Config, error) { return cfg, nil }, Audit: &failingAudit{after: 0}})
	cred, err := m.Open(context.Background(), req("patrikmichi/app", "contents=write"))
	require.NoError(t, err)
	_, err = cred.Value(context.Background(), mintsession.TokenField)
	require.Error(t, err)
	assert.Equal(t, []string{mintsessiontest.Token(1)}, f.stub.Revoked())
}
