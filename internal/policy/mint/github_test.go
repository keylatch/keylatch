package mint_test

import (
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func basePolicy() *config.GitHubAppMintPolicy {
	return &config.GitHubAppMintPolicy{
		DenyOwners:        []string{"abugodev"},
		AllowOwners:       []string{"patrikmichi"},
		AllowRepos:        []string{"keylatch/keylatch", "abugodev/site"},
		PermissionCeiling: map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"},
		MaxTTL:            3600,
	}
}

func req(repo string, perms map[string]string) mint.Request {
	return mint.Request{Repository: repo, Permissions: perms}
}

var contentsWrite = map[string]string{"contents": "write", "metadata": "read"}

func TestMintDenyOwnerWinsOverAllowRepos(t *testing.T) {
	err := mint.CheckGitHubApp(basePolicy(), mint.CallerService, req("abugodev/site", contentsWrite))
	require.ErrorIs(t, err, mint.ErrDenied)
	assert.Contains(t, err.Error(), "deny list")

	err = mint.CheckGitHubApp(basePolicy(), mint.CallerService, req("AbugoDev/site", contentsWrite))
	require.ErrorIs(t, err, mint.ErrDenied, "owner matching ignores case")
}

func TestMintAllowlistAndCeiling(t *testing.T) {
	p := basePolicy()
	assert.NoError(t, mint.CheckGitHubApp(p, mint.CallerService, req("patrikmichi/any", contentsWrite)))
	assert.NoError(t, mint.CheckGitHubApp(p, mint.CallerHost, req("keylatch/keylatch", map[string]string{"contents": "read"})))

	err := mint.CheckGitHubApp(p, mint.CallerService, req("keylatch/other", contentsWrite))
	assert.ErrorIs(t, err, mint.ErrDenied, "repo neither owner-allowed nor listed")

	err = mint.CheckGitHubApp(p, mint.CallerService, req("patrikmichi/any", map[string]string{"workflows": "write"}))
	assert.ErrorIs(t, err, mint.ErrDenied, "permission absent from the ceiling")

	err = mint.CheckGitHubApp(p, mint.CallerService, req("patrikmichi/any", map[string]string{"metadata": "write"}))
	assert.ErrorIs(t, err, mint.ErrDenied, "level above the ceiling")

	err = mint.CheckGitHubApp(p, mint.CallerService, req("patrikmichi/any", map[string]string{"contents": "admin"}))
	assert.ErrorIs(t, err, mint.ErrDenied)

	err = mint.CheckGitHubApp(p, mint.CallerService, req("patrikmichi/any", nil))
	assert.ErrorIs(t, err, mint.ErrDenied, "empty permission set")
}

func TestMintEmptyAllowlistsDenyEverything(t *testing.T) {
	p := basePolicy()
	p.AllowOwners, p.AllowRepos = nil, nil
	assert.ErrorIs(t, mint.CheckGitHubApp(p, mint.CallerService, req("patrikmichi/any", contentsWrite)), mint.ErrDenied)

	p = basePolicy()
	p.PermissionCeiling = nil
	assert.ErrorIs(t, mint.CheckGitHubApp(p, mint.CallerService, req("patrikmichi/any", contentsWrite)), mint.ErrDenied)
}

func TestMintNilPolicyDenies(t *testing.T) {
	assert.ErrorIs(t, mint.CheckGitHubApp(nil, mint.CallerService, req("patrikmichi/any", contentsWrite)), mint.ErrDenied)
}

func TestMintAgentDeniedByDefault(t *testing.T) {
	p := basePolicy()
	assert.ErrorIs(t, mint.CheckGitHubApp(p, mint.CallerAgent, req("patrikmichi/any", contentsWrite)), mint.ErrDenied)
	assert.ErrorIs(t, mint.CheckGitHubApp(nil, mint.CallerAgent, req("patrikmichi/any", contentsWrite)), mint.ErrDenied)

	p.Callers = []string{"agent"}
	assert.ErrorIs(t, mint.CheckGitHubApp(p, mint.CallerAgent, req("patrikmichi/any", contentsWrite)), mint.ErrDenied)
	assert.ErrorIs(t, mint.Validate(p), mint.ErrInvalidPolicy)
}

func TestMintCallerKinds(t *testing.T) {
	p := basePolicy()
	assert.NoError(t, mint.CheckGitHubApp(p, mint.CallerService, req("patrikmichi/a", contentsWrite)))
	assert.NoError(t, mint.CheckGitHubApp(p, mint.CallerHost, req("patrikmichi/a", contentsWrite)))
	assert.ErrorIs(t, mint.CheckGitHubApp(p, mint.CallerHuman, req("patrikmichi/a", contentsWrite)), mint.ErrDenied,
		"humans are not in the default caller set")

	p.Callers = []string{"service"}
	assert.ErrorIs(t, mint.CheckGitHubApp(p, mint.CallerHost, req("patrikmichi/a", contentsWrite)), mint.ErrDenied)

	p.Callers = []string{"human"}
	assert.NoError(t, mint.CheckGitHubApp(p, mint.CallerHuman, req("patrikmichi/a", contentsWrite)))

	p.Callers = []string{"robot"}
	assert.ErrorIs(t, mint.CheckGitHubApp(p, mint.CallerService, req("patrikmichi/a", contentsWrite)), mint.ErrInvalidPolicy)
}

func TestMintMaxTTLValidated(t *testing.T) {
	for _, ttl := range []int{-1, 3601, 86400} {
		p := basePolicy()
		p.MaxTTL = ttl
		assert.ErrorIs(t, mint.Validate(p), mint.ErrInvalidPolicy, "max_ttl %d", ttl)
		assert.ErrorIs(t, mint.CheckGitHubApp(p, mint.CallerService, req("patrikmichi/a", contentsWrite)), mint.ErrInvalidPolicy)
	}
	p := basePolicy()
	p.MaxTTL = 0
	assert.Equal(t, time.Hour, mint.MaxLifetime(p))
	p.MaxTTL = 1800
	assert.NoError(t, mint.Validate(p))
	assert.Equal(t, 30*time.Minute, mint.MaxLifetime(p))
}

func TestMintInvalidCeilingOrRepoInPolicy(t *testing.T) {
	p := basePolicy()
	p.PermissionCeiling["contents"] = "owner"
	assert.ErrorIs(t, mint.Validate(p), mint.ErrInvalidPolicy)

	p = basePolicy()
	p.AllowRepos = []string{"no-slash"}
	assert.ErrorIs(t, mint.Validate(p), mint.ErrInvalidPolicy)
}

func TestParseRepository(t *testing.T) {
	o, n, err := mint.ParseRepository("patrikmichi/keylatch.go")
	require.NoError(t, err)
	assert.Equal(t, "patrikmichi", o)
	assert.Equal(t, "keylatch.go", n)
	for _, bad := range []string{"", "a", "a/", "/b", "a/b/c", "a/..", "-a/b", "a b/c", "a/b?x"} {
		_, _, err := mint.ParseRepository(bad)
		assert.Error(t, err, bad)
	}
}

func TestParsePermission(t *testing.T) {
	k, v, err := mint.ParsePermission("pull_requests=write")
	require.NoError(t, err)
	assert.Equal(t, "pull_requests", k)
	assert.Equal(t, "write", v)
	for _, bad := range []string{"contents", "contents=", "=read", "Contents=read", "contents=owner", "a-b=read"} {
		_, _, err := mint.ParsePermission(bad)
		assert.Error(t, err, bad)
	}
}
