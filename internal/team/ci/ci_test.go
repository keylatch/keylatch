package ci_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team/ci"
)

// testEnv sets up an httptest.Server serving a JWKS for the given provider,
// mints a signed JWT with the provided claims override, and cleans up on t.Cleanup.
type testEnv struct {
	jwks   *ci.TestJWKS
	server *httptest.Server
}

func newTestEnv(t *testing.T, provider ci.CIProvider) *testEnv {
	t.Helper()
	jwks, err := ci.NewTestJWKS()
	if err != nil {
		t.Fatalf("NewTestJWKS: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks.ServeTestJWKS())
	}))
	ci.SetJWKSOverride(provider, srv.URL)
	t.Cleanup(func() {
		srv.Close()
		ci.ClearJWKSOverride(provider)
	})
	return &testEnv{jwks: jwks, server: srv}
}

func (e *testEnv) mintToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	token, err := ci.MintSignedTestJWT(claims, e.jwks.PrivateKey, e.jwks.KeyID)
	if err != nil {
		t.Fatalf("MintSignedTestJWT: %v", err)
	}
	return token
}

func mintGitHubToken(t *testing.T, env *testEnv, overrides map[string]interface{}) string {
	t.Helper()
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss":        "https://token.actions.githubusercontent.com",
		"sub":        "repo:myorg/myrepo:ref:refs/heads/main",
		"aud":        "keylatch",
		"exp":        now + 3600,
		"iat":        now,
		"repository": "myorg/myrepo",
		"ref":        "refs/heads/main",
		"workflow":   "ci.yml",
	}
	for k, v := range overrides {
		claims[k] = v
	}
	return env.mintToken(t, claims)
}

func TestGitHubActions_Verify_Valid(t *testing.T) {
	env := newTestEnv(t, ci.ProviderGitHubActions)
	token := mintGitHubToken(t, env, nil)
	opts := ci.VerifyOpts{
		Provider:        ci.ProviderGitHubActions,
		Audience:        []string{"keylatch"},
		AllowedRepos:    []string{"myorg/myrepo"},
		AllowedBranches: []string{"main"},
	}
	identity, err := ci.Verify(context.Background(), token, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if identity.Repo != "myorg/myrepo" {
		t.Errorf("Repo = %q, want myorg/myrepo", identity.Repo)
	}
	if identity.Branch != "main" {
		t.Errorf("Branch = %q, want main", identity.Branch)
	}
}

func TestVerify_AudCheck(t *testing.T) {
	env := newTestEnv(t, ci.ProviderGitHubActions)
	token := mintGitHubToken(t, env, map[string]interface{}{
		"aud": "other-service",
	})
	opts := ci.VerifyOpts{
		Provider: ci.ProviderGitHubActions,
		Audience: []string{"keylatch"},
	}
	_, err := ci.Verify(context.Background(), token, opts)
	if err != ci.ErrCIAudMissing {
		t.Errorf("wrong aud: got %v, want ErrCIAudMissing", err)
	}
}

func TestVerify_IssuerMismatch(t *testing.T) {
	env := newTestEnv(t, ci.ProviderGitHubActions)
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss":        "https://evil.example.com",
		"sub":        "repo:myorg/myrepo:ref:refs/heads/main",
		"aud":        "keylatch",
		"exp":        now + 3600,
		"iat":        now,
		"repository": "myorg/myrepo",
		"ref":        "refs/heads/main",
	}
	token := env.mintToken(t, claims)
	opts := ci.VerifyOpts{
		Provider: ci.ProviderGitHubActions,
	}
	_, err := ci.Verify(context.Background(), token, opts)
	if err != ci.ErrCIIssuerMismatch {
		t.Errorf("wrong issuer: got %v, want ErrCIIssuerMismatch", err)
	}
}

func TestVerify_RepoDenied(t *testing.T) {
	env := newTestEnv(t, ci.ProviderGitHubActions)
	token := mintGitHubToken(t, env, nil)
	opts := ci.VerifyOpts{
		Provider:     ci.ProviderGitHubActions,
		AllowedRepos: []string{"other-org/other-repo"},
	}
	_, err := ci.Verify(context.Background(), token, opts)
	if err != ci.ErrCIRepoDenied {
		t.Errorf("repo not in allowlist: got %v, want ErrCIRepoDenied", err)
	}
}

func TestVerify_BranchDenied(t *testing.T) {
	env := newTestEnv(t, ci.ProviderGitHubActions)
	token := mintGitHubToken(t, env, nil)
	opts := ci.VerifyOpts{
		Provider:        ci.ProviderGitHubActions,
		AllowedBranches: []string{"release/*"},
	}
	_, err := ci.Verify(context.Background(), token, opts)
	if err != ci.ErrCIBranchDenied {
		t.Errorf("branch not in allowlist: got %v, want ErrCIBranchDenied", err)
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	env := newTestEnv(t, ci.ProviderGitHubActions)
	token := mintGitHubToken(t, env, map[string]interface{}{
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	opts := ci.VerifyOpts{
		Provider: ci.ProviderGitHubActions,
	}
	_, err := ci.Verify(context.Background(), token, opts)
	if err != ci.ErrTokenExpired {
		t.Errorf("expired token: got %v, want ErrTokenExpired", err)
	}
}

func TestVerify_TamperedToken(t *testing.T) {
	env := newTestEnv(t, ci.ProviderGitHubActions)
	token := mintGitHubToken(t, env, nil)
	// Corrupt the signature by flipping bytes at the end.
	if len(token) > 10 {
		tokenBytes := []byte(token)
		tokenBytes[len(tokenBytes)-5] ^= 0xFF
		token = string(tokenBytes)
	}
	opts := ci.VerifyOpts{
		Provider: ci.ProviderGitHubActions,
	}
	// Tampered token must now return an error (signature invalid).
	_, err := ci.Verify(context.Background(), token, opts)
	if err == nil {
		t.Error("tampered token should return an error, got nil")
	}
}

func TestVerify_GitLabCI(t *testing.T) {
	env := newTestEnv(t, ci.ProviderGitLabCI)
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss":          "https://gitlab.com",
		"sub":          "project_path:mygroup/myproject:ref_type:branch:ref:main",
		"aud":          "keylatch",
		"exp":          now + 3600,
		"project_path": "mygroup/myproject",
		"ref":          "main",
	}
	token := env.mintToken(t, claims)

	opts := ci.VerifyOpts{
		Provider:     ci.ProviderGitLabCI,
		Audience:     []string{"keylatch"},
		AllowedRepos: []string{"mygroup/myproject"},
	}
	identity, err := ci.Verify(context.Background(), token, opts)
	if err != nil {
		t.Fatalf("GitLab Verify: %v", err)
	}
	if identity.Provider != ci.ProviderGitLabCI {
		t.Errorf("Provider = %v, want GitLabCI", identity.Provider)
	}
}

func TestVerify_CircleCI(t *testing.T) {
	env := newTestEnv(t, ci.ProviderCircleCI)
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss": "https://oidc.circleci.com/org",
		"sub": "org/project/user",
		"aud": "keylatch",
		"exp": now + 3600,
	}
	token := env.mintToken(t, claims)
	opts := ci.VerifyOpts{
		Provider: ci.ProviderCircleCI,
	}
	_, err := ci.Verify(context.Background(), token, opts)
	if err != nil {
		t.Errorf("CircleCI Verify: %v", err)
	}
}

func TestVerify_Buildkite(t *testing.T) {
	env := newTestEnv(t, ci.ProviderBuildkite)
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss":           "https://agent.buildkite.com",
		"sub":           "org:org-slug:pipeline:pipeline-slug",
		"aud":           "keylatch",
		"exp":           now + 3600,
		"pipeline_slug": "my-pipeline",
		"branch":        "main",
	}
	token := env.mintToken(t, claims)
	opts := ci.VerifyOpts{
		Provider: ci.ProviderBuildkite,
	}
	identity, err := ci.Verify(context.Background(), token, opts)
	if err != nil {
		t.Errorf("Buildkite Verify: %v", err)
	}
	if identity.Branch != "main" {
		t.Errorf("Branch = %q, want main", identity.Branch)
	}
}

func TestVerify_EmptyRepo_DeniedWhenAllowlistSet(t *testing.T) {
	env := newTestEnv(t, ci.ProviderGitHubActions)
	now := time.Now().Unix()
	// JWT with missing repository claim.
	claims := map[string]interface{}{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "test",
		"aud": "keylatch",
		"exp": now + 3600,
		"ref": "refs/heads/main",
		// "repository" intentionally omitted.
	}
	token := env.mintToken(t, claims)
	opts := ci.VerifyOpts{
		Provider:     ci.ProviderGitHubActions,
		AllowedRepos: []string{"myorg/myrepo"},
	}
	_, err := ci.Verify(context.Background(), token, opts)
	if err != ci.ErrCIRepoDenied {
		t.Errorf("empty repo with allowlist: got %v, want ErrCIRepoDenied", err)
	}
}

func TestVerify_EmptyBranch_DeniedWhenAllowlistSet(t *testing.T) {
	env := newTestEnv(t, ci.ProviderGitHubActions)
	now := time.Now().Unix()
	// JWT with missing branch claim.
	claims := map[string]interface{}{
		"iss":        "https://token.actions.githubusercontent.com",
		"sub":        "test",
		"aud":        "keylatch",
		"exp":        now + 3600,
		"repository": "myorg/myrepo",
		// "ref" intentionally omitted.
	}
	token := env.mintToken(t, claims)
	opts := ci.VerifyOpts{
		Provider:        ci.ProviderGitHubActions,
		AllowedBranches: []string{"main"},
	}
	_, err := ci.Verify(context.Background(), token, opts)
	if err != ci.ErrCIBranchDenied {
		t.Errorf("empty branch with allowlist: got %v, want ErrCIBranchDenied", err)
	}
}

func TestVerify_MissingExpClaim(t *testing.T) {
	env := newTestEnv(t, ci.ProviderGitHubActions)
	claims := map[string]interface{}{
		"iss":        "https://token.actions.githubusercontent.com",
		"sub":        "test",
		"aud":        "keylatch",
		"repository": "myorg/myrepo",
		"ref":        "refs/heads/main",
		// "exp" intentionally omitted.
	}
	token := env.mintToken(t, claims)
	opts := ci.VerifyOpts{
		Provider: ci.ProviderGitHubActions,
	}
	_, err := ci.Verify(context.Background(), token, opts)
	if err == nil {
		t.Error("missing exp claim should return an error")
	}
}

func TestVerify_JWKSUnavailable(t *testing.T) {
	// Point to a server that immediately closes without serving JWKS.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	srv.Close() // closed immediately — will return connection refused

	ci.SetJWKSOverride(ci.ProviderGitHubActions, "http://"+srv.Listener.Addr().String())
	defer ci.ClearJWKSOverride(ci.ProviderGitHubActions)

	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss":        "https://token.actions.githubusercontent.com",
		"sub":        "test",
		"aud":        "keylatch",
		"exp":        now + 3600,
		"repository": "myorg/myrepo",
		"ref":        "refs/heads/main",
	}
	// Use MintTestJWT (no real signing) — won't reach signature check anyway.
	token, _ := ci.MintTestJWT(claims)
	opts := ci.VerifyOpts{
		Provider: ci.ProviderGitHubActions,
	}
	_, err := ci.Verify(context.Background(), token, opts)
	if err != ci.ErrJWKSUnavailable {
		t.Errorf("unreachable JWKS: got %v, want ErrJWKSUnavailable", err)
	}
}
