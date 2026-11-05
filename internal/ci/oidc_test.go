package ci_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/keylatch/keylatch/internal/ci"
	"github.com/keylatch/keylatch/internal/ci/citest"
	"github.com/keylatch/keylatch/internal/config"
)

const aud = "keylatch-ci"

func trust(iss *citest.Issuer) config.CITrust {
	return config.CITrust{
		Provider: ci.GitHubActions, Audience: aud, JWKSURL: iss.JWKSURL,
		Repositories: []string{"acme/app"}, Refs: []string{"refs/heads/main"}, Connections: []string{"github-app"},
	}
}

func verifier() *ci.Verifier { return &ci.Verifier{AllowHTTP: true} }

func TestOIDCAudienceRequired(t *testing.T) {
	iss := citest.NewIssuer(t)
	tok := iss.Sign(t, citest.GitHubClaims(aud, "acme/app", "refs/heads/main"))

	noAud := trust(iss)
	noAud.Audience = ""
	if _, err := verifier().Verify(context.Background(), tok, noAud); !errors.Is(err, ci.ErrTrustInvalid) {
		t.Fatalf("trust without audience: %v, want ErrTrustInvalid", err)
	}

	other := citest.GitHubClaims("someone-else", "acme/app", "refs/heads/main")
	if _, err := verifier().Verify(context.Background(), iss.Sign(t, other), trust(iss)); !errors.Is(err, ci.ErrToken) {
		t.Fatalf("token for another audience: %v, want ErrToken", err)
	}
	missing := citest.GitHubClaims(aud, "acme/app", "refs/heads/main")
	delete(missing, "aud")
	if _, err := verifier().Verify(context.Background(), iss.Sign(t, missing), trust(iss)); !errors.Is(err, ci.ErrToken) {
		t.Fatalf("token without audience: %v, want ErrToken", err)
	}
	if _, err := verifier().Verify(context.Background(), tok, trust(iss)); err != nil {
		t.Fatalf("valid token: %v", err)
	}
}

func TestRefKindExact(t *testing.T) {
	iss := citest.NewIssuer(t)
	tr := trust(iss)
	for _, tc := range []struct {
		name, ref string
		ok        bool
	}{
		{"branch", "refs/heads/main", true},
		{"tag named like the branch", "refs/tags/main", false},
		{"other branch", "refs/heads/feature", false},
		{"prefix of the branch", "refs/heads/main-2", false},
		{"bare name", "main", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier().Verify(context.Background(), iss.Sign(t, citest.GitHubClaims(aud, "acme/app", tc.ref)), tr)
			if tc.ok && err != nil || !tc.ok && !errors.Is(err, ci.ErrRef) {
				t.Fatalf("ref %q: %v", tc.ref, err)
			}
		})
	}

	t.Run("gitlab branch and tag", func(t *testing.T) {
		gl := config.CITrust{
			Provider: ci.GitLab, Audience: aud, JWKSURL: iss.JWKSURL, Issuer: "https://gitlab.example.com",
			Repositories: []string{"grp/app"}, Refs: []string{"refs/heads/main"}, Connections: []string{"c"},
		}
		claims := func(kind string) jwt.MapClaims {
			return jwt.MapClaims{
				"iss": "https://gitlab.example.com", "aud": aud, "exp": time.Now().Add(time.Hour).Unix(),
				"project_path": "grp/app", "ref": "main", "ref_type": kind,
			}
		}
		if _, err := verifier().Verify(context.Background(), iss.Sign(t, claims("branch")), gl); err != nil {
			t.Fatalf("branch: %v", err)
		}
		if _, err := verifier().Verify(context.Background(), iss.Sign(t, claims("tag")), gl); !errors.Is(err, ci.ErrRef) {
			t.Fatalf("tag main against branch main: %v, want ErrRef", err)
		}
		if _, err := verifier().Verify(context.Background(), iss.Sign(t, claims("")), gl); !errors.Is(err, ci.ErrRef) {
			t.Fatalf("unknown ref type: %v, want ErrRef", err)
		}
	})
}

func TestTrustPolicyMatch(t *testing.T) {
	iss := citest.NewIssuer(t)
	good := func() jwt.MapClaims { return citest.GitHubClaims(aud, "acme/app", "refs/heads/main") }
	cases := []struct {
		name   string
		mutate func(jwt.MapClaims, *config.CITrust)
		want   error
	}{
		{"accepted", func(jwt.MapClaims, *config.CITrust) {}, nil},
		{"wrong repository", func(c jwt.MapClaims, _ *config.CITrust) { c["repository"] = "acme/other" }, ci.ErrRepository},
		{"repository glob", func(c jwt.MapClaims, tr *config.CITrust) {
			c["repository"] = "acme/other"
			tr.Repositories = []string{"acme/*"}
		}, nil},
		{"no repository claim", func(c jwt.MapClaims, _ *config.CITrust) { delete(c, "repository") }, ci.ErrRepository},
		{"environment listed", func(_ jwt.MapClaims, tr *config.CITrust) { tr.Environments = []string{"prod"} }, nil},
		{"environment not listed", func(_ jwt.MapClaims, tr *config.CITrust) { tr.Environments = []string{"staging"} }, ci.ErrEnvironment},
		{"no environment claim", func(c jwt.MapClaims, tr *config.CITrust) {
			delete(c, "environment")
			tr.Environments = []string{"prod"}
		}, ci.ErrEnvironment},
		{"workflow pinned", func(_ jwt.MapClaims, tr *config.CITrust) {
			tr.JobWorkflowRefs = []string{"acme/app/.github/workflows/deploy.yml@refs/heads/main"}
		}, nil},
		{"workflow differs", func(_ jwt.MapClaims, tr *config.CITrust) {
			tr.JobWorkflowRefs = []string{"acme/app/.github/workflows/release.yml@refs/heads/main"}
		}, ci.ErrWorkflow},
		{"wrong issuer", func(c jwt.MapClaims, _ *config.CITrust) { c["iss"] = "https://evil.example.com" }, ci.ErrToken},
		{"expired", func(c jwt.MapClaims, _ *config.CITrust) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, ci.ErrToken},
		{"no expiry", func(c jwt.MapClaims, _ *config.CITrust) { delete(c, "exp") }, ci.ErrToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims, tr := good(), trust(iss)
			tc.mutate(claims, &tr)
			id, err := verifier().Verify(context.Background(), iss.Sign(t, claims), tr)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if tc.want == nil && id.Provider != ci.GitHubActions {
				t.Fatalf("identity: %+v", id)
			}
		})
	}
}

func TestVerifyRejectsForgedTokens(t *testing.T) {
	iss := citest.NewIssuer(t)
	tr := trust(iss)
	claims := citest.GitHubClaims(aud, "acme/app", "refs/heads/main")

	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	hmacKey := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	hmacKey.Header["kid"] = citest.KeyID
	hs, _ := hmacKey.SignedString(iss.Key.N.Bytes())

	other := citest.NewIssuer(t)
	forged := other.Sign(t, claims)
	tampered := iss.Sign(t, claims)
	tampered = tampered[:len(tampered)-4] + "AAAA"

	for name, tok := range map[string]string{"alg none": none, "hmac with public key": hs, "other signer": forged, "tampered": tampered, "garbage": "x.y.z"} {
		if _, err := verifier().Verify(context.Background(), tok, tr); !errors.Is(err, ci.ErrToken) {
			t.Errorf("%s: %v, want ErrToken", name, err)
		}
	}
}

func TestVerifyKeysFailClosed(t *testing.T) {
	iss := citest.NewIssuer(t)
	tr := trust(iss)
	tok := iss.Sign(t, citest.GitHubClaims(aud, "acme/app", "refs/heads/main"))

	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	tr.JWKSURL = down.URL
	if _, err := verifier().Verify(context.Background(), tok, tr); !errors.Is(err, ci.ErrKeys) {
		t.Fatalf("unreachable key set: %v, want ErrKeys", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"keys":[]}`)) }))
	defer bad.Close()
	tr.JWKSURL = bad.URL
	if _, err := verifier().Verify(context.Background(), tok, tr); !errors.Is(err, ci.ErrKeys) {
		t.Fatalf("empty key set: %v, want ErrKeys", err)
	}

	if _, err := (&ci.Verifier{}).Verify(context.Background(), tok, trust(iss)); !errors.Is(err, ci.ErrTrustInvalid) {
		t.Fatalf("http key set without AllowHTTP: %v, want ErrTrustInvalid", err)
	}
}

func TestVerifyCachesKeysAndAcceptsEC(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, _ := ec.PublicKey.Bytes()
	enc := base64.RawURLEncoding.EncodeToString
	doc, _ := json.Marshal(map[string]any{"keys": []any{
		map[string]string{"kty": "EC", "kid": "ec1", "crv": "P-256", "x": enc(point[1:33]), "y": enc(point[33:])},
		map[string]string{"kty": "oct", "kid": "skip"},
		map[string]string{"kty": "EC", "kid": "bad", "crv": "P-192"},
	}})
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++; _, _ = w.Write(doc) }))
	defer srv.Close()
	tr := config.CITrust{
		Provider: ci.GitHubActions, Audience: aud, JWKSURL: srv.URL,
		Repositories: []string{"acme/app"}, Refs: []string{"refs/heads/main"}, Connections: []string{"c"},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, citest.GitHubClaims(aud, "acme/app", "refs/heads/main"))
	tok.Header["kid"] = "ec1"
	raw, err := tok.SignedString(ec)
	if err != nil {
		t.Fatal(err)
	}
	v := verifier()
	for range 3 {
		if _, err := v.Verify(context.Background(), raw, tr); err != nil {
			t.Fatalf("ES256 token: %v", err)
		}
	}
	if hits != 1 {
		t.Fatalf("key set fetched %d times, want 1", hits)
	}
	unknown := jwt.NewWithClaims(jwt.SigningMethodES256, citest.GitHubClaims(aud, "acme/app", "refs/heads/main"))
	unknown.Header["kid"] = "rotated"
	raw2, _ := unknown.SignedString(ec)
	if _, err := v.Verify(context.Background(), raw2, tr); !errors.Is(err, ci.ErrToken) {
		t.Fatalf("unknown key id: %v, want ErrToken", err)
	}
}

func TestValidateRejectsUnsafeTrust(t *testing.T) {
	ok := config.CITrust{
		Provider: ci.GitHubActions, Audience: aud,
		Repositories: []string{"acme/app"}, Refs: []string{"refs/tags/v*"}, Connections: []string{"c"},
	}
	if err := ci.Validate(ok); err != nil {
		t.Fatalf("valid trust: %v", err)
	}
	for name, mutate := range map[string]func(*config.CITrust){
		"provider":         func(c *config.CITrust) { c.Provider = "jenkins" },
		"audience":         func(c *config.CITrust) { c.Audience = " " },
		"no repositories":  func(c *config.CITrust) { c.Repositories = nil },
		"any repository":   func(c *config.CITrust) { c.Repositories = []string{"*"} },
		"no refs":          func(c *config.CITrust) { c.Refs = nil },
		"bare branch":      func(c *config.CITrust) { c.Refs = []string{"main"} },
		"no connections":   func(c *config.CITrust) { c.Connections = nil },
		"ttl":              func(c *config.CITrust) { c.MaxTTL = 7200 },
		"http issuer":      func(c *config.CITrust) { c.Issuer = "http://idp.example.com" },
		"http key set url": func(c *config.CITrust) { c.JWKSURL = "http://idp.example.com/keys" },
	} {
		c := ok
		mutate(&c)
		if err := ci.Validate(c); !errors.Is(err, ci.ErrTrustInvalid) {
			t.Errorf("%s: %v, want ErrTrustInvalid", name, err)
		}
	}
}

func TestVerifyAnyPicksTheAcceptingEntry(t *testing.T) {
	iss := citest.NewIssuer(t)
	deny, allow := trust(iss), trust(iss)
	deny.Repositories = []string{"acme/other"}
	deny.Connections = []string{"denied"}
	allow.Connections = []string{"allowed"}
	tok := iss.Sign(t, citest.GitHubClaims(aud, "acme/app", "refs/heads/main"))

	got, id, err := verifier().VerifyAny(context.Background(), tok, []config.CITrust{deny, allow}, ci.GitHubActions, aud)
	if err != nil || got.Connections[0] != "allowed" || id.Repository != "acme/app" {
		t.Fatalf("VerifyAny: %v %v %+v", err, got.Connections, id)
	}
	if _, _, err := verifier().VerifyAny(context.Background(), tok, []config.CITrust{deny}, ci.GitHubActions, aud); !errors.Is(err, ci.ErrRepository) {
		t.Fatalf("only the denying entry: %v, want ErrRepository", err)
	}
	if _, _, err := verifier().VerifyAny(context.Background(), tok, []config.CITrust{allow}, ci.GitLab, aud); !errors.Is(err, ci.ErrNoTrustMatch) {
		t.Fatalf("other provider: %v, want ErrNoTrustMatch", err)
	}
	if !strings.Contains(ci.ErrNoTrustMatch.Error(), "no trust entry") {
		t.Fatal("error text changed")
	}
}
