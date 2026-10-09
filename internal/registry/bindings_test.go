package registry

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bareTemplate = `
provider: %s
display_name: Bare
category: ai
secret_fields:
  - name: api_key
    required: true
    sensitive: true
auth_flow: api_key
storage_path_tpl: "{{.Namespace}}/ai/bare/{{.Account}}"
trust_level: 0
runtime_support:
  preferred: gateway_typed
test_strategy:
  kind: http_get
  endpoint: https://api.example.com/v1
  expect:
    status_code: 200
`

func TestValidateTemplateBytes_CoreProviderWithoutBindingsRejected(t *testing.T) {
	for _, p := range []string{"github", "vercel", "supabase", "stripe", "openai", "anthropic"} {
		y := strings.Replace(bareTemplate, "%s", p, 1)
		err := ValidateTemplateBytes([]byte(y))
		require.Error(t, err, p)
		assert.Contains(t, err.Error(), "hosts required", p)
	}
}

func TestValidateTemplateBytes_NonCoreWithoutBindingsAccepted(t *testing.T) {
	require.NoError(t, ValidateTemplateBytes([]byte(strings.Replace(bareTemplate, "%s", "acme", 1))))
}

func TestValidateBindings_Rejections(t *testing.T) {
	base := func() ConnectionTemplate {
		return ConnectionTemplate{
			Provider:         "acme",
			SecretFields:     []SecretField{{Name: "k"}},
			Hosts:            []string{"api.acme.test"},
			Slots:            []Slot{{Field: "k", In: SlotHeader, Name: "x-key", Hosts: []string{"api.acme.test"}}},
			PlaceholderShape: PlaceholderShape{Prefix: "ak_", MinLength: 16},
			EnvClass:         EnvClassSpec{Default: EnvProd},
		}
	}
	require.NoError(t, ValidateBindings(base()))

	cases := map[string]func(*ConnectionTemplate){
		"unknown field":      func(c *ConnectionTemplate) { c.Slots[0].Field = "nope" },
		"header no name":     func(c *ConnectionTemplate) { c.Slots[0].Name = "" },
		"basic no part":      func(c *ConnectionTemplate) { c.Slots[0] = Slot{Field: "k", In: SlotBasic, Hosts: c.Hosts} },
		"bad location":       func(c *ConnectionTemplate) { c.Slots[0].In = "body" },
		"slot host outside":  func(c *ConnectionTemplate) { c.Slots[0].Hosts = []string{"evil.test"} },
		"slot without hosts": func(c *ConnectionTemplate) { c.Slots[0].Hosts = nil },
		"bare wildcard":      func(c *ConnectionTemplate) { c.Hosts = []string{"*"} },
		"tld wildcard":       func(c *ConnectionTemplate) { c.Hosts = []string{"*.com"} },
		"inner wildcard":     func(c *ConnectionTemplate) { c.Hosts = []string{"api.*.test"} },
		"url as host":        func(c *ConnectionTemplate) { c.Hosts = []string{"https://api.acme.test"} },
		"bad adapter":        func(c *ConnectionTemplate) { c.Adapter = Adapter{Kind: "smtp", Field: "k", Hosts: c.Hosts} },
		"adapter field":      func(c *ConnectionTemplate) { c.Adapter = Adapter{Kind: AdapterPostgres, Field: "x", Hosts: c.Hosts} },
		"short min length":   func(c *ConnectionTemplate) { c.PlaceholderShape.MinLength = 1 },
		"bad env class":      func(c *ConnectionTemplate) { c.EnvClass.Default = "staging" },
	}
	for name, mut := range cases {
		c := base()
		mut(&c)
		assert.Error(t, ValidateBindings(c), name)
	}
}

func TestMatchAuthority(t *testing.T) {
	cases := []struct {
		pattern, authority string
		want               bool
	}{
		{"api.stripe.com", "api.stripe.com", true},
		{"api.stripe.com", "API.Stripe.com:443", true},
		{"api.stripe.com", "api.stripe.com:8443", false},
		{"api.stripe.com", "evil.api.stripe.com", false},
		{"api.stripe.com", "api.stripe.com.evil.test", false},
		{"*.supabase.co", "abc.supabase.co", true},
		{"*.supabase.co", "db.abc.supabase.co", true},
		{"*.supabase.co", "supabase.co", false},
		{"*.supabase.co", "evilsupabase.co", false},
		{"*.supabase.co:5432", "db.abc.supabase.co:5432", true},
		{"*.supabase.co:5432", "db.abc.supabase.co", false},
		{"api.stripe.com", "api.stripe.com@evil.test", false},
		{"api.stripe.com", "api.stripe.com.", false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, MatchAuthority(c.pattern, c.authority), "%s vs %s", c.pattern, c.authority)
	}
}

func TestPlaceholderShapeAndEnvClass(t *testing.T) {
	s := PlaceholderShape{Prefix: "sk_", MinLength: 12}
	p := s.Wrap("abc")
	assert.True(t, s.Matches(p))
	assert.Len(t, p, 12)
	assert.False(t, s.Matches("pk_abcdefghijk"))

	c := EnvClassSpec{Default: EnvProd, ByPrefix: map[string]EnvClass{"sk_test_": EnvTest, "sk_": EnvDev}}
	assert.Equal(t, EnvTest, c.Classify("sk_test_x"))
	assert.Equal(t, EnvDev, c.Classify("sk_other"))
	assert.Equal(t, EnvProd, c.Classify("zzz"))
}

func TestBindingFor(t *testing.T) {
	b, err := BindingFor("stripe")
	require.NoError(t, err)
	assert.True(t, b.AllowsHost("api.stripe.com:443"))
	assert.False(t, b.AllowsHost("evil.test"))
	assert.Len(t, b.SlotsFor("secret_key", "files.stripe.com"), 2)
	assert.Empty(t, b.SlotsFor("secret_key", "evil.test"))

	_, err = BindingFor("no-such-provider")
	assert.ErrorIs(t, err, ErrProviderNotFound)
	_, err = BindingFor("google-workspace")
	assert.Error(t, err)
}

func TestCoreProvidersDeclareValidBindings(t *testing.T) {
	for p := range coreProviders {
		tmpl, err := Get(p)
		require.NoError(t, err, p)
		require.NoError(t, ValidateBindings(tmpl), p)
		b, ok := tmpl.Binding()
		require.True(t, ok, p)
		assert.NotEmpty(t, b.Slots, p)
	}
}

// clientCase reproduces the request an official client sends for a provider.
type clientCase struct {
	name      string
	provider  string
	field     string
	authority string // authority the real client connects to
	build     func(base, ph string) *http.Request
}

func newReq(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, rawURL, nil)
	require.NoError(t, err)
	return r
}

func clientCases(t *testing.T) []clientCase {
	bearer := func(path, scheme string) func(base, ph string) *http.Request {
		return func(base, ph string) *http.Request {
			r := newReq(t, http.MethodGet, base+path)
			r.Header.Set("Authorization", scheme+" "+ph)
			return r
		}
	}
	return []clientCase{
		{"github rest bearer (octokit, go-github)", "github", "token", "api.github.com", bearer("/user", "Bearer")},
		{"github rest token scheme (gh cli, octokit pat)", "github", "token", "api.github.com", bearer("/user", "token")},
		{"github release upload", "github", "token", "uploads.github.com", bearer("/repos/o/r/releases/1/assets", "Bearer")},
		{"github git over https", "github", "token", "github.com", func(base, ph string) *http.Request {
			r := newReq(t, http.MethodGet, base+"/o/r.git/info/refs?service=git-upload-pack")
			r.SetBasicAuth("x-access-token", ph)
			return r
		}},
		{"vercel cli", "vercel", "api_token", "api.vercel.com", bearer("/v2/user", "Bearer")},
		{"supabase-js legacy key", "supabase", "service_role_key", "abc.supabase.co", func(base, ph string) *http.Request {
			r := newReq(t, http.MethodGet, base+"/rest/v1/items")
			r.Header.Set("apikey", ph)
			r.Header.Set("Authorization", "Bearer "+ph)
			return r
		}},
		{"supabase new-style key header only", "supabase", "service_role_key", "abc.supabase.co", func(base, ph string) *http.Request {
			r := newReq(t, http.MethodGet, base+"/rest/v1/items")
			r.Header.Set("apikey", ph)
			return r
		}},
		{"supabase realtime websocket upgrade", "supabase", "anon_key", "abc.supabase.co", func(base, ph string) *http.Request {
			r := newReq(t, http.MethodGet, base+"/realtime/v1/websocket?"+url.Values{"apikey": {ph}, "vsn": {"1.0.0"}}.Encode())
			r.Header.Set("Upgrade", "websocket")
			return r
		}},
		{"supabase management api", "supabase", "access_token", "api.supabase.com", bearer("/v1/projects", "Bearer")},
		{"stripe-node bearer", "stripe", "secret_key", "api.stripe.com", bearer("/v1/balance", "Bearer")},
		{"stripe curl basic user", "stripe", "secret_key", "api.stripe.com", func(base, ph string) *http.Request {
			r := newReq(t, http.MethodGet, base+"/v1/charges")
			r.SetBasicAuth(ph, "")
			return r
		}},
		{"stripe file upload", "stripe", "secret_key", "files.stripe.com", bearer("/v1/files", "Bearer")},
		{"openai sdk", "openai", "api_key", "api.openai.com", bearer("/v1/chat/completions", "Bearer")},
		{"anthropic sdk", "anthropic", "api_key", "api.anthropic.com", func(base, ph string) *http.Request {
			r := newReq(t, http.MethodPost, base+"/v1/messages")
			r.Header.Set("x-api-key", ph)
			r.Header.Set("anthropic-version", "2023-06-01")
			return r
		}},
	}
}

type position struct {
	in           SlotLocation
	name, scheme string
	part         string
}

// placeholderPositions lists every request position that carries ph.
func placeholderPositions(r *http.Request, ph string) []position {
	var out []position
	for name, vals := range r.Header {
		for _, v := range vals {
			if name == "Authorization" {
				scheme, cred, _ := strings.Cut(v, " ")
				if scheme == "Basic" {
					raw, err := base64.StdEncoding.DecodeString(cred)
					if err == nil {
						user, pass, _ := strings.Cut(string(raw), ":")
						if user == ph {
							out = append(out, position{in: SlotBasic, part: BasicUser})
						}
						if pass == ph {
							out = append(out, position{in: SlotBasic, part: BasicPassword})
						}
					}
					continue
				}
				if cred == ph {
					out = append(out, position{in: SlotHeader, name: name, scheme: scheme})
				}
				continue
			}
			if v == ph {
				out = append(out, position{in: SlotHeader, name: name})
			}
		}
	}
	for name, vals := range r.URL.Query() {
		for _, v := range vals {
			if v == ph {
				out = append(out, position{in: SlotQuery, name: name})
			}
		}
	}
	return out
}

func slotMatches(s Slot, p position) bool {
	if s.In != p.in {
		return false
	}
	switch p.in {
	case SlotHeader:
		return http.CanonicalHeaderKey(s.Name) == http.CanonicalHeaderKey(p.name) && s.Scheme == p.scheme
	case SlotQuery:
		return s.Name == p.name
	default:
		return s.Part == p.part
	}
}

func TestCoreProviderSlotsMatchClientRequests(t *testing.T) {
	for _, c := range clientCases(t) {
		t.Run(c.name, func(t *testing.T) {
			b, err := BindingFor(c.provider)
			require.NoError(t, err)

			ph := b.Shape.Wrap("klphTESTTOKEN")
			require.True(t, b.Shape.Matches(ph))

			var got *http.Request
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Clone(r.Context())
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()

			resp, err := srv.Client().Do(c.build(srv.URL, ph))
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.NotNil(t, got)

			positions := placeholderPositions(got, ph)
			require.NotEmpty(t, positions, "client did not carry the placeholder")

			require.True(t, b.AllowsHost(c.authority), "authority %s not bound", c.authority)
			slots := b.SlotsFor(c.field, c.authority)
			for _, p := range positions {
				found := false
				for _, s := range slots {
					if slotMatches(s, p) {
						found = true
					}
				}
				assert.True(t, found, "position %+v has no declared slot for %s on %s", p, c.field, c.authority)
			}
			assert.False(t, b.AllowsHost("evil.example.test"))
		})
	}
}

func TestCoreProviderEnvClassAndShapes(t *testing.T) {
	stripe, err := BindingFor("stripe")
	require.NoError(t, err)
	assert.Equal(t, EnvTest, stripe.EnvClass.Classify("sk_test_abc"))
	assert.Equal(t, EnvTest, stripe.EnvClass.Classify("rk_test_abc"))
	assert.Equal(t, EnvProd, stripe.EnvClass.Classify("sk_live_abc"))
	assert.Equal(t, EnvProd, stripe.EnvClass.Classify("rk_live_abc"))

	for _, c := range []struct{ provider, prefix string }{
		{"github", "gh" + "p_"}, {"stripe", "sk_"}, {"openai", "sk-"}, {"anthropic", "sk-an" + "t-"}, {"supabase", "sb_secret_"},
	} {
		b, err := BindingFor(c.provider)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(b.Shape.Wrap("t"), c.prefix), c.provider)
	}
}

func TestSupabaseAdapterHosts(t *testing.T) {
	b, err := BindingFor("supabase")
	require.NoError(t, err)
	assert.Equal(t, AdapterPostgres, b.Adapter.Kind)
	assert.True(t, b.AllowsHost("db.abc.supabase.co:5432"))
	assert.True(t, b.AllowsHost("aws-0-eu-west-1.pooler.supabase.com:6543"))
	assert.False(t, b.AllowsHost("db.abc.supabase.co:6543"))
	assert.Empty(t, b.SlotsFor("service_role_key", "db.abc.supabase.co:5432"))
}
