package customsecret

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateName(t *testing.T) {
	valid := []string{"a", "acme", "acme-prod-2", "a" + strings.Repeat("b", 62)}
	for _, n := range valid {
		assert.NoError(t, ValidateName(n), n)
	}
	invalid := []string{"", "Acme", "1acme", "-acme", "acme_prod", "acme.prod", "acme/prod", "acme prod", "a" + strings.Repeat("b", 63), "../x"}
	for _, n := range invalid {
		assert.Error(t, ValidateName(n), n)
	}
}

func TestNormalizeHost(t *testing.T) {
	valid := map[string]string{
		"api.acme.example":       "api.acme.example",
		"API.Acme.Example":       "api.acme.example",
		" api.acme.example ":     "api.acme.example",
		"xn--bcher-kva.example":  "xn--bcher-kva.example",
		"a-b.c-d.example.co.uk":  "a-b.c-d.example.co.uk",
		"api.example.github.io":  "api.example.github.io",
		"1.2.3.4.nip.example.io": "1.2.3.4.nip.example.io",
	}
	for in, want := range valid {
		got, err := NormalizeHost(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	invalid := map[string]string{
		"":                                       "empty",
		"127.0.0.1":                              "IPv4 literal",
		"10.0.0.8":                               "private IPv4",
		"169.254.169.254":                        "metadata IP",
		"::1":                                    "IPv6 literal",
		"[::1]":                                  "bracketed IPv6",
		"2130706433":                             "decimal IPv4 and single label",
		"0x7f.1":                                 "hex IPv4 form",
		"127.1":                                  "short IPv4 form",
		"localhost":                              "localhost",
		"app.localhost":                          "localhost suffix",
		"printer.local":                          "mDNS suffix",
		"db.internal":                            "internal suffix",
		"router.lan":                             "lan suffix",
		"nas.home.arpa":                          "home.arpa suffix",
		"intranet":                               "single label",
		"com":                                    "bare TLD",
		"co.uk":                                  "multi-label public suffix",
		"github.io":                              "private-section public suffix",
		"*.acme.example":                         "wildcards are not supported",
		"*.com":                                  "wildcard on TLD",
		"*.co.uk":                                "wildcard on multi-label public suffix",
		"*.github.io":                            "wildcard on hosting suffix",
		"*":                                      "bare wildcard",
		"*.":                                     "wildcard with nothing",
		"**.acme.example":                        "double star",
		"a.*.acme.example":                       "wildcard not leftmost",
		"*.*.acme.example":                       "two wildcards",
		"*acme.example":                          "partial wildcard",
		"api*.acme.example":                      "partial wildcard label",
		"https://api.acme.test":                  "scheme",
		"api.acme.example:8443":                  "port",
		"api.acme.example/v1":                    "path",
		"user@api.acme.example":                  "userinfo",
		"api.acme.example?x=1":                   "query",
		"api.acme.example.":                      "trailing dot",
		".acme.example":                          "leading dot",
		"api..acme.example":                      "empty label",
		"-api.acme.example":                      "leading hyphen",
		"api-.acme.example":                      "trailing hyphen",
		"api acme.example":                       "space",
		"api_acme.example":                       "underscore",
		"bücher.example":                         "non-ASCII",
		strings.Repeat("a", 64) + ".example.com": "label too long",
	}
	for in, why := range invalid {
		_, err := NormalizeHost(in)
		assert.Error(t, err, "%q (%s)", in, why)
	}
}

func TestNormalizePath(t *testing.T) {
	valid := map[string]string{"/": "/", "/v1": "/v1", "/v1/": "/v1", " /v1/chat ": "/v1/chat", "/a-b_c.d": "/a-b_c.d"}
	for in, want := range valid {
		got, err := NormalizePath(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "v1", "/v1//x", "/v1/../x", "/./x", "/v1?x=1", "/v1#f", "/v%2Fx", `/v1\x`, "/v1 x", "//evil.example", "/.."} {
		_, err := NormalizePath(in)
		assert.Error(t, err, in)
	}
}

func TestNormalizeMethod(t *testing.T) {
	for in, want := range map[string]string{"get": "GET", "Post": "POST", "DELETE": "DELETE"} {
		got, err := NormalizeMethod(in)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	for _, in := range []string{"", "CONNECT", "TRACE", "GET POST", "FETCH"} {
		_, err := NormalizeMethod(in)
		assert.Error(t, err, in)
	}
}

func TestParseHeaderRule(t *testing.T) {
	good := map[string]Injection{
		"Authorization: Bearer {value}":      {Kind: InjectHeader, Name: "Authorization", Format: "Bearer {value}"},
		"X-Api-Key: {value}":                 {Kind: InjectHeader, Name: "X-Api-Key", Format: "{value}"},
		"Authorization: Token token={value}": {Kind: InjectHeader, Name: "Authorization", Format: "Token token={value}"},
	}
	for spec, want := range good {
		got, err := ParseHeaderRule(spec)
		require.NoError(t, err, spec)
		assert.Equal(t, want, got, spec)
	}
	_, err := ParseHeaderRule("Authorization: sk-live-supersecret")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sk-live-supersecret", "the spec is not echoed")
	assert.NoError(t, Injection{Kind: InjectBasic, Name: "svc"}.validate())
	for _, u := range []string{"a\x00b", "a\tb", "a\x7fb", "a\u0085b", "a:b", ""} {
		assert.Error(t, Injection{Kind: InjectBasic, Name: u}.validate(), "%q", u)
	}
	for _, spec := range []string{
		"", "Authorization", "Authorization:", ": {value}", "Authorization: Bearer token",
		"Authorization: {value}{value}", "Host: {value}", "Content-Length: {value}", "Cookie: {value}",
		"Transfer-Encoding: {value}", "Bad Name: {value}", "X-Key: {value}\r\nX-Evil: 1", "X-Key: {value}\x00",
		"X-Key: välue {value}",
	} {
		_, err := ParseHeaderRule(spec)
		assert.Error(t, err, "%q", spec)
	}
}

func TestInjectionValidate(t *testing.T) {
	assert.NoError(t, Injection{Kind: InjectQuery, Name: "api_key"}.validate())
	assert.NoError(t, Injection{Kind: InjectBasic, Name: "svc-user"}.validate())
	assert.Error(t, Injection{Kind: InjectQuery, Name: "a b"}.validate())
	assert.Error(t, Injection{Kind: InjectQuery, Name: "key", Format: "{value}"}.validate())
	assert.Error(t, Injection{Kind: InjectBasic, Name: "a:b"}.validate())
	assert.Error(t, Injection{Kind: InjectBasic}.validate())
	assert.Error(t, Injection{Kind: "cookie", Name: "x"}.validate())
}

func TestValidateBaseURLEnv(t *testing.T) {
	for _, n := range []string{"ACME_BASE_URL", "ACME_API_URL", "ACME_URL", "ACME_ENDPOINT", "ACME_API_HOST", "OPENAI_BASE_URL"} {
		assert.NoError(t, ValidateBaseURLEnv(n), n)
	}
	for _, n := range []string{
		"", "acme_base_url", "1ACME_BASE_URL", "ACME-URL", "PATH", "HOME", "LD_PRELOAD", "LD_BASE_URL",
		"KEYLATCH_GATEWAY_TOKEN", "KEYLATCH_BASE_URL", "NODE_OPTIONS", "DYLD_INSERT_LIBRARIES", "PYTHONPATH",
		"HTTPS_PROXY", "ACME_BASE_URL_X", "ACME_KEY",
	} {
		assert.Error(t, ValidateBaseURLEnv(n), n)
	}
}

func TestValidateValue(t *testing.T) {
	assert.NoError(t, ValidateValue([]byte("sk-abc 123")))
	for _, v := range []string{"", "a\nb", "a\rb", "a\x00b", "a\x7fb"} {
		assert.Error(t, ValidateValue([]byte(v)), "%q", v)
	}
}

func TestNormalizeSecret(t *testing.T) {
	base := func() Secret {
		return Secret{
			Name:      "acme",
			Hosts:     []string{"API.acme.example"},
			Injection: Injection{Kind: InjectQuery, Name: "key"},
		}
	}

	s := base()
	require.NoError(t, s.Normalize())
	assert.Equal(t, []string{"api.acme.example"}, s.Hosts)
	assert.Equal(t, []string{"/"}, s.Paths, "paths default to the root")
	assert.Equal(t, DefaultMethods, s.Methods, "an empty method list defaults to the safe set")
	assert.NotContains(t, s.Methods, "TRACE")
	assert.NotContains(t, s.Methods, "CONNECT")

	s = base()
	s.Hosts = []string{"API.acme.example", "eu.acme.example", "api.acme.example"}
	require.NoError(t, s.Normalize())
	assert.Equal(t, []string{"api.acme.example", "eu.acme.example"}, s.Hosts, "lowercased, deduplicated, order kept")

	s = base()
	s.Paths, s.Methods = []string{"/v1/", "/health"}, []string{"get", "post"}
	require.NoError(t, s.Normalize())
	assert.Equal(t, []string{"/health", "/v1"}, s.Paths)
	assert.Equal(t, []string{"GET", "POST"}, s.Methods)

	cases := map[string]func(*Secret){
		"no hosts":         func(s *Secret) { s.Hosts = nil },
		"wildcard second":  func(s *Secret) { s.Hosts = []string{"api.acme.example", "*.acme.example"} },
		"ip second":        func(s *Secret) { s.Hosts = []string{"api.acme.example", "10.0.0.1"} },
		"wildcard host":    func(s *Secret) { s.Hosts = []string{"*.acme.example"} },
		"bad host":         func(s *Secret) { s.Hosts = []string{"127.0.0.1"} },
		"bad path":         func(s *Secret) { s.Paths = []string{"/../etc"} },
		"bad method":       func(s *Secret) { s.Methods = []string{"TRACE"} },
		"connect method":   func(s *Secret) { s.Methods = []string{"CONNECT"} },
		"bad name":         func(s *Secret) { s.Name = "Acme" },
		"bad injection":    func(s *Secret) { s.Injection = Injection{Kind: "cookie"} },
		"bad base url env": func(s *Secret) { s.BaseURLEnv = "PATH" },
	}
	for name, mutate := range cases {
		s := base()
		mutate(&s)
		assert.Error(t, s.Normalize(), name)
	}
}

func TestRefSchemeOf(t *testing.T) {
	for ref, want := range map[string]string{
		"op://Private/acme/key":        "op",
		" aws-sm://eu-west-1/acme-key": "aws-sm",
		"hashivault://secret/acme#key": "hashivault",
	} {
		got, err := RefSchemeOf(ref)
		require.NoError(t, err, ref)
		assert.Equal(t, want, got)
	}
	for _, ref := range []string{"", "sk-live-123", "https://x.example/y", "op://vaultonly", "file:///etc/passwd"} {
		_, err := RefSchemeOf(ref)
		assert.Error(t, err, ref)
	}
}
