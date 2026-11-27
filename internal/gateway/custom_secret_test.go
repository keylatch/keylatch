package gateway

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/customsecret"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const customValue = "acme-live-0123456789abcdef"

// customHarness registers a custom secret holding customValue and starts a
// gateway whose upstream transport records every request.
func customHarness(t *testing.T, mutate func(*customsecret.Secret)) *scHarness {
	t.Helper()
	sec := customsecret.Secret{
		Name:      "acme",
		Hosts:     []string{"api.acme.example", "*.acme.example"},
		Paths:     []string{"/v1"},
		Methods:   []string{"GET", "POST"},
		Injection: customsecret.Injection{Kind: customsecret.InjectHeader, Name: "Authorization", Format: "Bearer {value}"},
	}
	if mutate != nil {
		mutate(&sec)
	}
	require.NoError(t, sec.Normalize())
	require.Empty(t, customsecret.RegisterAll([]customsecret.Secret{sec}))
	t.Cleanup(func() {
		require.NoError(t, registry.InitFromConfig(context.Background(), llmcontext.DefaultLookup))
		delete(registry.AllowedProviderBaseURLs, sec.Name)
	})
	return scNewHarness(t, &scVault{values: map[string][]byte{customsecret.ValuePath(sec.Name): []byte(customValue)}})
}

func (h *scHarness) customToken(t *testing.T, mutate func(*token.TokenSpec)) string {
	t.Helper()
	return h.mint(t, func(s *token.TokenSpec) {
		s.Capabilities = []string{"acme.request"}
		if mutate != nil {
			mutate(s)
		}
	})
}

func (h *scHarness) customDo(t *testing.T, jwtStr, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return h.do(t, req)
}

func TestCustomSecret_HeaderInjectionAndForwarding(t *testing.T) {
	h := customHarness(t, nil)
	jwtStr := h.customToken(t, nil)

	rr := h.customDo(t, jwtStr, http.MethodPost, "/sdk/acme/v1/v1/chat/completions?stream=false", `{"q":1}`,
		map[string]string{"Content-Type": "application/json", "X-Keylatch-Trace": "internal", "X-Api-Key": "caller-supplied", "Cookie": "s=1"})

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Len(t, h.upstream, 1)
	up := h.upstream[0]
	assert.Equal(t, "https", up.URL.Scheme)
	assert.Equal(t, "api.acme.example", up.URL.Host, "requests go to the first host")
	assert.Equal(t, "/v1/chat/completions", up.URL.Path)
	assert.Equal(t, "stream=false", up.URL.RawQuery, "the caller's query is forwarded")
	assert.Equal(t, http.MethodPost, up.Method)
	assert.Equal(t, "Bearer "+customValue, up.Header.Get("Authorization"), "the rule's format is applied to the stored value")
	assert.NotContains(t, up.Header.Get("Authorization"), jwtStr, "the gateway session token never reaches the upstream")
	assert.Empty(t, up.Header.Get("X-Keylatch-Trace"), "x-keylatch-* headers are stripped")
	assert.Empty(t, up.Header.Get("X-Api-Key"), "caller credential headers are stripped")
	assert.Empty(t, up.Header.Get("Cookie"))
	assert.Equal(t, "application/json", up.Header.Get("Content-Type"))
	body, _ := io.ReadAll(up.Body)
	assert.JSONEq(t, `{"q":1}`, string(body))
	assert.NotContains(t, rr.Body.String(), customValue)
}

func TestCustomSecret_BareHeaderInjection(t *testing.T) {
	h := customHarness(t, func(s *customsecret.Secret) {
		s.Injection = customsecret.Injection{Kind: customsecret.InjectHeader, Name: "X-Api-Key", Format: "{value}"}
	})
	rr := h.customDo(t, h.customToken(t, nil), http.MethodGet, "/sdk/acme/v1/v1/models", "", nil)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	up := h.upstream[0]
	assert.Equal(t, customValue, up.Header.Get("X-Api-Key"))
	assert.Empty(t, up.Header.Get("Authorization"), "the session token must not fall through to the upstream")
}

func TestCustomSecret_QueryInjection(t *testing.T) {
	h := customHarness(t, func(s *customsecret.Secret) {
		s.Injection = customsecret.Injection{Kind: customsecret.InjectQuery, Name: "auth"}
	})
	jwtStr := h.customToken(t, nil)

	rr := h.customDo(t, jwtStr, http.MethodGet, "/sdk/acme/v1/v1/models?limit=2", "", nil)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	up := h.upstream[0]
	assert.Equal(t, customValue, up.URL.Query().Get("auth"))
	assert.Equal(t, "2", up.URL.Query().Get("limit"), "other query parameters survive")
	assert.Empty(t, up.Header.Get("Authorization"))

	rr = h.customDo(t, jwtStr, http.MethodGet, "/sdk/acme/v1/v1/models?auth=caller-value", "", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, customValue, h.upstream[1].URL.Query().Get("auth"), "a caller-supplied parameter of the same name is overwritten")

	rr = h.customDo(t, jwtStr, http.MethodGet, "/sdk/acme/v1/v1/models?api_key=caller-value", "", nil)
	assert.Equal(t, http.StatusForbidden, rr.Code, "credential-shaped caller parameters are refused")
	assert.Len(t, h.upstream, 2)
}

func TestCustomSecret_BasicInjection(t *testing.T) {
	h := customHarness(t, func(s *customsecret.Secret) {
		s.Injection = customsecret.Injection{Kind: customsecret.InjectBasic, Name: "svc-user"}
	})
	rr := h.customDo(t, h.customToken(t, nil), http.MethodGet, "/sdk/acme/v1/v1/me", "", nil)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc-user:"+customValue))
	assert.Equal(t, want, h.upstream[0].Header.Get("Authorization"))
}

func TestCustomSecret_RoutingDenials(t *testing.T) {
	h := customHarness(t, nil)
	jwtStr := h.customToken(t, nil)

	cases := []struct {
		name, method, target string
		// The mux redirects non-canonical paths to the clean form before routing.
		wantAny []int
	}{
		{"path outside the allowed prefix", http.MethodGet, "/sdk/acme/v1/admin/users", []int{http.StatusNotFound}},
		{"prefix is not a substring match", http.MethodGet, "/sdk/acme/v1/v1beta/x", []int{http.StatusNotFound}},
		{"method not allowed", http.MethodDelete, "/sdk/acme/v1/v1/models", []int{http.StatusNotFound}},
		{"dot-dot traversal", http.MethodGet, "/sdk/acme/v1/v1/%2e%2e/admin", []int{http.StatusNotFound, http.StatusMovedPermanently, http.StatusTemporaryRedirect}},
		{"authority smuggling", http.MethodGet, "/sdk/acme/v1//evil.example/v1", []int{http.StatusNotFound, http.StatusMovedPermanently, http.StatusTemporaryRedirect}},
		{"unknown secret", http.MethodGet, "/sdk/nope/v1/v1/models", []int{http.StatusNotFound}},
	}
	for _, tc := range cases {
		rr := h.customDo(t, jwtStr, tc.method, tc.target, "", nil)
		assert.Contains(t, tc.wantAny, rr.Code, tc.name)
	}
	assert.Empty(t, h.upstream, "a denied request must never reach the upstream")
}

func TestCustomSecret_HostOverrideRefused(t *testing.T) {
	h := customHarness(t, nil)
	jwtStr := h.customToken(t, nil)

	rr := h.customDo(t, jwtStr, http.MethodGet, "/sdk/acme/v1/v1/models", "", map[string]string{"X-Forwarded-Host": "evil.example"})
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Empty(t, h.upstream)
}

func TestCustomSecret_CapabilityIsPerSecret(t *testing.T) {
	h := customHarness(t, nil)

	other := h.customToken(t, func(s *token.TokenSpec) { s.Capabilities = []string{"openai.embeddings"} })
	rr := h.customDo(t, other, http.MethodGet, "/sdk/acme/v1/v1/models", "", nil)
	assert.Equal(t, http.StatusForbidden, rr.Code, "a token for another provider cannot use the secret")

	wildcard := h.customToken(t, func(s *token.TokenSpec) { s.Capabilities = []string{"acme.*"} })
	rr = h.customDo(t, wildcard, http.MethodGet, "/sdk/acme/v1/v1/models", "", nil)
	assert.Equal(t, http.StatusOK, rr.Code, "the wildcard grant that keylatch run mints works")
}

func TestCustomSecret_DeniedInLLMSession(t *testing.T) {
	h := customHarness(t, nil)
	rr := h.customDo(t, h.customToken(t, func(s *token.TokenSpec) { s.LLMSession = true }), http.MethodGet, "/sdk/acme/v1/v1/models", "", nil)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "llm_session_deny", scErrCode(t, rr))
	assert.Empty(t, h.upstream)
}

func TestCustomSecret_RedirectToAnotherOriginIsNotFollowed(t *testing.T) {
	h := customHarness(t, nil)
	h.respond = func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": {"https://evil.example/steal"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}
	// The test client follows redirects like net/http's default; the route must not.
	rr := h.customDo(t, h.customToken(t, nil), http.MethodGet, "/sdk/acme/v1/v1/models", "", nil)

	assert.Equal(t, http.StatusFound, rr.Code, "the redirect is handed back to the caller")
	require.Len(t, h.upstream, 1, "the redirect target is never contacted")
	assert.Equal(t, "api.acme.example", h.upstream[0].URL.Host)
	assert.NotContains(t, rr.Body.String(), customValue)
}

func TestCustomSecret_AuditEventNamesHostAndPathButNotValue(t *testing.T) {
	h := customHarness(t, nil)
	rr := h.customDo(t, h.customToken(t, nil), http.MethodPost, "/sdk/acme/v1/v1/chat?q=secret-looking", "{}", nil)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var found bool
	for _, e := range h.events(t) {
		if e.Action != audit.ActionGatewayCall || e.Outcome != audit.OutcomeOK {
			continue
		}
		found = true
		assert.Equal(t, "acme.request", e.Extra["capability"], "the secret name is audited through its capability")
		assert.Equal(t, "api.acme.example", e.Extra["host"])
		assert.Equal(t, "/v1/chat", e.Extra["path"])
		assert.Equal(t, "POST", e.Extra["method"])
		for _, v := range e.Extra {
			if s, ok := v.(string); ok {
				assert.NotContains(t, s, customValue)
				assert.NotContains(t, s, "secret-looking", "the query string is not audited")
			}
		}
	}
	assert.True(t, found, "no ok gateway audit event")
}

func TestCustomSecret_MissingStoredValueFailsClosed(t *testing.T) {
	h := customHarness(t, nil)
	h.srv.vault = &scVault{values: map[string][]byte{}}
	rr := h.customDo(t, h.customToken(t, nil), http.MethodGet, "/sdk/acme/v1/v1/models", "", nil)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Empty(t, h.upstream, "no unauthenticated request is forwarded")
}

func TestCustomSecret_SSRFGateAllowsOnlyTheFirstHost(t *testing.T) {
	_ = customHarness(t, nil)
	gate := NewSSRFGate()

	assert.Equal(t, []string{"api.acme.example"}, gate.allowedBaseURLs["acme"])
	err := gate.Validate("acme", "evil.example")
	assert.ErrorIs(t, err, ErrSSRFTargetForbidden)
	err = gate.Validate("acme", "foo.acme.example")
	assert.ErrorIs(t, err, ErrSSRFTargetForbidden, "wildcard entries are never dialled")
	assert.ErrorIs(t, gate.Validate("not-registered", "api.acme.example"), ErrSSRFTargetForbidden)
}
