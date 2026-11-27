package gateway

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/customsecret"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oneByteReader hands out one byte per Read, so any match that straddles reads is exercised.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

func TestCredentialScrubberCoversTheInjectedForms(t *testing.T) {
	const cred = "tok/en+with=special&chars"
	s := newCredentialScrubber(registry.AuthPlacement{In: "basic", Name: "svc"}, []byte(cred))

	forms := []string{
		cred,
		url.QueryEscape(cred),
		url.PathEscape(cred),
		base64.StdEncoding.EncodeToString([]byte("svc:" + cred)),
		base64.RawURLEncoding.EncodeToString([]byte("svc:" + cred)),
		base64.StdEncoding.EncodeToString([]byte(cred)),
	}
	for _, f := range forms {
		got := string(s.bytes([]byte("before " + f + " after")))
		assert.Equal(t, "before **** after", got, f)
	}
	assert.Equal(t, "nothing here", string(s.bytes([]byte("nothing here"))))
	assert.Equal(t, "x", string(newCredentialScrubber(registry.AuthPlacement{}, nil).bytes([]byte("x"))), "an empty credential masks nothing")
}

func TestCustomSecret_EchoedCredentialIsScrubbed(t *testing.T) {
	h := customHarness(t, nil)
	h.respond = func(*http.Request) (*http.Response, error) {
		body := `{"debug":"Authorization: Bearer ` + customValue + `","enc":"` + url.QueryEscape(customValue) + `"}`
		return &http.Response{
			StatusCode: http.StatusFound,
			Header: http.Header{
				"Content-Type": {"application/json"},
				"Location":     {"https://other.example/cb?token=" + customValue},
				"X-Echo":       {"Bearer " + customValue},
			},
			// One byte per read: a match split across chunks must still be masked.
			Body: io.NopCloser(oneByteReader{strings.NewReader(body)}),
		}, nil
	}
	rr := h.customDo(t, h.customToken(t, nil), http.MethodGet, "/sdk/acme/v1/v1/models", "", nil)

	require.Equal(t, http.StatusFound, rr.Code)
	assert.NotContains(t, rr.Body.String(), customValue)
	assert.Contains(t, rr.Body.String(), "****")
	for k, vv := range rr.Header() {
		for _, v := range vv {
			assert.NotContains(t, v, customValue, k)
		}
	}
	assert.Equal(t, "https://other.example/cb?token=****", rr.Header().Get("Location"))
}

func TestCustomSecret_QueryAndBasicEchoScrubbed(t *testing.T) {
	cases := map[string]customsecret.Injection{
		"query": {Kind: customsecret.InjectQuery, Name: "auth"},
		"basic": {Kind: customsecret.InjectBasic, Name: "svc"},
	}
	for name, inj := range cases {
		h := customHarness(t, func(s *customsecret.Secret) { s.Injection = inj })
		h.respond = func(r *http.Request) (*http.Response, error) {
			user, pass, _ := r.BasicAuth()
			echo := r.URL.RawQuery + " " + r.Header.Get("Authorization") + " " + user + ":" + pass
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(echo))}, nil
		}
		rr := h.customDo(t, h.customToken(t, nil), http.MethodGet, "/sdk/acme/v1/v1/x", "", nil)
		require.Equal(t, http.StatusOK, rr.Code, name)
		assert.NotContains(t, rr.Body.String(), customValue, name)
		assert.NotContains(t, rr.Body.String(), base64.StdEncoding.EncodeToString([]byte("svc:"+customValue)), name)
		assert.Contains(t, rr.Body.String(), "****", name)
	}
}

func TestCustomSecret_TraceAndConnectNeverReachUpstream(t *testing.T) {
	// No explicit methods: the secret gets the safe default set.
	h := customHarness(t, func(s *customsecret.Secret) { s.Methods = nil })
	jwtStr := h.customToken(t, nil)

	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodDelete} {
		rr := h.customDo(t, jwtStr, m, "/sdk/acme/v1/v1/x", "", nil)
		assert.Equal(t, http.StatusOK, rr.Code, m)
	}
	n := len(h.upstream)
	for _, m := range []string{http.MethodTrace, http.MethodConnect, "PROPFIND"} {
		rr := h.customDo(t, jwtStr, m, "/sdk/acme/v1/v1/x", "", nil)
		assert.NotEqual(t, http.StatusOK, rr.Code, m)
	}
	assert.Len(t, h.upstream, n, "TRACE and CONNECT are never forwarded")
}
