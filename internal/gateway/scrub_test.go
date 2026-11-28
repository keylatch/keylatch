package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html"
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

func TestCredentialScrubberCoversJSONHTMLAndLowercaseHexForms(t *testing.T) {
	const cred = `ab/c+d&e<f>g"h'i=j k`
	s := newCredentialScrubber(registry.AuthPlacement{In: "header"}, []byte(cred))

	jsonHTML, _ := jsonEscaped(cred, true)
	jsonPlain, _ := jsonEscaped(cred, false)
	forms := map[string]string{
		"json":            jsonPlain,
		"json html":       jsonHTML,
		"json slash":      strings.ReplaceAll(jsonPlain, "/", `\/`),
		"html":            html.EscapeString(cred),
		"query lower hex": lowerPercentHex(url.QueryEscape(cred)),
		"path lower hex":  lowerPercentHex(url.PathEscape(cred)),
		"query upper hex": url.QueryEscape(cred),
	}
	for name, form := range forms {
		require.NotEqual(t, cred, form, name+": the form must differ from the raw value to test anything")
		got := string(s.bytes([]byte("x " + form + " y")))
		assert.Equal(t, "x **** y", got, name)
	}
	assert.Contains(t, lowerPercentHex("%2F%3A"), "%2f%3a")
}

func TestCustomSecret_KeyEchoedInAJSONErrorIsScrubbed(t *testing.T) {
	h := customHarness(t, nil)
	h.respond = func(*http.Request) (*http.Response, error) {
		// The key contains characters JSON escapes, so the echo differs from the raw value.
		return &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"error":"invalid api key \"` + jsonValue(t, customValue) + `\""}`))}, nil
	}
	rr := h.customDo(t, h.customToken(t, nil), http.MethodGet, "/sdk/acme/v1/v1/x", "", nil)
	assert.NotContains(t, rr.Body.String(), customValue)
	assert.Contains(t, rr.Body.String(), "****")
}

func jsonValue(t *testing.T, v string) string {
	t.Helper()
	out, ok := jsonEscaped(v, true)
	require.True(t, ok)
	return out
}

func TestCustomSecret_JSONEscapedKeyIsScrubbed(t *testing.T) {
	const key = "ke/y\"with<odd>&chars-0123"
	h := customHarness(t, nil)
	h.srv.vault = &scVault{values: map[string][]byte{customsecret.ValuePath("acme"): []byte(key)}}
	h.respond = func(*http.Request) (*http.Response, error) {
		body, _ := json.Marshal(map[string]string{"error": "bad key " + key})
		return &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(bytes.NewReader(body))}, nil
	}
	rr := h.customDo(t, h.customToken(t, nil), http.MethodGet, "/sdk/acme/v1/v1/x", "", nil)
	require.Equal(t, 401, rr.Code)
	assert.NotContains(t, rr.Body.String(), strings.ReplaceAll(key, `"`, `\"`))
	assert.NotContains(t, rr.Body.String(), "odd")
	assert.Contains(t, rr.Body.String(), "bad key ****")
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestCustomSecret_OverLimitBodyIs502NotTruncated(t *testing.T) {
	h := customHarness(t, nil)
	h.respond = func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(io.LimitReader(zeroReader{}, defaultBodyLimitForTest+1))}, nil
	}
	rr := h.customDo(t, h.customToken(t, nil), http.MethodGet, "/sdk/acme/v1/v1/x", "", nil)
	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Equal(t, "upstream_too_large", scErrCode(t, rr))

	// Exactly at the limit is still served in full.
	h.respond = func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(io.LimitReader(zeroReader{}, defaultBodyLimitForTest))}, nil
	}
	rr = h.customDo(t, h.customToken(t, nil), http.MethodGet, "/sdk/acme/v1/v1/x", "", nil)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, defaultBodyLimitForTest, rr.Body.Len())
}

const defaultBodyLimitForTest = 10 * 1024 * 1024

func TestReadUpstreamBodyStrictAndLenient(t *testing.T) {
	mk := func() *http.Response {
		return &http.Response{Header: http.Header{}, Body: io.NopCloser(strings.NewReader("0123456789"))}
	}
	got, err := readUpstreamBody(mk(), 4, false)
	require.NoError(t, err)
	assert.Equal(t, "0123", string(got), "existing routes keep their cut-off behaviour")
	_, err = readUpstreamBody(mk(), 4, true)
	assert.ErrorIs(t, err, errBodyTooLarge)
	got, err = readUpstreamBody(mk(), 10, true)
	require.NoError(t, err)
	assert.Equal(t, "0123456789", string(got))
}

func TestCustomSecret_SecondHostThroughTheSSRFGate(t *testing.T) {
	h := customHarness(t, nil)
	var resolved []string
	h.srv.ssrfGate = &SSRFGate{
		allowedBaseURLs: registry.AllowedProviderBaseURLs,
		denyRanges:      registry.SSRFDenyRanges,
		lookup: func(host string) ([]string, error) {
			resolved = append(resolved, host)
			if host == "eu.acme.example" {
				return []string{"93.184.216.34"}, nil
			}
			return []string{"10.0.0.7"}, nil
		},
	}
	jwtStr := h.customToken(t, nil)

	rr := h.customDo(t, jwtStr, http.MethodGet, "/sdk/acme/h/eu.acme.example/v1/models", "", nil)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "eu.acme.example", h.upstream[0].URL.Host)
	assert.Equal(t, []string{"eu.acme.example"}, resolved, "the gate re-checks the host of this request")

	// A listed host that now resolves to a private address is blocked.
	rr = h.customDo(t, jwtStr, http.MethodGet, "/sdk/acme/v1/v1/models", "", nil)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "ssrf_blocked", scErrCode(t, rr))
	assert.Len(t, h.upstream, 1)

	// An unlisted host never reaches the gate or the upstream.
	before := len(resolved)
	rr = h.customDo(t, jwtStr, http.MethodGet, "/sdk/acme/h/evil.example/v1/models", "", nil)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Len(t, resolved, before)
}
