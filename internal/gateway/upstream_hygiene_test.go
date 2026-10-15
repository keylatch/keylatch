package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
)

// pinnedRequest builds a request to srv's address with the address pinned the
// way the handler does after the SSRF gate approved it.
func pinnedRequest(t *testing.T, srv *httptest.Server, path string) *http.Request {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withPinnedIPs(context.Background(), u.Hostname(), []net.IP{net.ParseIP(u.Hostname())})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// A redirect is never followed, so the credential injected for the validated
// host is not sent to the redirect target, in a header or a query string.
func TestNoRedirectWithCredentials(t *testing.T) {
	var leaked atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
		_, _ = io.WriteString(w, "reached")
	}))
	defer elsewhere.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal?key="+r.URL.Query().Get("key"), http.StatusFound)
	}))
	defer origin.Close()

	req := pinnedRequest(t, origin, "/start?key=query-credential")
	req.Header.Set("Authorization", "Bearer injected-credential")
	req.Header.Set("X-Api-Key", "injected-credential")
	resp, err := newProviderHTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // test
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want the 302 returned as is", resp.StatusCode)
	}
	if n := leaked.Load(); n != 0 {
		t.Fatalf("the redirect target received %d request(s)", n)
	}
}

// The upstream connection goes to the address the SSRF gate checked, however
// the name resolves afterwards, and to nothing the gate did not check.
func TestDialPinsResolvedIP(t *testing.T) {
	var lookups atomic.Int32
	gate := &SSRFGate{
		allowedBaseURLs: map[string][]string{"p": nil},
		denyRanges:      registry.SSRFDenyRanges,
		lookup: func(string) ([]string, error) {
			if lookups.Add(1) == 1 {
				return []string{"93.184.216.34"}, nil
			}
			return []string{"127.0.0.1"}, nil // the rebound answer
		},
	}
	ips, err := gate.Resolve("p", "api.example.test")
	if err != nil {
		t.Fatal(err)
	}

	var dialed []string
	dial := pinnedDialContext(func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("stop")
	})
	ctx := withPinnedIPs(context.Background(), "api.example.test", ips)
	_, _ = dial(ctx, "tcp", "api.example.test:443")
	if len(dialed) != 1 || dialed[0] != "93.184.216.34:443" {
		t.Fatalf("dialed %v, want only the checked address", dialed)
	}
	if lookups.Load() != 1 {
		t.Fatalf("the name was resolved %d times, want once", lookups.Load())
	}

	if _, err := dial(context.Background(), "tcp", "api.example.test:443"); !errors.Is(err, errUnpinnedDial) {
		t.Fatalf("dial with nothing pinned: %v", err)
	}
	if _, err := dial(ctx, "tcp", "other.example.test:443"); !errors.Is(err, errUnpinnedDial) {
		t.Fatalf("dial to a host that was not checked: %v", err)
	}
	if len(dialed) != 1 {
		t.Fatalf("unchecked dials reached the network: %v", dialed)
	}

	// An answer that already includes a denied address is refused outright.
	bad := &SSRFGate{
		allowedBaseURLs: map[string][]string{"p": nil},
		denyRanges:      registry.SSRFDenyRanges,
		lookup:          func(string) ([]string, error) { return []string{"93.184.216.34", "10.0.0.5"}, nil },
	}
	if _, err := bad.Resolve("p", "api.example.test"); !errors.Is(err, ErrSSRFTargetForbidden) {
		t.Fatalf("mixed public and private answer: %v", err)
	}
}

// Only allowlisted headers and the ones the template declares are forwarded;
// cookies, encodings and anything that looks like a credential never are.
func TestHeaderAllowlist(t *testing.T) {
	declared := []string{"X-Svc-Version", "X-Svc-Api-Key"}
	src := http.Header{
		"Accept": {"application/json"}, "Content-Type": {"application/json"}, "User-Agent": {"agent/1"},
		"X-Svc-Version": {"2"}, "X-Svc-Api-Key": {"agent-supplied"},
		"Cookie": {"s=1"}, "Accept-Encoding": {"gzip"}, "Connection": {"keep-alive"},
		"Transfer-Encoding": {"chunked"}, "Te": {"trailers"}, "X-Unlisted": {"v"},
	}
	dst := http.Header{}
	copyForwardedHeaders(dst, src, declared)
	for _, h := range []string{"Accept", "Content-Type", "User-Agent", "X-Svc-Version"} {
		if dst.Get(h) == "" {
			t.Errorf("%s was not forwarded", h)
		}
	}
	for _, h := range []string{"X-Svc-Api-Key", "Cookie", "Accept-Encoding", "Connection", "Transfer-Encoding", "Te", "X-Unlisted"} {
		if v := dst.Get(h); v != "" {
			t.Errorf("%s was forwarded: %q", h, v)
		}
	}
}

// The whole body is inspected, not just its first 64 KiB, and a body over the
// limit is rejected instead of being truncated.
func TestFullBodyInspected(t *testing.T) {
	var gotLen int
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotLen = len(b)
		w.WriteHeader(http.StatusOK)
	})
	h := authBlockerMiddleware(next, false, 1<<20)
	filler := strings.Repeat("x", 200_000)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/p/a", strings.NewReader(body))
		req.ContentLength = int64(len(body))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	if rr := post(filler + " Bearer sk-hidden-after-the-first-64k"); rr.Code != http.StatusForbidden {
		t.Fatalf("credential past 64 KiB: status %d, want 403", rr.Code)
	}
	if rr := post(filler); rr.Code != http.StatusOK || gotLen != len(filler) {
		t.Fatalf("large clean body: status %d, forwarded %d of %d bytes", rr.Code, gotLen, len(filler))
	}
	if rr := post(strings.Repeat("y", 1<<20+1)); rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body over the limit: status %d, want 413", rr.Code)
	}
}
