package gateway

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newSourceTestServer(t *testing.T, cidrs ...string) *Server {
	t.Helper()
	prefixes, err := ParseAllowSources(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s, err := New(ServerOptions{
		SigningKey:     make([]byte, 32),
		ApprovalsDir:   filepath.Join(dir, "approvals"),
		TokenStorePath: filepath.Join(dir, "tokens.json"),
		Env:            func(string) string { return "" },
		AllowSources:   prefixes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func serveFrom(s *Server, remoteAddr, path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
	req.RemoteAddr = remoteAddr
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, req)
	return w
}

func TestAllowSource(t *testing.T) {
	s := newSourceTestServer(t, "192.168.122.0/24", "fd00:1::/64")
	cases := []struct {
		name    string
		remote  string
		refused bool
	}{
		{"ipv4 inside", "192.168.122.17:50000", false},
		{"ipv4 outside", "192.168.123.17:50000", true},
		{"ipv4 loopback outside", "127.0.0.1:50000", true},
		{"ipv6 inside", "[fd00:1::5]:50000", false},
		{"ipv6 outside", "[fd00:2::5]:50000", true},
		{"ipv4-mapped inside", "[::ffff:192.168.122.9]:50000", false},
		{"ipv4-mapped outside", "[::ffff:10.0.0.9]:50000", true},
		{"ipv6 zone inside", "[fd00:1::5%eth0]:50000", false},
		{"unparsable peer", "not-an-address", true},
		{"empty peer", "", true},
		{"unix socket peer", "@", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := serveFrom(s, tc.remote, "/health", nil)
			if tc.refused {
				if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "source_not_allowed") {
					t.Fatalf("got %d %s, want 403 source_not_allowed", w.Code, w.Body.String())
				}
				return
			}
			if w.Code != http.StatusOK {
				t.Fatalf("got %d, want 200", w.Code)
			}
		})
	}
}

func TestAllowSourceRefusesBeforeAuth(t *testing.T) {
	s := newSourceTestServer(t, "192.168.122.0/24")

	// No token: a permitted peer is asked to authenticate, a refused peer is not.
	if w := serveFrom(s, "192.168.122.2:1", "/api/openrouter/chat", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("inside peer without token = %d, want 401", w.Code)
	}
	w := serveFrom(s, "10.9.9.9:1", "/api/openrouter/chat", map[string]string{"Authorization": "Bearer anything"})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "source_not_allowed") {
		t.Fatalf("outside peer = %d %s, want 403 source_not_allowed", w.Code, w.Body.String())
	}
}

func TestAllowSourceIgnoresForwardingHeaders(t *testing.T) {
	s := newSourceTestServer(t, "192.168.122.0/24")
	spoof := map[string]string{
		"X-Forwarded-For": "192.168.122.5",
		"X-Real-IP":       "192.168.122.5",
		"Forwarded":       "for=192.168.122.5",
	}
	if w := serveFrom(s, "10.9.9.9:1", "/health", spoof); w.Code != http.StatusForbidden {
		t.Fatalf("outside peer with spoofed headers = %d, want 403", w.Code)
	}
	hostile := map[string]string{"X-Forwarded-For": "10.9.9.9"}
	if w := serveFrom(s, "192.168.122.5:1", "/health", hostile); w.Code != http.StatusOK {
		t.Fatalf("inside peer with outside X-Forwarded-For = %d, want 200", w.Code)
	}
}

func TestAllowSourceEmptyListAllowsAll(t *testing.T) {
	s := newSourceTestServer(t)
	if w := serveFrom(s, "203.0.113.7:1", "/health", nil); w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
}

func TestParseAllowSources(t *testing.T) {
	good, err := ParseAllowSources([]string{"10.0.0.7/24", " fd00::/8 ", "192.168.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	if got := good[0].String(); got != "10.0.0.0/24" {
		t.Errorf("host bits not masked: %s", got)
	}
	for _, bad := range []string{"", "10.0.0.0", "10.0.0.0/33", "fd00::/129", "not-a-cidr", "10.0.0.0/24/8", "::ffff:10.0.0.0/104", "fe80::1%eth0/64"} {
		if _, err := ParseAllowSources([]string{bad}); err == nil {
			t.Errorf("ParseAllowSources(%q) accepted a malformed CIDR", bad)
		}
	}
}
