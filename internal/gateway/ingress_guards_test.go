package gateway

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/masking"
	"github.com/keylatch/keylatch/internal/registry"
)

func scOKHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestResolveBindAddr_Precedence(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == EnvListenKey {
				return v
			}
			return ""
		}
	}
	cases := []struct {
		name      string
		flag      string
		unsafeAll bool
		env       func(string) string
		wantBind  string
		wantAllow bool
	}{
		{"default loopback", "", false, nil, "127.0.0.1:7878", false},
		{"unsafe bind all", "", true, nil, "0.0.0.0:7878", true},
		{"env overrides default", "", false, env("10.1.2.3:9000"), "10.1.2.3:9000", true},
		{"empty env ignored", "", false, env(""), "127.0.0.1:7878", false},
		{"flag beats env", "192.168.1.5:1", false, env("10.1.2.3:9000"), "192.168.1.5:1", true},
		{"flag beats unsafe", "127.0.0.1:1", true, nil, "127.0.0.1:1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bind, allow := ResolveBindAddr(7878, tc.flag, tc.unsafeAll, tc.env)
			if bind != tc.wantBind || allow != tc.wantAllow {
				t.Fatalf("got (%q,%v), want (%q,%v)", bind, allow, tc.wantBind, tc.wantAllow)
			}
		})
	}
}

func TestHostOverrideBlocker_WithAllowlist(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		header  string
		allowed bool
	}{
		{"allowed host with port", "api.example.test:443", "", true},
		{"allowed host case-insensitive", "API.Example.Test", "", true},
		{"explicit Host header wins", "api.example.test", "evil.example.test", false},
		{"off-list host", "evil.example.test", "", false},
		{"ipv6 literal not stripped", "[::1]:8080", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var called bool
			h := hostOverrideBlockerMiddleware(scOKHandler(&called), []string{"api.example.test:443"})
			req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
			req.Host = tc.host
			if tc.header != "" {
				req.Header.Set("Host", tc.header)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if called != tc.allowed {
				t.Fatalf("next called = %v, want %v (status %d)", called, tc.allowed, rr.Code)
			}
			if !tc.allowed && (rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "host_override_blocked")) {
				t.Fatalf("blocked response: %d %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestStripPort(t *testing.T) {
	cases := map[string]string{
		"host:80":       "host",
		"host":          "host",
		"[::1]:80":      "[::1]:80",
		"::1":           "::1",
		"10.0.0.1:8080": "10.0.0.1",
	}
	for in, want := range cases {
		if got := stripPort(in); got != want {
			t.Errorf("stripPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuthBlocker_AllowSelfAuthPassesCredentialParams(t *testing.T) {
	var called bool
	h := authBlockerMiddleware(scOKHandler(&called), true)
	req := httptest.NewRequest(http.MethodGet, "/api/x?api_key=abc", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !called || rr.Code != http.StatusNoContent {
		t.Fatalf("self-auth provider should pass through: called=%v status=%d", called, rr.Code)
	}

	called = false
	h = authBlockerMiddleware(scOKHandler(&called), false)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/x?api_key=abc", nil))
	if called || rr.Code != http.StatusForbidden {
		t.Fatalf("credential param must be blocked: called=%v status=%d", called, rr.Code)
	}
}

func TestUntrustedWriteGate_PathHeuristicOnSafeMethod(t *testing.T) {
	var provider string
	for p, untrusted := range masking.UntrustedContentProviders {
		if untrusted {
			provider = p
			break
		}
	}
	if provider == "" {
		t.Skip("no untrusted content providers registered")
	}
	writeCheck := NewUntrustedWriteGate(provider, masking.UntrustedContentPolicy{RequireApprovalOnWriteCombination: true})

	cases := []struct {
		path    string
		blocked bool
	}{
		{"/api/" + provider + "/messages.send", true},
		{"/api/" + provider + "/records.DELETE", true},
		{"/api/" + provider + "/messages.list", false},
	}
	for _, tc := range cases {
		var called bool
		rr := httptest.NewRecorder()
		writeCheck.Middleware(scOKHandler(&called)).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if called == tc.blocked {
			t.Errorf("%s: called=%v blocked=%v status=%d", tc.path, called, tc.blocked, rr.Code)
		}
		if tc.blocked && !strings.Contains(rr.Body.String(), "untrusted_write_requires_approval") {
			t.Errorf("%s: body %s", tc.path, rr.Body.String())
		}
	}
}

func scGate(allow map[string][]string, deny ...string) *SSRFGate {
	g := &SSRFGate{allowedBaseURLs: allow}
	for _, cidr := range deny {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		g.denyRanges = append(g.denyRanges, n)
	}
	return g
}

func TestSSRFGate_Decisions(t *testing.T) {
	g := scGate(map[string][]string{
		"pinned": {"203.0.113.10", "169.254.169.254"},
		"open":   {},
	}, "169.254.0.0/16", "127.0.0.0/8", "10.0.0.0/8")

	cases := []struct {
		name     string
		provider string
		host     string
		ok       bool
	}{
		{"unknown provider fails closed", "nope", "203.0.113.10", false},
		{"host outside allowlist", "pinned", "203.0.113.11", false},
		{"allowlisted public ip", "pinned", "203.0.113.10", true},
		{"allowlisted but metadata ip denied", "pinned", "169.254.169.254", false},
		{"open provider private ip denied", "open", "10.1.2.3", false},
		{"open provider loopback denied", "open", "127.0.0.1", false},
		{"open provider public ip", "open", "198.51.100.7", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := g.Validate(tc.provider, tc.host)
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrSSRFTargetForbidden) {
				t.Fatalf("want ErrSSRFTargetForbidden, got %v", err)
			}
		})
	}
}

func TestSSRFGate_ResolvedNamesChecked(t *testing.T) {
	g := scGate(map[string][]string{"open": {}}, "127.0.0.0/8", "::1/128")
	// localhost resolves from the hosts file, so no network is involved.
	if err := g.Validate("open", "localhost"); !errors.Is(err, ErrSSRFTargetForbidden) {
		t.Fatalf("localhost: want ErrSSRFTargetForbidden, got %v", err)
	}
}

func TestSSRFGate_CompiledDenyRangesCoverMetadata(t *testing.T) {
	g := NewSSRFGate()
	for _, ip := range []string{"169.254.169.254", "127.0.0.1", "10.0.0.1", "192.168.1.1", "::1"} {
		if err := g.checkIP(net.ParseIP(ip)); !errors.Is(err, ErrSSRFTargetForbidden) {
			t.Errorf("%s: want forbidden, got %v", ip, err)
		}
	}
	if err := g.checkIP(net.ParseIP("203.0.113.10")); err != nil {
		t.Errorf("public ip rejected: %v", err)
	}
	if len(registry.SSRFDenyRanges) == 0 {
		t.Fatal("no compiled deny ranges")
	}
}
