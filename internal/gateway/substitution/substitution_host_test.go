package substitution_test

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/substitution"
)

func TestCheckRequest_HostHeaderDecisions(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		fwd     string
		blocked bool
	}{
		{"gateway loopback ipv4", "127.0.0.1:7878", "", false},
		{"gateway localhost", "localhost:7878", "", false},
		{"upstream host with port", "API.Example.Test:443", "", false},
		{"foreign host", "attacker.example:443", "", true},
		{"forwarded host matches upstream", "127.0.0.1", "api.example.test:443", false},
		{"forwarded host differs", "127.0.0.1", "attacker.example", true},
		{"non-numeric port suffix is not stripped", "api.example.test:abc", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/x/y", nil)
			r.Host = tc.host
			if tc.fwd != "" {
				r.Header.Set("X-Forwarded-Host", tc.fwd)
			}
			kind, err := substitution.CheckRequest(r, "api.example.test", nil, false)
			if tc.blocked {
				if !errors.Is(err, substitution.ErrSubstitutionBlocked) || kind != "host_override" {
					t.Fatalf("want host_override block, got kind=%q err=%v", kind, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected block kind=%q err=%v", kind, err)
			}
		})
	}
}

func TestCheckRequest_NoUpstreamHostSkipsHostChecks(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/x/y", nil)
	r.Host = "attacker.example"
	r.Header.Set("X-Forwarded-Host", "attacker.example")
	if kind, err := substitution.CheckRequest(r, "", nil, false); err != nil {
		t.Fatalf("kind=%q err=%v", kind, err)
	}
}
