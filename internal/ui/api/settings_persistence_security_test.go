//go:build securitysuite

package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// KNOWN-FAILING: SettingsHandler falls back to a fresh SettingsStore
// per request when none is injected, so a successful PUT is invisible to
// the next GET.
func TestSecurityRegression_SettingsPersistAcrossRequests(t *testing.T) {
	h := &SettingsHandler{}

	put := httptest.NewRecorder()
	h.ServeHTTP(put, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"approval_ttl_seconds":120}`)))
	if put.Code != 200 {
		t.Fatalf("setup PUT: %d", put.Code)
	}

	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest("GET", "/api/settings", nil))
	if !strings.Contains(get.Body.String(), `"approval_ttl_seconds":120`) {
		t.Fatalf("successful PUT lost: %s", get.Body.String())
	}
}

// KNOWN-FAILING: SettingsHandler applies each PUT field as it parses
// instead of validating the whole request first, so a request with one
// valid and one invalid field is rejected but still mutates the store.
func TestSecurityRegression_RejectedSettingsPUTDoesNotMutate(t *testing.T) {
	s := NewSettingsStore()
	before, _ := s.GetTTL()
	h := &SettingsHandler{Store: s}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"approval_ttl_seconds":120,"operating_mode":"invalid"}`)))
	if rec.Code != 400 {
		t.Fatalf("expected rejection, got %d", rec.Code)
	}

	after, _ := s.GetTTL()
	if after != before {
		t.Fatalf("rejected PUT mutated TTL: %d -> %d", before, after)
	}
}
