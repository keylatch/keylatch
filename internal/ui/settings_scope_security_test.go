package ui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/ui"
	"github.com/keylatch/keylatch/internal/ui/api"
)

// KNOWN-FAILING (F25): the settings route is mounted before the
// ScopeStatusOnly write ceiling, so a status-only session can still mutate
// the shared settings store through an authenticated, CSRF-valid PUT.
func TestSecurityRegression_F25_StatusOnlyScopeCannotMutateSettings(t *testing.T) {
	store := api.NewSettingsStore()
	s, err := ui.New(ui.ServerOptions{
		Bind:          "127.0.0.1:0",
		SigningKey:    make([]byte, 32),
		Scope:         ui.ScopeStatusOnly,
		SettingsStore: store,
		Env:           func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}

	boot := httptest.NewRecorder()
	s.TestServeHTTP(boot, httptest.NewRequest("GET", s.BootstrapURL(), nil))
	if boot.Code != 303 {
		t.Fatalf("bootstrap: %d", boot.Code)
	}

	req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"approval_ttl_seconds":120}`))
	for _, c := range boot.Result().Cookies() {
		if c.Name == "kl_session" {
			req.AddCookie(c)
		}
	}
	req.AddCookie(&http.Cookie{Name: "kl_csrf", Value: "synthetic-csrf"})
	req.Header.Set("X-CSRF-Token", "synthetic-csrf")

	rec := httptest.NewRecorder()
	s.TestServeHTTP(rec, req)
	if rec.Code != 200 && rec.Code != 403 && rec.Code != 404 {
		t.Fatalf("unexpected response: %d %s", rec.Code, rec.Body.String())
	}

	ttl, _ := store.GetTTL()
	if rec.Code == 200 && ttl == 120 {
		t.Fatal("status-only session successfully mutated shared settings")
	}
}
