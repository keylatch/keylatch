//go:build securitysuite

package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// KNOWN-FAILING: ConnectHandler returns {"ok":true} when its Store is
// nil instead of an explicit unavailable error, so a submission can report
// success while never persisting a credential.
func TestSecurityRegression_ConnectWithoutStoreReportsUnstored(t *testing.T) {
	h := &WizardHandlers{}

	rec := httptest.NewRecorder()
	h.ConnectHandler(rec, httptest.NewRequest("POST", "/v1/connect", strings.NewReader(`{"provider":"openrouter","backend":"bitwarden","api_key":"synthetic-key"}`)))
	if rec.Code == 200 && strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("reported stored without store: %s", rec.Body.String())
	}
}
