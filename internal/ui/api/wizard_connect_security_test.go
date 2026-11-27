//go:build securitysuite

package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityRegression_ConnectWithoutStoreReportsUnstored(t *testing.T) {
	h := &WizardHandlers{}

	rec := httptest.NewRecorder()
	h.ConnectHandler(rec, httptest.NewRequest("POST", "/v1/connect", strings.NewReader(`{"provider":"openrouter","backend":"bitwarden","api_key":"synthetic-key"}`)))
	if rec.Code == 200 && strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("reported stored without store: %s", rec.Body.String())
	}
}
