package api

import (
	"net/http/httptest"
	"testing"
)

// TestSecurityRegression_F26_ApprovalActionRequiresPendingRequest verifies
// ApprovalsHandler (F26) never fakes acceptance of an approval action: the
// inbox has no store backing it in M1, so every action returns an explicit
// unavailable response instead of {"status":"accepted"}.
func TestSecurityRegression_F26_ApprovalActionRequiresPendingRequest(t *testing.T) {
	for _, action := range []string{"approve", "deny"} {
		t.Run(action, func(t *testing.T) {
			h := &ApprovalsHandler{}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/approvals/nonexistent/"+action, nil))
			if rec.Code == 200 {
				t.Fatalf("accepted nonexistent approval: %s", rec.Body.String())
			}
		})
	}
}
