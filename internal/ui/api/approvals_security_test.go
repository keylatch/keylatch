package api

import (
	"net/http/httptest"
	"testing"
)

// KNOWN-FAILING (F26): ApprovalsHandler has no approval-store dependency —
// every action returns {"status":"accepted"} regardless of whether the
// referenced request exists.
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
