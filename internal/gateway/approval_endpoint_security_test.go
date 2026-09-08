//go:build securitysuite

// Requires the securitysuite build tag; excluded from the ordinary
// go test ./... run. Run with: go test -tags securitysuite ./...
package gateway

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway/approval"
)

// KNOWN-FAILING (F30): the approvals HTTP endpoints require no caller
// authentication, so an anonymous request can list pending approval tokens
// and approve them by ID.
func TestSecurityRegression_F30_AnonymousApproval(t *testing.T) {
	d := t.TempDir()
	ar, e := approval.RequestNew(context.Background(), d, "synthetic-actor", "test.write", "test", "bound", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	s, e := New(ServerOptions{SigningKey: make([]byte, 32), ApprovalsDir: d, TokenStorePath: filepath.Join(d, "tokens.json"), Env: func(string) string { return "" }})
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1/approvals", nil))
	if w.Code == 200 && strings.Contains(w.Body.String(), ar.Token) {
		t.Error("anonymous listing disclosed pending approval token")
	}
	w = httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, httptest.NewRequest("POST", "http://127.0.0.1/approve/"+ar.Token, nil))
	if w.Code == 200 && approval.Verify(context.Background(), d, ar.Token, "bound") == nil {
		t.Fatal("anonymous POST changed stored approval to approved")
	}
}
