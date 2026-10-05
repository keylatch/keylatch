package gateway

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway/approval"
)

// TestApprovalRoutesRemoved verifies the gateway exposes no approval
// surface: nothing a local process sends to it can list approval tokens,
// change an approval or touch files through a token path.
func TestApprovalRoutesRemoved(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "approvals")
	ar, err := approval.RequestNew(context.Background(), d, "synthetic-actor", "test.write", "test", "bound", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(root, "policy.json")
	victimBody := []byte(`{"status":"pending","expires_at":"2099-01-01T00:00:00Z"}`)
	if err := os.WriteFile(victim, victimBody, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(ServerOptions{SigningKey: make([]byte, 32), ApprovalsDir: d, TokenStorePath: filepath.Join(root, "tokens.json"), Env: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}

	requests := []struct{ method, path string }{
		{http.MethodGet, "/approvals"},
		{http.MethodPost, "/approvals"},
		{http.MethodPost, "/approve/" + ar.Token},
		{http.MethodGet, "/approve/" + ar.Token},
		{http.MethodPost, "/approve/..%2Fpolicy"},
		{http.MethodPost, "/approve/../policy"},
		{http.MethodPost, "/approve/"},
		{http.MethodGet, "/approvals/" + ar.Token},
		{http.MethodPost, "/APPROVE/" + ar.Token},
		{http.MethodGet, "/Approvals"},
		{http.MethodPost, "/approve"},
		{http.MethodPost, "/%61pprove/" + ar.Token},
		{http.MethodGet, "/approvals/../approvals"},
	}
	for _, rq := range requests {
		w := httptest.NewRecorder()
		s.httpSrv.Handler.ServeHTTP(w, httptest.NewRequest(rq.method, "http://127.0.0.1"+rq.path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", rq.method, rq.path, w.Code)
		}
		if strings.Contains(w.Body.String(), ar.Token) {
			t.Errorf("%s %s disclosed a pending approval token", rq.method, rq.path)
		}
	}

	got, err := approval.Get(context.Background(), d, ar.Token)
	if err != nil || got.Status != approval.StatusPending {
		t.Fatalf("approval changed through the gateway: %+v, %v", got, err)
	}
	pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if approval.Verify(context.Background(), d, ar.Token, "bound", pub) == nil {
		t.Fatal("approval verifies after requests to the gateway")
	}
	if body, _ := os.ReadFile(victim); string(body) != string(victimBody) {
		t.Fatalf("file outside the approvals directory changed: %s", body)
	}
}
