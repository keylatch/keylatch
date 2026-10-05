//go:build securitysuite

// Requires the securitysuite build tag; excluded from the ordinary
// go test ./... run. Run with: go test -tags securitysuite ./...
package approval

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Approve/Verify reject any token that doesn't match the format
// newApprovalToken generates before joining it into the approvals directory
// path — a "../"-prefixed token can no longer write outside the approvals
// directory. This is a real fix, not just HTTP-entry-point gating: the
// `keylatch approve`/`deny` CLI commands pass a caller-supplied token
// straight into this package too.
func TestSecurityRegression_ApprovalTraversal(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "approvals")
	os.Mkdir(dir, 0700)
	victim := filepath.Join(root, "outside.json")
	if e := os.WriteFile(victim, []byte(`{"status":"pending","expires_at":"2099-01-01T00:00:00Z"}`), 0600); e != nil {
		t.Fatal(e)
	}
	e := Approve(context.Background(), dir, "../outside", testKey)
	if e == nil {
		t.Fatal("approval accepted ../outside and rewrote JSON outside approvals directory")
	}
}

// Verify refuses an empty expected hash: an approval is only ever confirmed
// for the request it was bound to.
func TestSecurityRegression_ApprovalHashRequired(t *testing.T) {
	d := t.TempDir()
	ar, e := RequestNew(context.Background(), d, "a", "c", "p", "bound-request", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if e = Approve(context.Background(), d, ar.Token, testKey); e != nil {
		t.Fatal(e)
	}
	if Verify(context.Background(), d, ar.Token, "", testPub) == nil {
		t.Fatal("empty expected hash bypasses request binding")
	}
}
