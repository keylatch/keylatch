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

// F32: Approve/Verify reject any token that doesn't match the format
// newApprovalToken generates before joining it into the approvals directory
// path — a "../"-prefixed token can no longer write outside the approvals
// directory. This is a real fix, not just HTTP-entry-point gating: the
// `keylatch approve`/`deny` CLI commands pass a caller-supplied token
// straight into this package too.
func TestSecurityRegression_F32_ApprovalTraversal(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "approvals")
	os.Mkdir(dir, 0700)
	victim := filepath.Join(root, "outside.json")
	if e := os.WriteFile(victim, []byte(`{"status":"pending","expires_at":"2099-01-01T00:00:00Z"}`), 0600); e != nil {
		t.Fatal(e)
	}
	e := Approve(context.Background(), dir, "../outside")
	if e == nil {
		t.Fatal("approval accepted ../outside and rewrote JSON outside approvals directory")
	}
}

// KNOWN-FAILING (F33): Verify treats an empty expected hash as "no binding
// required" instead of rejecting it, letting an approval be confirmed
// without checking the request-hash binding. The gateway request path never
// supplies an externally-sourced approval claim to reach this call (M1 has
// no wiring from policy ApprovalRequired decisions into approval.Verify;
// see handler.go step 6); this test tracks the unwired library defect for
// nonempty binding enforcement required before expansion.
func TestSecurityRegression_F33_ApprovalHashRequired(t *testing.T) {
	d := t.TempDir()
	ar, e := RequestNew(context.Background(), d, "a", "c", "p", "bound-request", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if e = Approve(context.Background(), d, ar.Token); e != nil {
		t.Fatal(e)
	}
	if Verify(context.Background(), d, ar.Token, "") == nil {
		t.Fatal("empty expected hash bypasses request binding")
	}
}
