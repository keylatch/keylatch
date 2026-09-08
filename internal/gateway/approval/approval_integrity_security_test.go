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

// KNOWN-FAILING (F32): Approve joins the caller-supplied token directly
// into the approvals directory path without validating it, so a
// "../"-prefixed token writes outside the approvals directory.
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
// without checking the request-hash binding.
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
