//go:build securitysuite

// Requires the securitysuite build tag; excluded from the ordinary
// go test ./... run. Run with: go test -tags securitysuite ./...
// Uses the synthetic buildKeyring helper from crypto_test.go — no real KEK
// subprocess or password manager is invoked.
package file_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// KNOWN-FAILING (F36): decryption binds only to the ciphertext, nonce, and
// version sidecar files, not to the path they're stored under, so a
// ciphertext copied to a different secret's path decrypts successfully
// there.
func TestSecurityRegression_F36_VersionedRecordRelocation(t *testing.T) {
	d := t.TempDir()
	kr, _ := buildKeyring(t, d, envelope.XChaCha20Poly1305)
	fb, e := file.OpenWithKeyring(file.Options{Dir: d}, kr)
	if e != nil {
		t.Fatal(e)
	}
	a := "default/ai/alpha/api_key"
	b := "default/ai/beta/api_key"
	if e = fb.SetVersioned(context.Background(), a, 1, []byte("synthetic-alpha-secret")); e != nil {
		t.Fatal(e)
	}
	dst := filepath.Join(d, "values", b)
	os.MkdirAll(dst, 0700)
	for _, suffix := range []string{"", ".nonce", ".versionmeta"} {
		data, e := os.ReadFile(filepath.Join(d, "values", a, "1"+suffix))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dst, "1"+suffix), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	v, e := fb.GetVersioned(context.Background(), b, 1)
	if e == nil && string(v) == "synthetic-alpha-secret" {
		t.Fatal("ciphertext+nonce+sidecar copied to different path decrypts as destination credential")
	}
}

// F37: DeleteVersioned confines the resolved path to the vault root, so a
// "../"-prefixed key is rejected before any file is touched.
func TestSecurityRegression_F37_DeleteVersionedTraversal(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "vault")
	fb, e := file.Open(file.Options{Dir: d})
	if e != nil {
		t.Fatal(e)
	}
	victim := filepath.Join(root, "outside", "1")
	os.MkdirAll(filepath.Dir(victim), 0700)
	os.WriteFile(victim, []byte("synthetic"), 0600)
	e = fb.DeleteVersioned(context.Background(), "../../outside", 1)
	_, stat := os.Stat(victim)
	if e == nil && os.IsNotExist(stat) {
		t.Fatal("DeleteVersioned removed file outside vault root")
	}
}
