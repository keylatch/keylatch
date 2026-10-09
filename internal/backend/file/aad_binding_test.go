package file_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// Moving the vault directory changes the backend ID but not the stored path
// binding, so every secret must still read from the new location.
func TestAADBinding_MovedVaultStillReads(t *testing.T) {
	root := t.TempDir()
	kr, _ := buildKeyring(t, root, envelope.XChaCha20Poly1305)
	oldDir := filepath.Join(root, "vault")
	fb, err := file.OpenWithKeyring(file.Options{Dir: oldDir}, kr)
	if err != nil {
		t.Fatal(err)
	}
	const path = "default/ai/alpha/api_key"
	if err := fb.Set(context.Background(), path, []byte("synthetic-secret"), backend.Meta{}); err != nil {
		t.Fatal(err)
	}

	newDir := filepath.Join(root, "moved")
	if err := os.Rename(oldDir, newDir); err != nil {
		t.Fatal(err)
	}
	moved, err := file.OpenWithKeyring(file.Options{Dir: newDir}, kr)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := moved.Get(context.Background(), path)
	if err != nil {
		t.Fatalf("read after moving the vault: %v", err)
	}
	if string(got) != "synthetic-secret" {
		t.Errorf("got %q, want the stored secret", got)
	}
}
