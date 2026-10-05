package file_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
)

func bkSkipNonPOSIX(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("relies on POSIX rename/permission semantics")
	}
}

func bkSkipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
}

func bkExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// A directory squatting on a target file name makes the atomic rename fail.
func bkBlock(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestFileBackend_Set_NonceWriteFailure_RemovesCiphertext(t *testing.T) {
	bkSkipNonPOSIX(t)
	dir := t.TempDir()
	fb := openKeyringBackendInDir(t, dir)
	const p = "default/app/key"
	encPath := filepath.Join(dir, "default", "app", "key", "value.enc")
	bkBlock(t, encPath+".nonce")

	err := fb.Set(context.Background(), p, []byte("s3cret-value"), backend.Meta{})
	if err == nil || !strings.Contains(err.Error(), "write nonce") {
		t.Fatalf("got %v, want write nonce error", err)
	}
	if strings.Contains(err.Error(), "s3cret-value") {
		t.Fatal("secret leaked into error")
	}
	if bkExists(encPath) {
		t.Fatal("orphaned value.enc left behind after nonce failure")
	}
	if _, _, gerr := fb.Get(context.Background(), p); !errors.Is(gerr, backend.ErrNotFound) {
		t.Fatalf("failed Set must not be visible: Get err = %v", gerr)
	}
}

func TestFileBackend_Set_AADWriteFailure_RemovesCiphertextAndNonce(t *testing.T) {
	bkSkipNonPOSIX(t)
	dir := t.TempDir()
	fb := openKeyringBackendInDir(t, dir)
	encPath := filepath.Join(dir, "default", "app", "key", "value.enc")
	bkBlock(t, encPath+".aad")

	err := fb.Set(context.Background(), "default/app/key", []byte("v"), backend.Meta{})
	if err == nil || !strings.Contains(err.Error(), "write aad") {
		t.Fatalf("got %v, want write aad error", err)
	}
	if bkExists(encPath) || bkExists(encPath+".nonce") {
		t.Fatal("value.enc / nonce must be removed when the aad sidecar cannot be written")
	}
}

func TestFileBackend_Set_ManifestSaveFailure(t *testing.T) {
	bkSkipNonPOSIX(t)
	bkSkipIfRoot(t)
	dir := t.TempDir()
	fb := openKeyringBackendInDir(t, dir)
	ctx := context.Background()
	// Load the manifest and create the target dir while the root is writable.
	if err := fb.Set(ctx, "default/app/key", []byte("v1"), backend.Meta{}); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := fb.Set(ctx, "default/app/key", []byte("v2"), backend.Meta{})
	if err == nil || !strings.Contains(err.Error(), "save manifest") {
		t.Fatalf("got %v, want save manifest error", err)
	}
}

func TestFileBackend_Delete_RemoveFailure(t *testing.T) {
	bkSkipNonPOSIX(t)
	bkSkipIfRoot(t)
	dir := t.TempDir()
	fb := openKeyringBackendInDir(t, dir)
	ctx := context.Background()
	if err := fb.Set(ctx, "default/app/key", []byte("v"), backend.Meta{}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	parent := filepath.Join(dir, "default", "app")
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	err := fb.Delete(ctx, "default/app/key")
	if err == nil || !strings.Contains(err.Error(), "remove") {
		t.Fatalf("got %v, want remove error", err)
	}
	_ = os.Chmod(parent, 0o700)
	// The manifest entry is kept so a retried Delete can finish the removal.
	entries, lerr := fb.List(ctx, "default/app")
	if lerr != nil || len(entries) != 1 || entries[0].Path != "default/app/key" {
		t.Fatalf("manifest entry must survive a failed delete: %v %v", entries, lerr)
	}
	if err := fb.Delete(ctx, "default/app/key"); err != nil {
		t.Fatalf("retry Delete: %v", err)
	}
	if bkExists(filepath.Join(parent, "key")) {
		t.Fatal("retry Delete left the secret directory behind")
	}
}

func TestFileBackend_Open_DirUnderRegularFile(t *testing.T) {
	bkSkipNonPOSIX(t)
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := file.Open(file.Options{Dir: filepath.Join(f, "vault")})
	if err == nil || !strings.Contains(err.Error(), "mkdir") {
		t.Fatalf("got %v, want mkdir error", err)
	}
}

func TestFileBackend_SetVersioned_CiphertextWriteFailure(t *testing.T) {
	bkSkipNonPOSIX(t)
	dir := t.TempDir()
	fb := openKeyringBackendInDir(t, dir)
	bkBlock(t, filepath.Join(dir, "values", "default", "app", "key", "1"))

	err := fb.SetVersioned(context.Background(), "default/app/key", 1, []byte("v"))
	if err == nil || !strings.Contains(err.Error(), "write ciphertext") {
		t.Fatalf("got %v, want write ciphertext error", err)
	}
}

func TestFileBackend_SetVersioned_ValuesDirBlocked(t *testing.T) {
	bkSkipNonPOSIX(t)
	dir := t.TempDir()
	fb := openKeyringBackendInDir(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "values"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fb.SetVersioned(context.Background(), "default/app/key", 1, []byte("v")); err == nil {
		t.Fatal("expected error when values/ is a regular file")
	}
}

func TestFileBackend_SetVersioned_NonceWriteFailure_RemovesCiphertext(t *testing.T) {
	bkSkipNonPOSIX(t)
	dir := t.TempDir()
	fb := openKeyringBackendInDir(t, dir)
	vp := filepath.Join(dir, "values", "default", "app", "key", "2")
	bkBlock(t, vp+".nonce")

	err := fb.SetVersioned(context.Background(), "default/app/key", 2, []byte("v"))
	if err == nil || !strings.Contains(err.Error(), "write nonce") {
		t.Fatalf("got %v, want write nonce error", err)
	}
	if bkExists(vp) {
		t.Fatal("ciphertext must be removed when its nonce cannot be written")
	}
}

func TestFileBackend_SetVersioned_VersionMetaWriteFailure(t *testing.T) {
	bkSkipNonPOSIX(t)
	dir := t.TempDir()
	fb := openKeyringBackendInDir(t, dir)
	vp := filepath.Join(dir, "values", "default", "app", "key", "1")
	bkBlock(t, vp+".versionmeta")

	if err := fb.SetVersioned(context.Background(), "default/app/key", 1, []byte("v")); err == nil {
		t.Fatal("expected error when the version sidecar cannot be written")
	}
}

func TestFileBackend_GetVersioned_SidecarIsDirectory(t *testing.T) {
	bkSkipNonPOSIX(t)
	dir := t.TempDir()
	fb := openKeyringBackendInDir(t, dir)
	bkBlock(t, filepath.Join(dir, "values", "default", "app", "key", "1.versionmeta"))

	_, err := fb.GetVersioned(context.Background(), "default/app/key", 1)
	if err == nil || errors.Is(err, backend.ErrNotFound) || !strings.Contains(err.Error(), "read version meta") {
		t.Fatalf("got %v, want a non-NotFound read version meta error", err)
	}
}

func TestFileBackend_GetVersionedEncrypted_ErrorMapping(t *testing.T) {
	bkSkipNonPOSIX(t)
	dir := t.TempDir()
	kr, _ := buildKeyring(t, dir, envelope.XChaCha20Poly1305)
	t.Cleanup(kr.Zero)
	fb, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const p = "default/app/key"

	t.Run("unknown key term", func(t *testing.T) {
		vm := buildVersionMeta(t, p, 99, string(envelope.XChaCha20Poly1305), fb.ID())
		_, err := fb.GetVersionedEncrypted(ctx, p, vm, kr)
		if err == nil || !strings.Contains(err.Error(), "get DEK for term 99") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("ciphertext path is a directory", func(t *testing.T) {
		vm := buildVersionMeta(t, p, 1, string(envelope.XChaCha20Poly1305), fb.ID())
		vm.Version = 7
		bkBlock(t, filepath.Join(dir, "values", "default", "app", "key", "7"))
		_, err := fb.GetVersionedEncrypted(ctx, p, vm, kr)
		if err == nil || errors.Is(err, backend.ErrNotFound) || !strings.Contains(err.Error(), "read ciphertext") {
			t.Fatalf("got %v", err)
		}
	})
}

type bkFailingKEK struct{}

func (bkFailingKEK) Wrap([]byte) ([]byte, error)   { return nil, errors.New("wrap refused") }
func (bkFailingKEK) Unwrap([]byte) ([]byte, error) { return nil, errors.New("unwrap refused") }
func (bkFailingKEK) ID() string                    { return "failing" }
func (bkFailingKEK) Type() string                  { return "failing" }

var _ kek.KEK = bkFailingKEK{}

func TestInitKeyring_WrapFailure_WritesNoKeyring(t *testing.T) {
	dir := t.TempDir()
	err := file.InitKeyring(context.Background(), dir, bkFailingKEK{}, envelope.XChaCha20Poly1305)
	if err == nil || !strings.Contains(err.Error(), "wrap DEK") {
		t.Fatalf("got %v, want wrap DEK error", err)
	}
	if bkExists(filepath.Join(dir, "keyring", "keyring.json")) {
		t.Fatal("keyring.json must not be written when wrapping fails")
	}
}

func TestInitKeyring_VaultPathUnderRegularFile(t *testing.T) {
	bkSkipNonPOSIX(t)
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := file.InitKeyring(context.Background(), f, bkFailingKEK{}, envelope.XChaCha20Poly1305)
	if err == nil || !strings.Contains(err.Error(), "create keyring dir") {
		t.Fatalf("got %v, want create keyring dir error", err)
	}
}
