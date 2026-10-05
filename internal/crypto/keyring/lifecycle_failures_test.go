package keyring

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
)

// scKEK is a deterministic in-memory KEK. It tags wrapped blobs with its id so
// a different scKEK instance cannot unwrap them.
type scKEK struct {
	id        string
	failWrap  bool
	rejectDEK []byte
}

func (k *scKEK) Wrap(dek []byte) ([]byte, error) {
	if k.failWrap {
		return nil, errors.New("wrap refused")
	}
	out := append([]byte(k.id+":"), dek...)
	for i := len(k.id) + 1; i < len(out); i++ {
		out[i] ^= 0x5a
	}
	return out, nil
}

func (k *scKEK) Unwrap(wrapped []byte) ([]byte, error) {
	prefix := []byte(k.id + ":")
	if !bytes.HasPrefix(wrapped, prefix) {
		return nil, kek.ErrKEKUnavailable
	}
	dek := append([]byte(nil), wrapped[len(prefix):]...)
	for i := range dek {
		dek[i] ^= 0x5a
	}
	if k.rejectDEK != nil && bytes.Equal(dek, k.rejectDEK) {
		return nil, kek.ErrKEKUnavailable
	}
	return dek, nil
}

func (k *scKEK) ID() string   { return k.id }
func (k *scKEK) Type() string { return "passphrase" }

func scNewKeyring(t *testing.T, alg envelope.Algorithm) (*Keyring, string, *scKEK) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "kr")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "keyring.json")
	k := &scKEK{id: "primary"}
	if err := New(path, k, alg, 4); err != nil {
		t.Fatalf("New: %v", err)
	}
	kr, err := Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return kr, path, k
}

func scSkipNoPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("directory permission semantics differ")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
}

func scReadOnly(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

func TestNew_WrapFailureWritesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	bad := &scKEK{id: "x", failWrap: true}
	if err := New(path, bad, envelope.XChaCha20Poly1305, 0); err == nil || !strings.Contains(err.Error(), "wrap DEK") {
		t.Fatalf("New: %v", err)
	}
	if err := NewWithSalt(path, bad, envelope.XChaCha20Poly1305, 0, []byte("salt")); err == nil || !strings.Contains(err.Error(), "wrap DEK") {
		t.Fatalf("NewWithSalt: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("keyring file created despite wrap failure: %v", err)
	}
}

func TestOpen_WrongKEKAndDestroyedTerms(t *testing.T) {
	kr, path, k := scNewKeyring(t, envelope.XChaCha20Poly1305)
	if _, err := Open(path, &scKEK{id: "other"}); !errors.Is(err, ErrKEKMismatch) {
		t.Fatalf("wrong KEK: %v", err)
	}

	if _, err := kr.RotateTerm(k); err != nil {
		t.Fatal(err)
	}
	if err := kr.DestroyTerm(1); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, k)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := reopened.DEKForTerm(1); !errors.Is(err, ErrKeyTermDestroyed) {
		t.Fatalf("destroyed term: %v", err)
	}
	if _, err := reopened.DEKForTerm(7); !errors.Is(err, ErrKeyTermNotFound) {
		t.Fatalf("unknown term: %v", err)
	}
	if _, term, err := reopened.ActiveDEK(); err != nil || term != 2 {
		t.Fatalf("ActiveDEK: term=%d err=%v", term, err)
	}
}

func TestActiveDEK_MissingWhenActiveTermUndecryptable(t *testing.T) {
	kr, path, k := scNewKeyring(t, envelope.XChaCha20Poly1305)
	if _, err := kr.RotateTerm(k); err != nil {
		t.Fatal(err)
	}
	activeDEK, err := kr.DEKForTerm(2)
	if err != nil {
		t.Fatal(err)
	}
	partial := &scKEK{id: "primary", rejectDEK: append([]byte(nil), activeDEK...)}
	reopened, err := Open(path, partial)
	if err != nil {
		t.Fatalf("Open with one decryptable term: %v", err)
	}
	if _, _, err := reopened.ActiveDEK(); !errors.Is(err, ErrKeyTermNotFound) {
		t.Fatalf("ActiveDEK: %v", err)
	}
	if err := reopened.RotateKEK(&scKEK{id: "next"}); err == nil || !strings.Contains(err.Error(), "not in memory") {
		t.Fatalf("RotateKEK with missing DEK: %v", err)
	}
	if _, err := Open(path, k); err != nil {
		t.Fatalf("failed RotateKEK must leave keyring openable with old KEK: %v", err)
	}
}

func TestRotateKEK_SkipsDestroyedAndRewrapsRest(t *testing.T) {
	kr, path, k := scNewKeyring(t, envelope.XChaCha20Poly1305)
	if _, err := kr.RotateTerm(k); err != nil {
		t.Fatal(err)
	}
	if err := kr.DestroyTerm(1); err != nil {
		t.Fatal(err)
	}
	next := &scKEK{id: "next"}
	if err := kr.RotateKEK(next); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, k); !errors.Is(err, ErrKEKMismatch) {
		t.Fatalf("old KEK still opens keyring: %v", err)
	}
	reopened, err := Open(path, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, term, err := reopened.ActiveDEK(); err != nil || term != 2 {
		t.Fatalf("ActiveDEK after RotateKEK: %d %v", term, err)
	}

	if err := kr.RotateKEK(&scKEK{id: "bad", failWrap: true}); err == nil || !strings.Contains(err.Error(), "wrap term") {
		t.Fatalf("wrap failure: %v", err)
	}
	if _, err := Open(path, next); err != nil {
		t.Fatalf("keyring changed by failed RotateKEK: %v", err)
	}
}

func TestRotateTerm_WrapFailureLeavesFileUntouched(t *testing.T) {
	kr, path, _ := scNewKeyring(t, envelope.XChaCha20Poly1305)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.RotateTerm(&scKEK{id: "p", failWrap: true}); err == nil || !strings.Contains(err.Error(), "wrap DEK") {
		t.Fatalf("RotateTerm: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("keyring file modified by failed rotation")
	}
}

func TestMutations_LockPathUnavailable(t *testing.T) {
	kr, path, k := scNewKeyring(t, envelope.XChaCha20Poly1305)
	if err := os.Mkdir(path+".lock", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.RotateTerm(k); err == nil || !strings.Contains(err.Error(), "acquire lock") {
		t.Fatalf("RotateTerm: %v", err)
	}
	if err := kr.RotateKEK(k); err == nil || !strings.Contains(err.Error(), "acquire lock") {
		t.Fatalf("RotateKEK: %v", err)
	}
	if err := kr.DestroyTerm(1); err == nil || !strings.Contains(err.Error(), "acquire lock") {
		t.Fatalf("DestroyTerm: %v", err)
	}
}

func TestMutations_SaveFailures(t *testing.T) {
	scSkipNoPerms(t)
	kr, path, k := scNewKeyring(t, envelope.XChaCha20Poly1305)
	if _, err := kr.RotateTerm(k); err != nil {
		t.Fatal(err)
	}
	// Pre-create the lock file so the read-only directory only blocks the
	// temp-file write.
	if f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		_ = f.Close()
	}
	scReadOnly(t, filepath.Dir(path))

	if _, err := kr.RotateTerm(k); err == nil || !strings.Contains(err.Error(), "RotateTerm: save") {
		t.Fatalf("RotateTerm: %v", err)
	}
	if err := kr.RotateKEK(&scKEK{id: "n"}); err == nil || !strings.Contains(err.Error(), "RotateKEK: save") {
		t.Fatalf("RotateKEK: %v", err)
	}
	if err := kr.DestroyTerm(1); err == nil || !strings.Contains(err.Error(), "DestroyTerm: save") {
		t.Fatalf("DestroyTerm: %v", err)
	}
}

func TestDestroyTerm_FileGone(t *testing.T) {
	kr, path, _ := scNewKeyring(t, envelope.XChaCha20Poly1305)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := kr.DestroyTerm(1); !errors.Is(err, ErrKeyringNotFound) {
		t.Fatalf("DestroyTerm: %v", err)
	}
}

func TestLoadFile_StatAndReadErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFile(filepath.Join(blocker, "keyring.json")); !errors.Is(err, ErrKeyringCorrupt) {
		t.Fatalf("stat error: %v", err)
	}
	asDir := filepath.Join(dir, "asdir")
	if err := os.Mkdir(asDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(asDir, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(asDir, 0o700) })
	_, err := loadFile(asDir)
	if !errors.Is(err, ErrKeyringCorrupt) {
		t.Fatalf("read error: %v", err)
	}
	if runtime.GOOS != "windows" && !strings.Contains(err.Error(), "read") {
		t.Fatalf("read error message: %v", err)
	}
}

func TestAtomicWrite_Failures(t *testing.T) {
	dir := t.TempDir()
	if err := atomicWrite(filepath.Join(dir, "missing", "k.json"), []byte("{}")); err == nil || !strings.Contains(err.Error(), "create temp") {
		t.Fatalf("missing dir: %v", err)
	}

	target := filepath.Join(dir, "occupied")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(target, []byte("{}")); err == nil || !strings.Contains(err.Error(), "rename") {
		t.Fatalf("rename over directory: %v", err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".keyring-*.tmp"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left: %v", leftovers)
	}

	ok := filepath.Join(dir, "ok.json")
	if err := atomicWrite(ok, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(ok)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %04o", st.Mode().Perm())
		}
	}
}

func TestNextGCMNonce_LeaseRenewalFailures(t *testing.T) {
	t.Run("lock unavailable", func(t *testing.T) {
		kr, _, _ := scNewKeyring(t, envelope.AES256GCM)
		if err := os.Mkdir(kr.lockPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := kr.NextGCMNonce(1); err == nil || !strings.Contains(err.Error(), "flock") {
			t.Fatalf("NextGCMNonce: %v", err)
		}
	})

	t.Run("keyring file removed", func(t *testing.T) {
		kr, path, _ := scNewKeyring(t, envelope.AES256GCM)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := kr.NextGCMNonce(1); err == nil || !strings.Contains(err.Error(), "reload keyring") {
			t.Fatalf("NextGCMNonce: %v", err)
		}
	})

	t.Run("nonces unique across lease renewals", func(t *testing.T) {
		kr, _, _ := scNewKeyring(t, envelope.AES256GCM)
		seen := map[string]bool{}
		for i := 0; i < 10; i++ {
			n, err := kr.Next(envelope.AES256GCM, 1)
			if err != nil {
				t.Fatal(err)
			}
			if len(n) != 12 || seen[string(n)] {
				t.Fatalf("nonce %d invalid or repeated: %x", i, n)
			}
			seen[string(n)] = true
		}
	})
}
