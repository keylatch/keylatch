package keys

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRoot(b byte) []byte { return bytes.Repeat([]byte{b}, 48) }

func openTest(t *testing.T, dir string, root []byte) *Hierarchy {
	t.Helper()
	h, err := Open(dir, root, false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(h.Close)
	return h
}

func TestHierarchyDerivations(t *testing.T) {
	dir := t.TempDir()
	h := openTest(t, dir, testRoot(1))

	kidA, kekA := h.StoreKEK("1000")
	_, kekB := h.StoreKEK("1001")
	if len(kekA) != 32 || bytes.Equal(kekA, kekB) {
		t.Fatal("store KEKs must be 32 bytes and differ per partition")
	}
	if got, err := h.KEKFor(kidA, "1000"); err != nil || !bytes.Equal(got, kekA) {
		t.Fatalf("KEKFor current = %x, %v", got, err)
	}
	cred := h.BackendCredentialKEK()
	seed, seal := h.AuditKeys()
	for name, k := range map[string][]byte{"backend": cred, "audit seed": seed, "audit seal": seal} {
		if bytes.Equal(k, kekA) || len(k) != 32 {
			t.Fatalf("%s key collides with the store KEK or has the wrong length", name)
		}
	}
	if bytes.Equal(seed, seal) || bytes.Equal(seed, cred) {
		t.Fatal("audit seed, audit seal and backend KEKs must be independent")
	}

	pub, err := h.Public(PolicySigning)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := h.TokenKey()
	if err != nil || len(tok) != 32 {
		t.Fatalf("TokenKey = %x, %v", tok, err)
	}
	signer, _ := h.Signer(TokenSigning)
	if bytes.Equal(tok, signer.Seed()) {
		t.Fatal("the token MAC key must not be the signing seed")
	}

	// Reopening with the same root reproduces every key.
	h.Close()
	h2 := openTest(t, dir, testRoot(1))
	if _, k := h2.StoreKEK("1000"); !bytes.Equal(k, kekA) {
		t.Fatal("store KEK changed across reopen")
	}
	if pub2, _ := h2.Public(PolicySigning); !bytes.Equal(pub, pub2) {
		t.Fatal("policy-signing key changed across reopen")
	}

	// Keys are never written unwrapped.
	for _, name := range h2.Files() {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range [][]byte{kekA, signer.Seed(), testRoot(1)} {
			if bytes.Contains(b, secret) {
				t.Fatalf("%s contains unwrapped key material", name)
			}
		}
		info, _ := os.Stat(filepath.Join(dir, name))
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, want 0600", name, info.Mode().Perm())
		}
	}

	h2.Close()
	if _, err := Open(dir, testRoot(2), false); !errors.Is(err, ErrWrongRoot) {
		t.Fatalf("Open with another root = %v, want ErrWrongRoot", err)
	}
	if _, err := Open(dir, []byte("short"), false); !errors.Is(err, ErrNoRoot) {
		t.Fatalf("Open with a short root = %v, want ErrNoRoot", err)
	}
}

func TestBMKRotationRewraps(t *testing.T) {
	dir := t.TempDir()
	h := openTest(t, dir, testRoot(3))
	oldKID, oldKEK := h.StoreKEK("1000")
	pubs := map[Name]ed25519.PublicKey{}
	for _, n := range childNames {
		p, err := h.Public(n)
		if err != nil {
			t.Fatal(err)
		}
		pubs[n] = p
	}

	var gotOld, gotNew []byte
	if err := h.Rotate(func(o, n KEKFunc, _ string) error {
		gotOld, gotNew = o("1000"), n("1000")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotOld, oldKEK) || bytes.Equal(gotNew, oldKEK) {
		t.Fatal("rewrap must see the old KEK and a different new KEK")
	}
	newKID, newKEK := h.StoreKEK("1000")
	if newKID == oldKID || !bytes.Equal(newKEK, gotNew) {
		t.Fatal("the master key did not change")
	}
	for _, n := range childNames {
		if p, err := h.Public(n); err != nil || !bytes.Equal(p, pubs[n]) {
			t.Fatalf("%s changed across rotation: %v", n, err)
		}
	}
	if _, err := h.KEKFor(oldKID, "1000"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("the retired master key must be gone, got %v", err)
	}

	// The rotation survives a restart, and the old root-wrapped key is gone.
	h.Close()
	h2 := openTest(t, dir, testRoot(3))
	if h2.KeyID() != newKID {
		t.Fatalf("KeyID after reopen = %s, want %s", h2.KeyID(), newKID)
	}
	for _, n := range childNames {
		if p, err := h2.Public(n); err != nil || !bytes.Equal(p, pubs[n]) {
			t.Fatalf("%s unreadable after reopen: %v", n, err)
		}
	}
	for _, f := range h2.Files() {
		if strings.HasSuffix(f, stagedExt) {
			t.Fatalf("staged file %s left behind", f)
		}
	}
}

func TestRotationResumesAfterFailure(t *testing.T) {
	dir := t.TempDir()
	h := openTest(t, dir, testRoot(4))
	_, _ = h.Public(TokenSigning)
	oldKID, _ := h.StoreKEK("p")

	boom := errors.New("data rewrap failed")
	if err := h.Rotate(func(_, _ KEKFunc, _ string) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("Rotate = %v, want the rewrap error", err)
	}
	if !h.Pending() || h.KeyID() != oldKID {
		t.Fatal("a failed rewrap must leave the old key current and the rotation staged")
	}

	h.Close()
	h2 := openTest(t, dir, testRoot(4))
	if !h2.Pending() {
		t.Fatal("the staged rotation must be visible after a restart")
	}
	if _, err := h2.KEKFor(oldKID, "p"); err != nil {
		t.Fatalf("old data must stay readable while the rotation is staged: %v", err)
	}
	called := false
	if err := h2.Resume(func(_, _ KEKFunc, _ string) error { called = true; return nil }); err != nil || !called {
		t.Fatalf("Resume = %v called=%v", err, called)
	}
	if h2.Pending() || h2.KeyID() == oldKID {
		t.Fatal("Resume must commit the staged key")
	}
	if err := h2.Resume(nil); err != nil {
		t.Fatalf("Resume with nothing staged = %v", err)
	}
	if err := h2.Rotate(nil); err != nil {
		t.Fatalf("a second rotation must work: %v", err)
	}
}

func TestKeysMlocked(t *testing.T) {
	h, err := Open(t.TempDir(), testRoot(5), true)
	if err != nil {
		t.Skipf("mlock is not permitted here: %v", err)
	}
	defer h.Close()
	if !h.Locked() {
		t.Fatal("the master key must sit in locked memory")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skip("no /proc/self/status")
	}
	var lockedKB string
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "VmLck:"); ok {
			lockedKB = strings.TrimSpace(v)
		}
	}
	if lockedKB == "" || strings.HasPrefix(lockedKB, "0 ") {
		t.Fatalf("VmLck = %q, want pages locked", lockedKB)
	}
}

func TestLoadRoot(t *testing.T) {
	if _, err := LoadRoot(""); !errors.Is(err, ErrNoRoot) {
		t.Fatalf("empty dir = %v", err)
	}
	dir := t.TempDir()
	if _, err := LoadRoot(dir); !errors.Is(err, ErrNoRoot) {
		t.Fatalf("missing file = %v", err)
	}
	path := filepath.Join(dir, CredentialName)
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoot(dir); !errors.Is(err, ErrNoRoot) {
		t.Fatalf("short file = %v", err)
	}
	if err := os.WriteFile(path, testRoot(9), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := LoadRoot(dir); err != nil || !bytes.Equal(b, testRoot(9)) {
		t.Fatalf("LoadRoot = %x, %v", b, err)
	}
}

func TestSignerRejectsUnknownAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	h := openTest(t, dir, testRoot(6))
	if _, err := h.Signer("nope"); err == nil {
		t.Fatal("an unknown key name must be refused")
	}
	if _, err := h.Signer(MachineCA); err != nil {
		t.Fatal(err)
	}
	h.Close()

	if err := os.WriteFile(filepath.Join(dir, "machine-ca.key"), []byte(`{"v":1,"kid":"x","nonce":"","ct":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h2 := openTest(t, dir, testRoot(6))
	if _, err := h2.Signer(MachineCA); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("a key wrapped by an unknown master key = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "machine-ca.key"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h2.Signer(MachineCA); err == nil {
		t.Fatal("a corrupt key file must be refused")
	}
}

func TestLockRefusal(t *testing.T) {
	prev := lockMem
	lockMem = func([]byte) error { return errors.New("denied") }
	defer func() { lockMem = prev }()

	if _, err := Open(t.TempDir(), testRoot(7), true); err == nil {
		t.Fatal("Open must fail when key pages cannot be locked and locking is required")
	}
	h, err := Open(t.TempDir(), testRoot(7), false)
	if err != nil {
		t.Fatalf("Open without required locking = %v", err)
	}
	defer h.Close()
	if h.Locked() {
		t.Fatal("Locked must report false when mlock was refused")
	}
}

func TestWriteFailuresSurface(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	dir := t.TempDir()
	h := openTest(t, dir, testRoot(8))
	if _, err := h.Public(TokenSigning); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if _, err := h.Signer(PolicySigning); err == nil {
		t.Fatal("a key that cannot be stored must not be returned")
	}
	if err := h.Rotate(nil); err == nil {
		t.Fatal("a rotation that cannot be staged must fail")
	}
	if h.Pending() {
		t.Fatal("a failed staging must leave nothing pending")
	}
	if _, err := Open(filepath.Join(dir, "sub"), testRoot(8), false); err == nil {
		t.Fatal("Open must fail where the directory cannot be created")
	}
}

func TestOpenRejectsMalformedWrap(t *testing.T) {
	for name, body := range map[string]string{
		"format": `{"v":9,"kid":"x","nonce":"","ct":""}`,
		"nonce":  `{"v":1,"kid":"x","nonce":"AAAA","ct":"AAAA"}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, bmkFile), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(dir, testRoot(1), false); !errors.Is(err, ErrWrongRoot) {
				t.Fatalf("Open = %v, want ErrWrongRoot", err)
			}
		})
	}
}

func TestRotateRefusesWhileStaged(t *testing.T) {
	h := openTest(t, t.TempDir(), testRoot(2))
	boom := errors.New("stop")
	_ = h.Rotate(func(_, _ KEKFunc, _ string) error { return boom })
	if err := h.Rotate(nil); err == nil || !strings.Contains(err.Error(), "staged") {
		t.Fatalf("Rotate while staged = %v", err)
	}
}
