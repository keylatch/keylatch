package approval

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestApproverKeyUnlock(t *testing.T) {
	pass := []byte("correct horse battery")
	k, priv, err := NewApproverKey(pass, cheapKDF)
	if err != nil {
		t.Fatal(err)
	}
	unlocked, err := k.Unlock(pass)
	if err != nil {
		t.Fatalf("Unlock with the right passphrase: %v", err)
	}
	if !unlocked.Equal(priv) {
		t.Fatal("Unlock derived a different key")
	}
	if _, err := k.Unlock([]byte("correct horse battery!")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Unlock with a wrong passphrase = %v, want ErrWrongPassphrase", err)
	}
}

func TestApproverKeyRejectsShortPassphrase(t *testing.T) {
	if _, _, err := NewApproverKey([]byte("short"), cheapKDF); !errors.Is(err, ErrPassphraseTooShort) {
		t.Fatalf("NewApproverKey = %v, want ErrPassphraseTooShort", err)
	}
}

func TestApproverKeyFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "approver.json")
	if _, err := LoadApproverKey(path); !errors.Is(err, ErrNoApproverKey) {
		t.Fatalf("LoadApproverKey on a missing file = %v, want ErrNoApproverKey", err)
	}
	pass := []byte("correct horse battery")
	k, _, err := NewApproverKey(pass, cheapKDF)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveApproverKey(path, k); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("approver key mode = %v, want 0600", info.Mode().Perm())
		}
	}
	loaded, err := LoadApproverKey(path)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := loaded.Unlock(pass)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	ar := makeRequest(t, dir)
	if err := Approve(context.Background(), dir, ar.Token, shownOf(t, dir, ar.Token), priv); err != nil {
		t.Fatal(err)
	}
	pub, err := loaded.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), dir, ar.Token, ar.RequestHash, pub); err != nil {
		t.Fatalf("Verify with the approver public key: %v", err)
	}
}

func TestApproverKeyFileValidation(t *testing.T) {
	k, _, err := NewApproverKey([]byte("correct horse battery"), cheapKDF)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(k ApproverKey) ApproverKey{
		"zero time":          func(k ApproverKey) ApproverKey { k.Time = 0; return k },
		"huge memory":        func(k ApproverKey) ApproverKey { k.MemoryKiB = maxKDFMemoryKiB + 1; return k },
		"zero threads":       func(k ApproverKey) ApproverKey { k.Threads = 0; return k },
		"short salt":         func(k ApproverKey) ApproverKey { k.Salt = "c2FsdA=="; return k },
		"unknown version":    func(k ApproverKey) ApproverKey { k.Version = 2; return k },
		"invalid public key": func(k ApproverKey) ApproverKey { k.PublicKey = "AAAA"; return k },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := mutate(*k)
			if _, err := bad.Unlock([]byte("correct horse battery")); err == nil {
				t.Fatal("Unlock accepted an invalid key file")
			}
		})
	}

	path := filepath.Join(t.TempDir(), "approver.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"public_key":"","extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadApproverKey(path); err == nil {
		t.Fatal("LoadApproverKey accepted unknown fields")
	}
}
