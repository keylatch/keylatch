package testutil

import (
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/kek"
)

func TestMemoryIdentityStore(t *testing.T) {
	s := NewMemoryIdentityStore()
	if s.Name() != "memory" || s.Len() != 0 {
		t.Fatal("new store must be empty")
	}
	if _, err := s.Load("a"); !errors.Is(err, kek.ErrIdentityNotFound) {
		t.Fatalf("Load missing = %v", err)
	}
	if err := s.Delete("a"); !errors.Is(err, kek.ErrIdentityNotFound) {
		t.Fatalf("Delete missing = %v", err)
	}

	secret := []byte("secret")
	if err := s.Store("a", secret); err != nil {
		t.Fatal(err)
	}
	secret[0] = 'X'
	got, err := s.Load("a")
	if err != nil || string(got) != "secret" {
		t.Fatalf("Load = %q, %v: the store must copy what it is given", got, err)
	}
	got[0] = 'Y'
	if again, _ := s.Load("a"); string(again) != "secret" {
		t.Fatal("the store must return copies")
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d", s.Len())
	}

	s.StoreErr = ErrKeyringLocked
	if err := s.Store("b", secret); !errors.Is(err, ErrKeyringLocked) {
		t.Fatalf("Store = %v", err)
	}
	s.StoreErr = nil
	if err := s.Delete("a"); err != nil || s.Len() != 0 {
		t.Fatalf("Delete = %v, Len = %d", err, s.Len())
	}
}
