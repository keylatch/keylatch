//go:build windows

package kek

import (
	"bytes"
	"errors"
	"testing"
)

func TestDPAPIKEKRoundTrip(t *testing.T) {
	s := &dpapiIdentityStore{dir: t.TempDir()}
	id := bytes.Repeat([]byte{7}, identitySize)
	if err := s.Store("vault-abc", id); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, err := s.Load("vault-abc")
	if err != nil || !bytes.Equal(got, id) {
		t.Fatalf("load = %x, %v", got, err)
	}
	if err := s.Delete("vault-abc"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Load("vault-abc"); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}
