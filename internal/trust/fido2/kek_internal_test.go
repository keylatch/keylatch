package fido2

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/trust"
)

func clearSessionSignals(t *testing.T) {
	t.Helper()
	for _, s := range llmcontext.Signals {
		t.Setenv(s.EnvKey, "")
	}
}

func TestWrapUnwrapRoundTripWithDerivedKEK(t *testing.T) {
	clearSessionSignals(t)
	key := bytes.Repeat([]byte{0x42}, 32)
	a := &Adapter{id: "fido2-test", deriveKEK: func(context.Context) ([]byte, error) {
		return bytes.Clone(key), nil
	}}
	dek := []byte("0123456789abcdef0123456789abcdef")
	want := bytes.Clone(dek)

	wrapped, err := a.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if !bytes.Equal(dek, make([]byte, len(dek))) {
		t.Fatal("Wrap must zero the caller's DEK")
	}
	got, err := a.Unwrap(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("Unwrap returned a different DEK")
	}

	wrapped[len(wrapped)-1] ^= 1
	if _, err := a.Unwrap(context.Background(), wrapped); err == nil {
		t.Fatal("Unwrap accepted a tampered blob")
	}
}

func TestWrapWithoutHardwareIsUnavailable(t *testing.T) {
	clearSessionSignals(t)
	a := &Adapter{id: "fido2-test"}
	if _, err := a.Wrap(context.Background(), make([]byte, 32)); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Fatalf("Wrap: want ErrRootUnavailable, got %v", err)
	}
	if _, err := a.Unwrap(context.Background(), make([]byte, 64)); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Fatalf("Unwrap: want ErrRootUnavailable, got %v", err)
	}
}

func TestDerivedKEKErrorPropagates(t *testing.T) {
	clearSessionSignals(t)
	boom := errors.New("assertion failed")
	a := &Adapter{id: "fido2-test", deriveKEK: func(context.Context) ([]byte, error) { return nil, boom }}
	if _, err := a.Wrap(context.Background(), make([]byte, 32)); !errors.Is(err, boom) {
		t.Fatalf("Wrap: want %v, got %v", boom, err)
	}
}
