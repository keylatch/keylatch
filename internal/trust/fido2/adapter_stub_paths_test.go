package fido2

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/trust"
)

func trfClearLLMEnv(t *testing.T) {
	t.Helper()
	clearSessionSignals(t)
}

func TestNewFromSpec(t *testing.T) {
	a, err := New(trust.RootSpec{ID: "fido2-abc", Label: "key"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != "fido2-abc" || a.opts.Label != "key" {
		t.Fatalf("adapter = %+v", a)
	}
	b, _ := New(trust.RootSpec{})
	if b.ID() != "fido2-unknown" {
		t.Fatalf("default ID = %q", b.ID())
	}

	r, err := trust.New(trust.RootSpec{Type: trust.RootFIDO2, ID: "fido2-reg"})
	if err != nil || r.ID() != "fido2-reg" || r.Type() != trust.RootFIDO2 {
		t.Fatalf("factory = %v, %v", r, err)
	}
}

func TestEnrollWithoutHardware(t *testing.T) {
	trfClearLLMEnv(t)
	a, spec, err := Enroll(context.Background(), EnrollOptions{DevicePath: "/dev/hidraw0", RPID: "keylatch://local"})
	if a != nil || spec.ID != "" {
		t.Fatalf("Enroll returned adapter=%v spec=%+v", a, spec)
	}
	if !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "requires hardware") {
		t.Fatalf("err = %v", err)
	}
}

func TestHardwareOperationsWithoutDevice(t *testing.T) {
	trfClearLLMEnv(t)
	a, _ := New(trust.RootSpec{ID: "f"})
	a.HMACFunc = func(b []byte) []byte { return b }
	ctx := context.Background()

	if _, _, err := a.Sign(ctx, []byte("c")); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Errorf("Sign: %v", err)
	}
	if err := a.Verify(ctx, nil, nil, nil); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Errorf("Verify: %v", err)
	}
	p, err := a.RequirePresence(ctx, "reveal")
	if !errors.Is(err, trust.ErrRootUnavailable) {
		t.Errorf("RequirePresence: %v", err)
	}
	if p != (trust.PresenceProof{}) {
		t.Errorf("failed presence must return an empty proof, got %+v", p)
	}
	if att, err := a.Attest(ctx); err != nil || att.Format != "packed" {
		t.Errorf("Attest = %+v, %v", att, err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if _, err := a.Unwrap(ctx, []byte("x")); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Errorf("Unwrap: %v", err)
	}
}

func TestVerifyPresenceProofStructure(t *testing.T) {
	a, _ := New(trust.RootSpec{})
	ctx := context.Background()
	if err := a.VerifyPresenceProof(ctx, trust.PresenceProof{RootID: "r"}); err == nil {
		t.Error("proof without timestamp accepted")
	}
	if err := a.VerifyPresenceProof(ctx, trust.PresenceProof{ConfirmedAt: timeNowForTest()}); err == nil {
		t.Error("proof without root ID accepted")
	}
	if err := a.VerifyPresenceProof(ctx, trust.PresenceProof{RootID: "r", ConfirmedAt: timeNowForTest()}); err != nil {
		t.Errorf("valid proof rejected: %v", err)
	}
}

func TestLLMSessionBlocksAllHardwarePaths(t *testing.T) {
	trfClearLLMEnv(t)
	t.Setenv("CLAUDECODE", "1")
	a, _ := New(trust.RootSpec{})
	called := false
	a.deriveKEK = func(context.Context) ([]byte, error) { called = true; return make([]byte, 32), nil }
	ctx := context.Background()

	if _, _, err := a.Sign(ctx, nil); !errors.Is(err, trust.ErrLLMSessionBlocked) {
		t.Errorf("Sign: %v", err)
	}
	if _, err := a.RequirePresence(ctx, "r"); !errors.Is(err, trust.ErrLLMSessionBlocked) {
		t.Errorf("RequirePresence: %v", err)
	}
	if _, err := a.Unwrap(ctx, make([]byte, 40)); !errors.Is(err, trust.ErrLLMSessionBlocked) {
		t.Errorf("Unwrap: %v", err)
	}
	if called {
		t.Fatal("KEK derived inside an LLM session")
	}
}

func TestBadKEKLengthAndShortCiphertext(t *testing.T) {
	trfClearLLMEnv(t)
	a, _ := New(trust.RootSpec{})
	a.deriveKEK = func(context.Context) ([]byte, error) { return make([]byte, 7), nil }
	ctx := context.Background()
	dek := []byte{1, 2, 3}
	if _, err := a.Wrap(ctx, dek); err == nil || !strings.Contains(err.Error(), "fido2: aes") {
		t.Errorf("Wrap: %v", err)
	}
	if dek[0]|dek[1]|dek[2] != 0 {
		t.Error("Wrap must zero the DEK on failure")
	}
	if _, err := a.Unwrap(ctx, make([]byte, 40)); err == nil || !strings.Contains(err.Error(), "fido2: aes") {
		t.Errorf("Unwrap: %v", err)
	}

	a.deriveKEK = func(context.Context) ([]byte, error) { return make([]byte, 32), nil }
	if _, err := a.Unwrap(ctx, make([]byte, 5)); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Errorf("short ciphertext: %v", err)
	}
	if _, err := a.Unwrap(ctx, make([]byte, 40)); err == nil {
		t.Error("tampered ciphertext must fail authentication")
	}
}

func timeNowForTest() time.Time { return time.Now().UTC() }
