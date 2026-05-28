package fido2_test

import (
	"context"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/trust"
	"github.com/keylatch/keylatch/internal/trust/fido2"
)

func TestFIDO2Adapter_Has(t *testing.T) {
	spec := trust.RootSpec{ID: "test-fido2", Type: trust.RootFIDO2, Status: trust.RootActive}
	a, err := fido2.New(spec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	caps := []struct {
		cap      trust.Capability
		expected bool
	}{
		{trust.CapWrap, true},
		{trust.CapSignChallenge, true},
		{trust.CapUserPresence, true},
		{trust.CapHardwareBound, true},
		{trust.CapAttestation, true},
		{trust.CapLaunchdSafe, false},
		{trust.CapMTLSClientAuth, false},
	}

	for _, tc := range caps {
		got := a.Has(tc.cap)
		if got != tc.expected {
			t.Errorf("Has(cap %d) = %v, want %v", tc.cap, got, tc.expected)
		}
	}
}

func TestFIDO2Adapter_LLMSessionBlock(t *testing.T) {
	// Set CLAUDE_CODE to trigger LLM session detection.
	os.Setenv("CLAUDE_CODE", "1")
	defer os.Unsetenv("CLAUDE_CODE")

	spec := trust.RootSpec{ID: "test-fido2", Type: trust.RootFIDO2, Status: trust.RootActive}
	a, err := fido2.New(spec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, _, err = a.Sign(context.Background(), []byte("test"))
	if err != trust.ErrLLMSessionBlocked {
		t.Errorf("Sign in LLM session: want ErrLLMSessionBlocked, got %v", err)
	}

	_, err = a.RequirePresence(context.Background(), "test reason")
	if err != trust.ErrLLMSessionBlocked {
		t.Errorf("RequirePresence in LLM session: want ErrLLMSessionBlocked, got %v", err)
	}
}

func TestFIDO2Adapter_EnrollBlockedInLLMSession(t *testing.T) {
	os.Setenv("CLAUDE_CODE", "1")
	defer os.Unsetenv("CLAUDE_CODE")

	_, _, err := fido2.Enroll(context.Background(), fido2.EnrollOptions{})
	if err != trust.ErrLLMSessionBlocked {
		t.Errorf("Enroll in LLM session: want ErrLLMSessionBlocked, got %v", err)
	}
}

func TestFIDO2Adapter_Type(t *testing.T) {
	spec := trust.RootSpec{ID: "test-fido2", Type: trust.RootFIDO2, Status: trust.RootActive}
	a, _ := fido2.New(spec)
	if a.Type() != trust.RootFIDO2 {
		t.Errorf("Type() = %q, want %q", a.Type(), trust.RootFIDO2)
	}
}

func TestFIDO2Integration(t *testing.T) {
	if os.Getenv("KEYLATCH_E2E_FIDO2") != "1" {
		t.Skip("KEYLATCH_E2E_FIDO2 not set; skipping integration test")
	}
	// Integration test body would go here.
	t.Log("FIDO2 integration test placeholder")
}
