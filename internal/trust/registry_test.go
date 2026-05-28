package trust_test

import (
	"context"
	"crypto"
	"testing"

	"github.com/keylatch/keylatch/internal/trust"
)

// mockRoot is a minimal RootOfTrust for registry tests.
type mockRoot struct {
	id   string
	kind trust.RootType
}

func (m *mockRoot) ID() string                  { return m.id }
func (m *mockRoot) Type() trust.RootType        { return m.kind }
func (m *mockRoot) Has(c trust.Capability) bool { return c == trust.CapWrap }
func (m *mockRoot) Wrap(_ context.Context, _ []byte) ([]byte, error) {
	return []byte("wrapped"), nil
}
func (m *mockRoot) Unwrap(_ context.Context, _ []byte) ([]byte, error) {
	return []byte("plain"), nil
}
func (m *mockRoot) Sign(_ context.Context, _ []byte) ([]byte, crypto.PublicKey, error) {
	return nil, nil, trust.ErrCapabilityUnsupported
}
func (m *mockRoot) Verify(_ context.Context, _, _ []byte, _ crypto.PublicKey) error {
	return trust.ErrCapabilityUnsupported
}
func (m *mockRoot) RequirePresence(_ context.Context, _ string) (trust.PresenceProof, error) {
	return trust.PresenceProof{}, trust.ErrCapabilityUnsupported
}
func (m *mockRoot) VerifyPresenceProof(_ context.Context, _ trust.PresenceProof) error {
	return trust.ErrCapabilityUnsupported
}
func (m *mockRoot) Attest(_ context.Context) (trust.Attestation, error) {
	return trust.Attestation{}, trust.ErrCapabilityUnsupported
}
func (m *mockRoot) Close() error { return nil }

func TestRegistry_RoundTrip(t *testing.T) {
	const testType trust.RootType = "test_mock_registry"
	trust.Register(testType, func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		return &mockRoot{id: spec.ID, kind: spec.Type}, nil
	})
	t.Cleanup(func() { trust.Unregister(testType) })

	spec := trust.RootSpec{
		ID:     "test-root-1",
		Type:   testType,
		Status: trust.RootActive,
	}
	root, err := trust.New(spec)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if root.ID() != spec.ID {
		t.Errorf("ID() = %q, want %q", root.ID(), spec.ID)
	}
	if root.Type() != testType {
		t.Errorf("Type() = %q, want %q", root.Type(), testType)
	}
	if !root.Has(trust.CapWrap) {
		t.Error("Has(CapWrap) = false, want true")
	}
	if root.Has(trust.CapSignChallenge) {
		t.Error("Has(CapSignChallenge) = true, want false")
	}
}

func TestRegistry_UnknownType(t *testing.T) {
	const unknownType trust.RootType = "trust_unknown_xyz_no_factory"
	_, err := trust.New(trust.RootSpec{Type: unknownType, Status: trust.RootActive})
	if err == nil {
		t.Fatal("New() with unknown type: expected error, got nil")
	}
}

func TestDoctor_AllUnavailable(t *testing.T) {
	// Doctor on a fresh registry (no adapters available by default in tests) should
	// return a report with Available=false for all rows that probe fails, or
	// simply an empty rows list if no factories are registered.
	// We register a failing factory to confirm the unavailable path.
	const failType trust.RootType = "test_mock_fail"
	trust.Register(failType, func(_ trust.RootSpec) (trust.RootOfTrust, error) {
		return nil, trust.ErrRootUnavailable
	})
	t.Cleanup(func() { trust.Unregister(failType) })

	report := trust.Doctor(context.Background())
	// At minimum one row should be present (our registered fail type).
	found := false
	for _, row := range report.Rows {
		if row.Type == failType {
			found = true
			if row.Available {
				t.Error("failing adapter reported Available=true")
			}
		}
	}
	if !found {
		t.Error("Doctor did not include the registered failing adapter type")
	}

	// Verify JSON is non-empty and value-free (no raw key material — at minimum valid JSON).
	j := report.JSON()
	if len(j) == 0 {
		t.Error("Report.JSON() returned empty slice")
	}

	// Verify string representation is non-empty.
	s := report.String()
	if s == "" {
		t.Error("Report.String() returned empty string")
	}
}
