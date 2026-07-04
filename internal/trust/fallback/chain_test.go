package fallback_test

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/trust"
	"github.com/keylatch/keylatch/internal/trust/fallback"
)

// registerMock registers a trust factory that always succeeds (returning a stub root).
// Registers cleanup to remove the factory when the test ends (Mi-7).
func registerMock(t *testing.T, rootType trust.RootType) {
	t.Helper()
	trust.Register(rootType, func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		return &stubRoot{id: spec.ID, kind: rootType}, nil
	})
	t.Cleanup(func() {
		trust.Unregister(rootType)
	})
}

// registerFailing registers a trust factory that always fails.
// Registers cleanup to remove the factory when the test ends (Mi-7).
func registerFailing(t *testing.T, rootType trust.RootType) {
	t.Helper()
	trust.Register(rootType, func(_ trust.RootSpec) (trust.RootOfTrust, error) {
		return nil, trust.ErrRootUnavailable
	})
	t.Cleanup(func() {
		trust.Unregister(rootType)
	})
}

func TestChain_FirstAvailableWins(t *testing.T) {
	const typeA trust.RootType = "test_chain_a"
	const typeB trust.RootType = "test_chain_b"
	registerMock(t, typeA)
	registerMock(t, typeB)

	specs := []trust.RootSpec{
		{ID: "a1", Type: typeA, Status: trust.RootActive},
		{ID: "b1", Type: typeB, Status: trust.RootActive},
	}
	chain := fallback.NewChain(specs)
	root, _, err := chain.Resolve(context.Background(), fallback.Operation{
		Kind:               fallback.OperationWrap,
		InteractiveAllowed: true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if root.ID() != "a1" {
		t.Errorf("first-wins: got %q, want %q", root.ID(), "a1")
	}
}

func TestChain_SkipsRetiredRoot(t *testing.T) {
	const typeR trust.RootType = "test_chain_retired"
	registerMock(t, typeR)

	specs := []trust.RootSpec{
		{ID: "retired", Type: typeR, Status: trust.RootRetired},
		{ID: "active", Type: typeR, Status: trust.RootActive},
	}
	chain := fallback.NewChain(specs)
	root, _, err := chain.Resolve(context.Background(), fallback.Operation{
		Kind:               fallback.OperationWrap,
		InteractiveAllowed: true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if root.ID() != "active" {
		t.Errorf("should skip retired, got %q", root.ID())
	}
}

func TestChain_AllUnavailable(t *testing.T) {
	const typeFail trust.RootType = "test_chain_fail"
	registerFailing(t, typeFail)

	specs := []trust.RootSpec{
		{ID: "f1", Type: typeFail, Status: trust.RootActive},
		{ID: "f2", Type: typeFail, Status: trust.RootActive},
	}
	chain := fallback.NewChain(specs)
	_, reason, err := chain.Resolve(context.Background(), fallback.Operation{
		Kind:               fallback.OperationWrap,
		InteractiveAllowed: true,
	})
	if !errors.Is(err, trust.ErrChainExhausted) {
		t.Errorf("want ErrChainExhausted, got %v", err)
	}
	if len(reason.Skipped) == 0 {
		t.Error("reason.Skipped should be non-empty")
	}
}

func TestChain_LLMSession_BlocksPresenceRequiring(t *testing.T) {
	// SE requires presence; should be skipped in LLM sessions.
	const seType trust.RootType = trust.RootSecureEnclave

	specs := []trust.RootSpec{
		{ID: "se1", Type: seType, Status: trust.RootActive},
	}
	chain := fallback.NewChain(specs)
	_, _, err := chain.Resolve(context.Background(), fallback.Operation{
		Kind:       fallback.OperationSign,
		LLMSession: true,
	})
	if !errors.Is(err, trust.ErrChainExhausted) {
		t.Errorf("LLM+SE: want ErrChainExhausted, got %v", err)
	}
}

func TestChain_HardwareOnly_NoPassphrase(t *testing.T) {
	// Hardware-only policy: passphrase root is available but must not be selected.
	const typePass trust.RootType = "test_chain_passphrase_hw"
	registerMock(t, typePass)

	specs := []trust.RootSpec{
		{ID: "pp1", Type: typePass, Status: trust.RootActive},
	}
	chain := fallback.NewChain(specs)

	// RequiredRootTypes = [RootSecureEnclave] but only passphrase is in specs.
	// passphrase must not be selected when hardware is required.
	_, _, err := chain.Resolve(context.Background(), fallback.Operation{
		Kind:               fallback.OperationWrap,
		InteractiveAllowed: true,
		RequiredRootTypes:  []trust.RootType{trust.RootSecureEnclave},
	})
	if !errors.Is(err, trust.ErrChainExhausted) {
		t.Errorf("hardware-only policy: want ErrChainExhausted, got %v", err)
	}
}

func TestChain_LaunchdUnsafe_Skipped(t *testing.T) {
	// FIDO2 requires user presence; not launchd-safe.
	const typeFIDO trust.RootType = "test_chain_fido_launchd"
	trust.Register(typeFIDO, func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		return &stubRoot{id: spec.ID, kind: typeFIDO, launchdSafe: false}, nil
	})
	t.Cleanup(func() { trust.Unregister(typeFIDO) })

	const typeVault trust.RootType = "test_chain_vault_launchd"
	trust.Register(typeVault, func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		return &stubRoot{id: spec.ID, kind: typeVault, launchdSafe: true}, nil
	})
	t.Cleanup(func() { trust.Unregister(typeVault) })

	specs := []trust.RootSpec{
		{ID: "fido1", Type: typeFIDO, Status: trust.RootActive},
		{ID: "vault1", Type: typeVault, Status: trust.RootActive},
	}
	chain := fallback.NewChain(specs)

	// InteractiveAllowed=false → FIDO2 (not launchd safe) should be skipped.
	// Vault (launchd safe) should be selected.
	root, _, err := chain.Resolve(context.Background(), fallback.Operation{
		Kind:               fallback.OperationWrap,
		InteractiveAllowed: false,
	})
	if err != nil {
		t.Fatalf("launchd mode: Resolve: %v", err)
	}
	if root.ID() != "vault1" {
		t.Errorf("launchd mode: want vault1, got %s", root.ID())
	}
}

func TestChain_ResolveAll_AllAvailable(t *testing.T) {
	const typeX trust.RootType = "test_resolveall_x"
	const typeY trust.RootType = "test_resolveall_y"
	registerMock(t, typeX)
	registerMock(t, typeY)

	specs := []trust.RootSpec{
		{ID: "x1", Type: typeX, Status: trust.RootActive},
		{ID: "y1", Type: typeY, Status: trust.RootActive},
	}
	chain := fallback.NewChain(specs)

	roots, _, err := chain.ResolveAll(context.Background(), fallback.Operation{
		RequireAllOfRootIDs: []string{"x1", "y1"},
		InteractiveAllowed:  true,
	})
	if err != nil {
		t.Fatalf("ResolveAll: %v", err)
	}
	if len(roots) != 2 {
		t.Errorf("ResolveAll: got %d roots, want 2", len(roots))
	}
}

func TestChain_ResolveAll_MissingOne(t *testing.T) {
	const typeX trust.RootType = "test_resolveall_missing_x"
	registerMock(t, typeX)

	specs := []trust.RootSpec{
		{ID: "x2", Type: typeX, Status: trust.RootActive},
		// "y2" is NOT in specs → should fail.
	}
	chain := fallback.NewChain(specs)

	_, _, err := chain.ResolveAll(context.Background(), fallback.Operation{
		RequireAllOfRootIDs: []string{"x2", "y2"},
	})
	if !errors.Is(err, trust.ErrChainExhausted) {
		t.Errorf("ResolveAll missing: want ErrChainExhausted, got %v", err)
	}
	// Error message should name the missing ID.
	if err != nil && !containsStr(err.Error(), "y2") {
		t.Errorf("error should mention missing ID 'y2', got: %v", err)
	}
}

// TestChain_ResolveAll_RequiredRootTypes_Enforced verifies that ResolveAll applies
// RequiredRootTypes per-entry (M-3): passphrase roots should be rejected when only
// secure_enclave is allowed.
func TestChain_ResolveAll_RequiredRootTypes_Enforced(t *testing.T) {
	const typePass trust.RootType = "test_resolveall_passphrase_rrt"
	registerMock(t, typePass)

	specs := []trust.RootSpec{
		{ID: "pp1", Type: typePass, Status: trust.RootActive},
	}
	chain := fallback.NewChain(specs)

	_, _, err := chain.ResolveAll(context.Background(), fallback.Operation{
		RequireAllOfRootIDs: []string{"pp1"},
		RequiredRootTypes:   []trust.RootType{trust.RootSecureEnclave},
		InteractiveAllowed:  true,
	})
	if !errors.Is(err, trust.ErrChainExhausted) {
		t.Errorf("ResolveAll with RequiredRootTypes=[SE] and only passphrase: want ErrChainExhausted, got %v", err)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

// --- stub implementation ---

type stubRoot struct {
	id          string
	kind        trust.RootType
	launchdSafe bool
}

func (s *stubRoot) ID() string           { return s.id }
func (s *stubRoot) Type() trust.RootType { return s.kind }
func (s *stubRoot) Has(c trust.Capability) bool {
	if c == trust.CapWrap {
		return true
	}
	if c == trust.CapLaunchdSafe {
		return s.launchdSafe
	}
	return false
}
func (s *stubRoot) Wrap(_ context.Context, _ []byte) ([]byte, error) {
	return []byte("wrapped"), nil
}
func (s *stubRoot) Unwrap(_ context.Context, _ []byte) ([]byte, error) {
	return []byte("dek"), nil
}
func (s *stubRoot) Sign(_ context.Context, _ []byte) ([]byte, crypto.PublicKey, error) {
	return nil, nil, trust.ErrCapabilityUnsupported
}
func (s *stubRoot) Verify(_ context.Context, _, _ []byte, _ crypto.PublicKey) error {
	return trust.ErrCapabilityUnsupported
}
func (s *stubRoot) RequirePresence(_ context.Context, _ string) (trust.PresenceProof, error) {
	return trust.PresenceProof{}, trust.ErrCapabilityUnsupported
}
func (s *stubRoot) VerifyPresenceProof(_ context.Context, _ trust.PresenceProof) error {
	return trust.ErrCapabilityUnsupported
}
func (s *stubRoot) Attest(_ context.Context) (trust.Attestation, error) {
	return trust.Attestation{}, trust.ErrCapabilityUnsupported
}
func (s *stubRoot) Close() error { return nil }
