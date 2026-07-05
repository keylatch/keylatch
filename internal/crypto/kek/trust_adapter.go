package kek

import (
	"context"
	"crypto"

	"github.com/keylatch/keylatch/internal/trust"
)

// kekRootAdapter wraps a KEK to implement the trust.RootOfTrust interface.
// It supports only CapWrap — all other capabilities return ErrCapabilityUnsupported.
//
// This shim is used to present legacy KEK backends as trust.RootOfTrust
// adapters for the fallback chain during the roots-of-trust migration.
type kekRootAdapter struct {
	k KEK
}

// AsRootOfTrust wraps a KEK as a trust.RootOfTrust adapter.
// The adapter only supports CapWrap; all cryptographic operations beyond
// Wrap/Unwrap return ErrCapabilityUnsupported.
func AsRootOfTrust(k KEK) trust.RootOfTrust {
	return &kekRootAdapter{k: k}
}

func (a *kekRootAdapter) ID() string { return a.k.ID() }

func (a *kekRootAdapter) Type() trust.RootType {
	switch a.k.Type() {
	case "passphrase":
		return trust.RootPassphrase
	case "keychain":
		return trust.RootKeychain
	case "op":
		return trust.RootOnePassword
	case "bw":
		return trust.RootBitwarden
	case "age-env":
		return trust.RootEncryptedFile
	default:
		return trust.RootType(a.k.Type())
	}
}

func (a *kekRootAdapter) Has(c trust.Capability) bool {
	return c == trust.CapWrap
}

// Wrap delegates to the underlying KEK and zeros dek before returning.
func (a *kekRootAdapter) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()
	return a.k.Wrap(dek)
}

// Unwrap delegates to the underlying KEK.
func (a *kekRootAdapter) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	return a.k.Unwrap(wrapped)
}

func (a *kekRootAdapter) Sign(_ context.Context, _ []byte) ([]byte, crypto.PublicKey, error) {
	return nil, nil, trust.ErrCapabilityUnsupported
}

func (a *kekRootAdapter) Verify(_ context.Context, _, _ []byte, _ crypto.PublicKey) error {
	return trust.ErrCapabilityUnsupported
}

func (a *kekRootAdapter) RequirePresence(_ context.Context, _ string) (trust.PresenceProof, error) {
	return trust.PresenceProof{}, trust.ErrCapabilityUnsupported
}

func (a *kekRootAdapter) VerifyPresenceProof(_ context.Context, _ trust.PresenceProof) error {
	return trust.ErrCapabilityUnsupported
}

func (a *kekRootAdapter) Attest(_ context.Context) (trust.Attestation, error) {
	return trust.Attestation{}, trust.ErrCapabilityUnsupported
}

func (a *kekRootAdapter) Close() error { return nil }
