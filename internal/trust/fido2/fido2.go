// Package fido2 implements a trust.RootOfTrust adapter backed by a FIDO2/WebAuthn token.
// Integration tests require a real FIDO2 device and are gated by KEYLATCH_E2E_FIDO2=1.
//
// The package compiles without any native library dependency by using a stub implementation
// that returns ErrRootUnavailable for all hardware operations.
package fido2

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/trust"
)

// EnrollOptions configures a FIDO2 enrolment ceremony.
type EnrollOptions struct {
	// DevicePath is the path to the FIDO2 device (e.g. /dev/hidraw0).
	DevicePath string
	// RPID is the relying-party ID (default "keylatch://local").
	RPID string
	// Label is a human-readable name for this root.
	Label string
}

// Adapter implements trust.RootOfTrust using a FIDO2 token.
type Adapter struct {
	opts     EnrollOptions
	id       string
	credID   []byte   //nolint:unused // planned: used by FIDO2 assertion in Phase 11 hardware integration
	hmacSalt [32]byte //nolint:unused // planned: used by HMAC-secret extension in Phase 11 FIDO2 operations
	// HMACFunc computes an HMAC of its argument under the keyring's HMAC key.
	// When non-nil, it is used to HMAC the raw adapter ID before embedding it
	// in PresenceProof.RootID (S11-3: root IDs must be HMAC'd at emission).
	HMACFunc func([]byte) []byte
}

// Enroll performs a FIDO2 registration ceremony and returns a new Adapter and RootSpec.
// Requires physical user presence (touch). Blocked in LLM sessions.
func Enroll(ctx context.Context, opts EnrollOptions) (*Adapter, trust.RootSpec, error) {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return nil, trust.RootSpec{}, trust.ErrLLMSessionBlocked
	}

	// Stub: in production this calls go-libfido2 MakeCredential.
	return nil, trust.RootSpec{}, fmt.Errorf("%w: FIDO2 enrolment requires hardware (set KEYLATCH_E2E_FIDO2=1 for integration tests)", trust.ErrRootUnavailable)
}

// New returns a FIDO2 Adapter from a persisted RootSpec.
// The spec.Extra["cred_id"] field must be set (base64-encoded credential ID).
func New(spec trust.RootSpec) (*Adapter, error) {
	id := spec.ID
	if id == "" {
		id = "fido2-unknown"
	}
	return &Adapter{
		opts: EnrollOptions{Label: spec.Label},
		id:   id,
	}, nil
}

func (a *Adapter) ID() string           { return a.id }
func (a *Adapter) Type() trust.RootType { return trust.RootFIDO2 }

func (a *Adapter) Has(c trust.Capability) bool {
	switch c {
	case trust.CapWrap, trust.CapSignChallenge, trust.CapUserPresence, trust.CapHardwareBound, trust.CapAttestation:
		return true
	case trust.CapLaunchdSafe:
		return false // FIDO2 requires user presence
	default:
		return false
	}
}

// Wrap derives a 32-byte KEK from the FIDO2 hmac-secret assertion and AES-256-GCM
// encrypts dek. Requires physical user presence.
func (a *Adapter) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return nil, trust.ErrLLMSessionBlocked
	}
	defer zeroBytes(dek)

	kek, err := a.deriveKEK(ctx)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(kek)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("fido2: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("fido2: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("fido2: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, dek, nil), nil
}

// Unwrap decrypts a blob produced by Wrap. Requires physical user presence.
func (a *Adapter) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return nil, trust.ErrLLMSessionBlocked
	}

	kek, err := a.deriveKEK(ctx)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(kek)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("fido2: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("fido2: gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(wrapped) < ns {
		return nil, trust.ErrRootUnavailable
	}
	return gcm.Open(nil, wrapped[:ns], wrapped[ns:], nil)
}

// deriveKEK calls the FIDO2 assertion hmac-secret to derive a 32-byte wrapping key.
// Stub: returns ErrRootUnavailable.
func (a *Adapter) deriveKEK(_ context.Context) ([]byte, error) {
	return nil, fmt.Errorf("%w: FIDO2 assertion requires hardware", trust.ErrRootUnavailable)
}

// Sign creates a FIDO2 assertion and returns the signature bytes.
func (a *Adapter) Sign(ctx context.Context, challenge []byte) ([]byte, crypto.PublicKey, error) {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return nil, nil, trust.ErrLLMSessionBlocked
	}
	_ = challenge
	return nil, nil, fmt.Errorf("%w: FIDO2 assertion requires hardware", trust.ErrRootUnavailable)
}

func (a *Adapter) Verify(_ context.Context, _, _ []byte, _ crypto.PublicKey) error {
	return fmt.Errorf("%w: FIDO2 verify requires hardware", trust.ErrRootUnavailable)
}

// RequirePresence creates a FIDO2 assertion requiring user presence.
func (a *Adapter) RequirePresence(ctx context.Context, reason string) (trust.PresenceProof, error) {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return trust.PresenceProof{}, trust.ErrLLMSessionBlocked
	}
	_, _, err := a.Sign(ctx, []byte(reason))
	if err != nil {
		// Mi-6: always return empty proof on any error — never return non-empty proof with error.
		return trust.PresenceProof{}, err
	}
	// S11-3: HMAC the root ID at emission.
	rootID := a.id
	if a.HMACFunc != nil {
		rootID = base64.RawURLEncoding.EncodeToString(a.HMACFunc([]byte(a.id)))
	}
	return trust.PresenceProof{
		Method:      "fido2-assertion",
		ConfirmedAt: time.Now().UTC(),
		RootID:      rootID,
	}, nil
}

func (a *Adapter) VerifyPresenceProof(_ context.Context, p trust.PresenceProof) error {
	if p.RootID == "" || p.ConfirmedAt.IsZero() {
		return errors.New("fido2: invalid presence proof")
	}
	return nil
}

func (a *Adapter) Attest(_ context.Context) (trust.Attestation, error) {
	return trust.Attestation{Format: "packed"}, nil
}

func (a *Adapter) Close() error { return nil }

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func init() {
	trust.Register(trust.RootFIDO2, func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		return New(spec)
	})
}
