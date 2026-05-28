// Package trust defines the Root of Trust interface, capability flags, and sentinel
// errors for the Phase 11 pluggable hardware security module layer.
//
// Security invariants:
//   - S11-1: RootOfTrust.Wrap/Unwrap MUST zero plaintext DEK bytes before return.
//   - S11-2: Sign, RequirePresence, and Attest MUST return ErrLLMSessionBlocked in LLM sessions.
//   - S11-3: Root spec IDs are ALWAYS HMAC'd before appearing in audit events or JWT claims.
//   - S11-4: ErrModuleNotAllowlisted MUST be returned before any PKCS#11 session is opened.
package trust

import (
	"context"
	"crypto"
	"errors"
	"time"
)

// RootType identifies the kind of root-of-trust backend.
type RootType string

const (
	RootPassphrase    RootType = "passphrase"
	RootKeychain      RootType = "keychain"
	RootOnePassword   RootType = "op"
	RootBitwarden     RootType = "bw"
	RootEncryptedFile RootType = "encrypted_file"
	RootSecureEnclave RootType = "secure_enclave"
	RootSSHAgent      RootType = "ssh_agent"
	RootPKCS11        RootType = "pkcs11"
	RootGPGCard       RootType = "gpg_card"
	RootFIDO2         RootType = "fido2"
	RootVaultTransit  RootType = "vault_transit"
)

// Capability is a bitmask flag describing what a RootOfTrust implementation supports.
type Capability int

const (
	// CapWrap indicates the root can wrap and unwrap DEK bytes.
	CapWrap Capability = 1 << iota
	// CapSignChallenge indicates the root can sign arbitrary challenge bytes.
	CapSignChallenge
	// CapUserPresence indicates the root requires physical user presence (touch/biometric).
	CapUserPresence
	// CapHardwareBound indicates the key material is hardware-bound and non-exportable.
	CapHardwareBound
	// CapLaunchdSafe indicates the root is safe for non-interactive (launchd/daemon) use.
	CapLaunchdSafe
	// CapAttestation indicates the root can produce a hardware attestation statement.
	CapAttestation
	// CapMTLSClientAuth indicates the root can serve as an mTLS client certificate.
	CapMTLSClientAuth
	// capReserved is reserved for future use.
	capReserved //nolint:unused // reserved iota slot for future capability flag
)

// PresenceProof is a signed record that a human was physically present.
// All fields are JSON-tagged. BindingHMAC is HMAC'd under the root's wrapping key.
type PresenceProof struct {
	Method      string    `json:"method"`
	ConfirmedAt time.Time `json:"confirmed_at"`
	RootID      string    `json:"root_id"`      // HMAC'd root spec ID per S11-3
	BindingHMAC string    `json:"binding_hmac"` // HMAC of canonical binding bytes
}

// Attestation is a hardware attestation statement from a root-of-trust device.
type Attestation struct {
	Format       string   `json:"format"`
	Statement    []byte   `json:"statement"`
	Certificates [][]byte `json:"certificates,omitempty"`
	AAGUID       string   `json:"aaguid,omitempty"`
}

// RootOfTrust is the unified interface for all root-of-trust backends.
// Implementations MUST be safe for concurrent use from multiple goroutines.
type RootOfTrust interface {
	// ID returns the stable, opaque root spec ID. NEVER expose raw in audit/JWT — HMAC first.
	ID() string

	// Type returns the RootType for this backend.
	Type() RootType

	// Has returns true if this root supports the given capability.
	Has(Capability) bool

	// Wrap encrypts dek under this root. Implementations MUST zero dek before returning.
	Wrap(ctx context.Context, dek []byte) ([]byte, error)

	// Unwrap decrypts wrapped to recover the original DEK bytes.
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)

	// Sign signs challenge and returns (signature, public key, error).
	// MUST return ErrCapabilityUnsupported if !Has(CapSignChallenge).
	Sign(ctx context.Context, challenge []byte) (sig []byte, pub crypto.PublicKey, err error)

	// Verify verifies sig over challenge using pub.
	Verify(ctx context.Context, challenge, sig []byte, pub crypto.PublicKey) error

	// RequirePresence obtains a user-presence confirmation for reason.
	// MUST return ErrLLMSessionBlocked if called in an LLM session.
	// MUST return ErrCapabilityUnsupported if !Has(CapUserPresence).
	RequirePresence(ctx context.Context, reason string) (PresenceProof, error)

	// VerifyPresenceProof cryptographically verifies a previously obtained PresenceProof.
	VerifyPresenceProof(ctx context.Context, p PresenceProof) error

	// Attest produces a hardware attestation statement.
	// MUST return ErrCapabilityUnsupported if !Has(CapAttestation).
	Attest(ctx context.Context) (Attestation, error)

	// Close releases any resources held by this root (sessions, file handles, etc.).
	// Safe to call multiple times.
	Close() error
}

// ErrPresenceProofStale is returned when a PresenceProof is older than MaxAgeSec.
var ErrPresenceProofStale = errors.New("trust: presence proof stale")

// ErrPresenceProofInvalid is returned when a PresenceProof fails structural validation.
var ErrPresenceProofInvalid = errors.New("trust: presence proof invalid")

// VerifyPresenceProofAge checks that p.ConfirmedAt is within maxAgeSec seconds of now.
// If maxAgeSec <= 0, no age check is performed.
// Returns ErrPresenceProofStale if the proof is too old.
// Returns ErrPresenceProofInvalid if p.ConfirmedAt is zero.
func VerifyPresenceProofAge(p PresenceProof, maxAgeSec int) error {
	if p.ConfirmedAt.IsZero() {
		return ErrPresenceProofInvalid
	}
	if maxAgeSec <= 0 {
		return nil
	}
	age := time.Since(p.ConfirmedAt)
	if age < 0 {
		age = -age // handle clock skew: negative age treated as zero
	}
	if age > time.Duration(maxAgeSec)*time.Second {
		return ErrPresenceProofStale
	}
	return nil
}

// Sentinel errors for the trust package.
var (
	// ErrCapabilityUnsupported is returned when an operation requires a capability
	// the root does not have.
	ErrCapabilityUnsupported = errors.New("trust: capability unsupported")

	// ErrRootUnavailable is returned when the root backend is not reachable or
	// not configured on this system.
	ErrRootUnavailable = errors.New("trust: root unavailable")

	// ErrRootRevoked is returned when the root has been revoked and must not be used.
	ErrRootRevoked = errors.New("trust: root revoked")

	// ErrRootExpired is returned when the root's validity period has elapsed.
	ErrRootExpired = errors.New("trust: root expired")

	// ErrTokenExpired is returned when a challenge or approval token has expired.
	ErrTokenExpired = errors.New("trust: token expired")

	// ErrTokenAlreadyUsed is returned when a single-use token has already been consumed.
	ErrTokenAlreadyUsed = errors.New("trust: token already used")

	// ErrCSRFMismatch is returned when the CSRF binding check fails.
	ErrCSRFMismatch = errors.New("trust: csrf mismatch")

	// ErrChainExhausted is returned by Chain.Resolve when no root can satisfy the operation.
	ErrChainExhausted = errors.New("trust: fallback chain exhausted")

	// ErrModuleNotAllowlisted is returned when a PKCS#11 module path is not in the allowlist.
	ErrModuleNotAllowlisted = errors.New("trust: pkcs11 module not allowlisted")

	// ErrModuleHashMismatch is returned when the on-disk PKCS#11 module hash does not match
	// the expected hash in the allowlist entry.
	ErrModuleHashMismatch = errors.New("trust: pkcs11 module hash mismatch")

	// ErrModuleHashUnpinned is returned when a PKCS#11 module allowlist entry has no
	// SHA-256 hash configured. The module is still loaded but the caller should warn.
	ErrModuleHashUnpinned = errors.New("trust: pkcs11 module hash not pinned")

	// ErrAttestationInvalid is returned when an attestation statement fails verification.
	ErrAttestationInvalid = errors.New("trust: attestation invalid")

	// ErrLLMSessionBlocked is returned when an operation that requires physical human
	// presence is attempted from within an LLM session.
	ErrLLMSessionBlocked = errors.New("trust: operation blocked in LLM session")
)
