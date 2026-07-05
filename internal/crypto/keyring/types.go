// Package keyring manages the keyring file that stores wrapped DEKs and
// the AES-GCM nonce counter state.
package keyring

import (
	"errors"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/trust"
)

// SchemaVersion is the keyring file schema version this package writes.
// Bumped to 2 to accommodate the Roots and ApprovalChain fields.
const SchemaVersion = 2

// TermStatus represents the lifecycle state of a DEK term.
type TermStatus string

const (
	// TermActive is the current write term. Exactly one term per keyring file.
	TermActive TermStatus = "active"

	// TermRotating is reserved for future use during atomic term rotation.
	// When a full background re-encryption pass is implemented, RotateTerm will
	// set the retiring term to TermRotating until all values are re-encrypted,
	// then transition it to TermRetired.
	TermRotating TermStatus = "rotating"

	// TermRetired means the term's DEK is still available for reads but no
	// new values should be written under it.
	TermRetired TermStatus = "retired"

	// TermDestroyed means the wrapped DEK has been deleted. Values encrypted
	// under this term are permanently unreadable.
	TermDestroyed TermStatus = "destroyed"
)

// TermRecord holds a single DEK term in the keyring file.
type TermRecord struct {
	// Term is the monotonically increasing term number (starts at 1).
	Term int `json:"term"`

	// Status is the lifecycle state of this term.
	Status TermStatus `json:"status"`

	// WrappedDEK is the DEK encrypted under the keyring's KEK.
	// Empty for TermDestroyed terms.
	WrappedDEK []byte `json:"wrapped_dek,omitempty"`

	// CreatedAt is the RFC3339 timestamp when this term was created.
	CreatedAt string `json:"created_at"`

	// KEKType records the type of KEK that wrapped this term's DEK.
	// Used for audit and forward-compat validation.
	KEKType string `json:"kek_type,omitempty"`
}

// GCMState tracks the monotonic nonce counter for AES-256-GCM encryption.
// Shared across all process instances via the keyring file.
type GCMState struct {
	// PerTerm maps term number to the current nonce counter value.
	// Counter starts at 0 and increments monotonically.
	PerTerm map[int]uint64 `json:"per_term"`

	// LeaseSize controls durable-lease optimization. When > 0, a process
	// pre-allocates a batch of nonces in a single fsync. 0 means strict
	// single-nonce mode (one fsync per encryption).
	LeaseSize uint64 `json:"lease_size"`
}

// Argon2Params stores the Argon2id parameters used for passphrase-based KEKs.
// Required for re-deriving the wrapping key during Unwrap.
type Argon2Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	Salt    []byte `json:"salt"` // base64 in JSON
	KeyLen  uint32 `json:"key_len"`
}

// RootOfTrustRecord associates a trust.RootSpec with the DEKs it has wrapped.
// Added when SchemaVersion=2.
type RootOfTrustRecord struct {
	// Spec is the persisted root-of-trust specification.
	Spec trust.RootSpec `json:"spec"`

	// WrappedDEKs maps term number → base64-encoded wrapped DEK bytes.
	// Each entry was produced by trust.RootOfTrust.Wrap.
	WrappedDEKs map[int]string `json:"wrapped_deks,omitempty"`
}

// KeyringFile is the on-disk JSON structure. It is written with mode 0o600.
//
// Schema §3.3: all field names are canonical; do not rename JSON tags.
type KeyringFile struct {
	// SchemaVersion must equal keyring.SchemaVersion (2 from the roots-of-trust upgrade onward).
	SchemaVersion int `json:"schema_version"`

	// Algorithm is the AEAD algorithm used for vault data encryption.
	// Wrapping (KEK→DEK) always uses XChaCha20-Poly1305 regardless of this field.
	Algorithm envelope.Algorithm `json:"algorithm"`

	// ActiveTerm is the term number currently used for new writes.
	ActiveTerm int `json:"active_term"`

	// Roots holds the root-of-trust records. Replaces legacy KEK fields
	// when non-empty. Each root can independently wrap/unwrap every DEK term.
	Roots []RootOfTrustRecord `json:"roots,omitempty"`

	// ApprovalChain is an ordered list of root spec IDs that form the approval chain
	// for two-person operations. Set by trust enroll and updated by trust revoke.
	ApprovalChain []string `json:"approval_chain,omitempty"`

	// --- Legacy fields (backward compat). ---
	// Retained as omitempty; present only in legacy keyrings or during migration.

	// KEKType identifies the KEK provider type for this keyring (legacy).
	KEKType string `json:"kek_type,omitempty"`

	// Salt is a 32-byte random value used by HKDF-based KEKs (age-env).
	// Also used as the HMAC salt for audit log derivation.
	Salt []byte `json:"salt,omitempty"`

	// Argon2 stores passphrase KDF parameters (only set for passphrase KEK).
	Argon2 *Argon2Params `json:"argon2,omitempty"`

	// KEKID is the legacy opaque KEK identifier (replaced by RootSpec.ID).
	KEKID string `json:"kek_id,omitempty"`

	// Terms holds all term records in ascending term order.
	Terms []TermRecord `json:"terms"`

	// GCMState tracks nonce counter state (only used for AES-256-GCM algorithm).
	GCMState *GCMState `json:"gcm_state,omitempty"`

	// Extra holds unknown fields for forward-compat JSON round-trip.
	// Keys prefixed with "x_" are reserved for future use.
	Extra map[string]any `json:"extra,omitempty"`
}

// Keyring sentinel errors.
var (
	ErrKeyringCorrupt          = errors.New("keyring: file corrupt or unreadable")
	ErrKeyringNotFound         = errors.New("keyring: file not found")
	ErrKeyTermNotFound         = errors.New("keyring: key term not found")
	ErrKeyTermDestroyed        = errors.New("keyring: key term has been destroyed")
	ErrKeyTermExhausted        = errors.New("keyring: key term nonce counter exhausted")
	ErrNonceCounterFlushFailed = errors.New("keyring: nonce counter flush failed")

	// ErrKEKMismatch is returned when Open cannot unwrap any term with the
	// provided KEK. Defined in the kek package but re-exported here for convenience.
	ErrKEKMismatch = errors.New("keyring: no term decryptable with this KEK")
)
