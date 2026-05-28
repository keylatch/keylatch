package trust

// RootStatus represents the lifecycle state of a registered root of trust.
type RootStatus string

const (
	// RootActive means the root is in normal use for wrap/unwrap/sign operations.
	RootActive RootStatus = "active"

	// RootRetired means the root is no longer used for new operations but its
	// wrapped DEKs remain accessible for unwrap (read-only legacy access).
	RootRetired RootStatus = "retired"

	// RootRevoked means the root has been compromised or explicitly revoked.
	// All operations MUST return ErrRootRevoked.
	RootRevoked RootStatus = "revoked"
)

// RootSpec is the persisted configuration record for a root-of-trust instance.
// It is stored in the keyring file under KeyringFile.Roots.
//
// Security: the ID field is opaque. Callers MUST HMAC the ID before logging
// or including it in JWT claims (S11-3).
type RootSpec struct {
	// ID is the stable opaque identifier for this root instance.
	ID string `json:"id"`

	// Type identifies the backend provider.
	Type RootType `json:"type"`

	// Status is the lifecycle state of this root.
	Status RootStatus `json:"status"`

	// Label is a human-readable name for display purposes only (value-free).
	Label string `json:"label,omitempty"`

	// AgePublicKey is the AGE public key derived for this root (FIND2-001).
	// Format: "age1..." for X25519 or "age1ssh-ed25519..." for SSH.
	// Empty when the root does not support AGE key derivation.
	AgePublicKey string `json:"age_public_key,omitempty"`

	// AgeKeyDerivation describes the derivation method used to produce AgePublicKey.
	// Examples: "hkdf-secure-enclave-ecies-v1", "age-plugin-ssh", "hkdf-pkcs11-hmac-v1".
	AgeKeyDerivation string `json:"age_key_derivation,omitempty"`

	// Extra holds provider-specific configuration fields. Keys prefixed "x_" are reserved.
	// Must never contain key material or passphrases.
	Extra map[string]any `json:"extra,omitempty"`
}
