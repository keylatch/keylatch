// Package meta defines the pure, value-free domain model for Phase 4 metadata.
// This package has zero dependencies on backend, CLI, or IO. It owns the
// canonical Meta struct, VersionMeta, DeliveryRecord, AADBinding, and ID.
package meta

import "time"

// CurrentSchemaVersion is the schema version written to all new Meta records.
// Bumped to 2 in v1.0.0: fingerprint_sha256 field removed from reference records.
// Records with schema_version < 2 are rejected with ErrUnsupportedFormat.
const CurrentSchemaVersion = 2

// MinSupportedSchemaVersion is the oldest schema_version this binary will accept.
// Records with schema_version < MinSupportedSchemaVersion return ErrUnsupportedFormat.
const MinSupportedSchemaVersion = 2

// DefaultMaxVersions is the number of versions retained before the oldest is
// soft-deleted on the next RotateValue call.
const DefaultMaxVersions = 5

// MaxDeliveryRecords is the maximum number of delivery records retained per
// VersionMeta. Oldest entries are evicted (FIFO) when the cap is exceeded.
const MaxDeliveryRecords = 16

// ID is an opaque per-path accessor token. Generated on first write; stable
// across reads and versions. Audit logs reference it (HMAC'd in Phase 5).
type ID string

// String returns the string representation of the ID.
func (id ID) String() string { return string(id) }

// IsZero reports whether the ID is unset (empty string).
func (id ID) IsZero() bool { return id == "" }

// AADBinding holds the AEAD associated-data context that binds a ciphertext to
// its metadata at encryption time. Every VersionMeta carries one AADBinding.
// Spec §3: all field names are canonical identifiers; do not rename JSON tags.
type AADBinding struct {
	SchemaVersion int       `json:"schema_version"`
	Namespace     string    `json:"namespace"`
	Path          string    `json:"path"`
	Version       int       `json:"version"`
	KeyTerm       int       `json:"key_term"`   // Phase 5 wires; 0 in Phase 4
	BackendID     string    `json:"backend_id"` // backend.ID() result
	CreatedAt     time.Time `json:"created_at"`
	Algorithm     string    `json:"algorithm"` // e.g. "xchacha20-poly1305"
}

// DeliveryRecord captures a single runtime delivery event for audit purposes.
// Phase 4 stores up to MaxDeliveryRecords per version (FIFO cap).
type DeliveryRecord struct {
	DeliveredAt     time.Time `json:"delivered_at"`
	RuntimeMode     string    `json:"runtime_mode"`
	CredentialShape string    `json:"credential_shape"`
	ReceiptID       string    `json:"receipt_id"`
	TokenAccessor   string    `json:"token_accessor"`
	SandboxProfile  string    `json:"sandbox_profile"`
	ProxyProfile    string    `json:"proxy_profile"`
}

// VersionMeta holds per-version metadata. Capped LastDeliveries slice at
// MaxDeliveryRecords; use AppendDelivery to add entries.
type VersionMeta struct {
	Version        int              `json:"version"`
	CreatedAt      time.Time        `json:"created_at"`
	CreatedBy      string           `json:"created_by,omitempty"`
	ExpiresAt      *time.Time       `json:"expires_at,omitempty"`
	DeletedAt      *time.Time       `json:"deleted_at,omitempty"`
	DestroyedAt    *time.Time       `json:"destroyed_at,omitempty"`
	AAD            AADBinding       `json:"aad"`
	LastDeliveries []DeliveryRecord `json:"last_deliveries,omitempty"`
}

// Meta is the value-free metadata record for a canonical secret path.
// It is stored separately from the encrypted value blobs so that listing,
// expiry checks, and version queries never touch plaintext.
type Meta struct {
	SchemaVersion     int               `json:"schema_version"`
	Path              string            `json:"path"`
	Accessor          ID                `json:"accessor"`
	Backend           string            `json:"backend,omitempty"`
	CurrentVersion    int               `json:"current_version"`
	OldestVersion     int               `json:"oldest_version"`
	MaxVersions       int               `json:"max_versions"`
	DestroyedVersions []int             `json:"destroyed_versions,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	IssuedAt          *time.Time        `json:"issued_at,omitempty"`
	ExpiresAt         *time.Time        `json:"expires_at,omitempty"`
	RotationHint      string            `json:"rotation_hint,omitempty"`
	Owner             string            `json:"owner,omitempty"`
	Scope             string            `json:"scope,omitempty"`
	Purpose           string            `json:"purpose,omitempty"`
	SafeFields        []string          `json:"safe_fields,omitempty"`
	Custom            map[string]string `json:"custom,omitempty"`
	Versions          []VersionMeta     `json:"versions,omitempty"`
	TeamID            string            `json:"team_id,omitempty"`
	SharedRecipients  []string          `json:"shared_recipients,omitempty"`
}
