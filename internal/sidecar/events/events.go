// Package events defines the value-free event types sent over the IPC channel
// from the keylatchd sidecar to the Tauri desktop shell.
//
// Security invariant: NEVER add fields that carry credential values,
// tokens, request bodies, or any other sensitive material. All fields must be
// value-free identifiers, counts, timestamps, or HMAC-derived labels.
//
// The CI lint (packaging/ci/lint-notification-fields.sh) rejects any field
// added here without a "// security-reviewed: <date>" inline comment.
package events

import "time"

// EventType identifies the category of a desktop event.
type EventType string

const (
	EventTypeApproval EventType = "approval"
	EventTypeReceipt  EventType = "receipt"
	EventTypeSecurity EventType = "security"
)

// Event is the union type carried on the Mux fan-out channel.
// Exactly one of the payload fields is non-nil per event.
type Event struct {
	Type     EventType      `cbor:"type"`
	Approval *ApprovalEvent `cbor:"approval,omitempty"`
	Receipt  *ReceiptEvent  `cbor:"receipt,omitempty"`
	Security *SecurityEvent `cbor:"security,omitempty"`
}

// ApprovalEvent carries a pending-approval notification.
// Fields: spec §3.7 — value-free; no credential data.
//
// NEVER add fields that carry credentials. (security-reviewed: 2026-05-14)
type ApprovalEvent struct {
	// ApprovalID is the unique identifier for this approval request. // security-reviewed: 2026-05-14
	ApprovalID string `cbor:"approval_id"`
	// Provider is the backend provider name (e.g. "github"). // security-reviewed: 2026-05-14
	Provider string `cbor:"provider"`
	// Action is the operation being approved (e.g. "read:repo"). // security-reviewed: 2026-05-14
	Action string `cbor:"action"`
	// Actor is the entity requesting approval (e.g. tool name). // security-reviewed: 2026-05-14
	Actor string `cbor:"actor"`
	// RequestedAt is when the approval request was created. // security-reviewed: 2026-05-14
	RequestedAt time.Time `cbor:"requested_at"`
	// ExpiresAt is when the approval request expires. // security-reviewed: 2026-05-14
	ExpiresAt time.Time `cbor:"expires_at"`
	// DeepLinkPath is the keylatch:// path for this approval's detail view. // security-reviewed: 2026-05-14
	DeepLinkPath string `cbor:"deep_link_path"`
}

// ReceiptEvent carries a receipt for a completed gateway operation.
// Fields: spec §3.8 — value-free; no raw credential body.
//
// NEVER add fields that carry credentials. (security-reviewed: 2026-05-14)
type ReceiptEvent struct {
	// ReceiptID is the unique identifier for this receipt. // security-reviewed: 2026-05-14
	ReceiptID string `cbor:"receipt_id"`
	// Actor is the entity that performed the operation. // security-reviewed: 2026-05-14
	Actor string `cbor:"actor"`
	// Provider is the backend provider used. // security-reviewed: 2026-05-14
	Provider string `cbor:"provider"`
	// Action is the operation performed. // security-reviewed: 2026-05-14
	Action string `cbor:"action"`
	// Runtime is the execution environment (e.g. "claude-code"). // security-reviewed: 2026-05-14
	Runtime string `cbor:"runtime"`
	// CredentialShape describes the token type without the value (e.g. "bearer-40"). // security-reviewed: 2026-05-14
	CredentialShape string `cbor:"credential_shape"`
	// PolicyDecision is "allow" or "deny". // security-reviewed: 2026-05-14
	PolicyDecision string `cbor:"policy_decision"`
	// TokenTTLLeft is remaining seconds on the credential TTL (a count, not a value). // security-reviewed: 2026-05-14
	TokenTTLLeft int64 `cbor:"token_ttl_left"`
	// StatusGroup is the HTTP response status group (e.g. "2xx"). // security-reviewed: 2026-05-14
	StatusGroup string `cbor:"status_group"`
	// DurationMS is the request round-trip time in milliseconds. // security-reviewed: 2026-05-14
	DurationMS int64 `cbor:"duration_ms"`
	// DeepLinkPath is the keylatch:// path for this receipt's detail view. // security-reviewed: 2026-05-14
	DeepLinkPath string `cbor:"deep_link_path"`
	// NoSecretsProof is a cryptographic proof that no secrets appear in the receipt. // security-reviewed: 2026-05-14
	NoSecretsProof string `cbor:"no_secrets_proof"`
}

// SecurityEvent carries a security-relevant alert.
//
// NEVER add fields that carry credentials. (security-reviewed: 2026-05-14)
type SecurityEvent struct {
	// EventID is a unique identifier for this security event. // security-reviewed: 2026-05-14
	EventID string `cbor:"event_id"`
	// Severity is "warning", "error", or "critical". // security-reviewed: 2026-05-14
	Severity string `cbor:"severity"`
	// Kind is the event category (e.g. "hmac_mismatch", "hash_drift"). // security-reviewed: 2026-05-14
	Kind string `cbor:"kind"`
	// Timestamp is when the event was detected. // security-reviewed: 2026-05-14
	Timestamp time.Time `cbor:"timestamp"`
	// AuditRef is the audit log entry ID for correlation. // security-reviewed: 2026-05-14
	AuditRef string `cbor:"audit_ref"`
}
