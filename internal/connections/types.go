// Package connections implements the full connection lifecycle: create, test,
// health-status, describe, and delete. It sits between the registry (templates)
// and the vault (storage) and is consumed by every CLI command that touches
// provider state.
package connections

import (
	"errors"
	"time"

	"github.com/keylatch/keylatch/internal/registry"
)

// ConnectOptions carries parameters for creating a connection.
type ConnectOptions struct {
	// Namespace is the vault namespace (e.g. "default").
	Namespace string
	// Account is the account name for multi-account providers.
	Account string
	// Mode is the RuntimeMode to store on the connection.
	Mode registry.RuntimeMode
	// NonInteractive skips interactive prompts; returns error if required fields are missing.
	NonInteractive bool
	// Fields are pre-supplied field values (field_name -> value).
	Fields map[string][]byte
}

// Connection represents a stored provider connection.
type Connection struct {
	Provider   string               `json:"provider"`
	Account    string               `json:"account"`
	Namespace  string               `json:"namespace"`
	Runtime    registry.RuntimeMode `json:"runtime"`
	CreatedAt  time.Time            `json:"created_at"`
	UpdatedAt  time.Time            `json:"updated_at"`
	Fields     []string             `json:"fields"` // field names only — no values
	Status     string               `json:"status"` // "untested" | "connected" | "missing" | "invalid" | ...
	LastTested *time.Time           `json:"last_tested,omitempty"`
}

// TestResult carries the outcome of a connection health test.
// S3-9: this struct MUST NOT include free-form upstream error text — status enum only.
type TestResult struct {
	// Status is one of the fixed enum values below.
	Status     string `json:"status"` // connected|missing|invalid|insufficient_scope|rate_limited|network_error
	StatusCode int    `json:"status_code,omitempty"`
	Duration   string `json:"duration,omitempty"`
	Provider   string `json:"provider"`
	Connection string `json:"connection,omitempty"`
	// Markers are allowed-listed body substrings found in the response.
	// Token-shaped substrings are stripped before inclusion (S3-9).
	Markers []string `json:"markers,omitempty"`
}

// Test status enum values.
const (
	TestStatusConnected         = "connected"
	TestStatusMissing           = "missing"
	TestStatusInvalid           = "invalid"
	TestStatusInsufficientScope = "insufficient_scope"
	TestStatusRateLimited       = "rate_limited"
	TestStatusNetworkError      = "network_error"
)

// StatusOptions controls the behaviour of Status().
type StatusOptions struct {
	Namespace string
	JSON      bool
	Test      bool // if true, run a health test for each connection
}

// ConnectionStatus is the output of Status() for a single connection.
type ConnectionStatus struct {
	Connection       Connection `json:"connection"`
	GatewaySupported bool       `json:"gateway_supported"`
	Capabilities     []string   `json:"capabilities"` // names only — no values
}

// Typed errors for connection operations.
var (
	// ErrAmbiguous is returned when a multi-account provider has an existing
	// connection but Account was not specified.
	ErrAmbiguous = errors.New("connections: ambiguous — multiple accounts exist; specify --account")

	// ErrConnectionNotFound is returned when a named connection is not in the vault.
	ErrConnectionNotFound = errors.New("connections: connection not found")

	// ErrProviderNotFound is returned when the provider slug is not in the registry.
	ErrProviderNotFound = errors.New("connections: provider not found")

	// ErrConnectionExists is returned when a connection for this provider+namespace+account
	// already exists and the caller did not request an update.
	ErrConnectionExists = errors.New("connections: connection already exists")
)
