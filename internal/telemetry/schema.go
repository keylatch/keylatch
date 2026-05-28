package telemetry

import "time"

// NOTE: These structs define the intended v1 wire schema.
// Current production emission via metrics.go uses a flat Event{Name,Fields} approach.
// Migration to typed emission is tracked in future cleanup work.
// Until migrated, this file is aspirational documentation, not production code.

// BaseEvent carries the common envelope present on every telemetry event.
// All fields are non-sensitive: no credentials, paths, or user-supplied strings.
type BaseEvent struct {
	EventType string    `json:"event_type"`
	InstallID string    `json:"install_id"`
	Version   string    `json:"version"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	Timestamp time.Time `json:"timestamp"`
}

// CLIInvokedEvent is emitted once per CLI invocation, after the command exits.
// Command and Subcommand are the literal cobra command names — never user arguments.
type CLIInvokedEvent struct {
	BaseEvent
	Command    string `json:"command"`
	Subcommand string `json:"subcommand"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
}

// GatewayStartedEvent is emitted when the keylatch gateway daemon starts.
// Provider is the provider name; Runtime is "local" | "docker" | "hosted".
type GatewayStartedEvent struct {
	BaseEvent
	Provider string `json:"provider"`
	Runtime  string `json:"runtime"`
}

// ConnectionEnrolledEvent is emitted when a new connection is enrolled.
// StorageMode is "direct" (credential stored locally) or "reference" (external store).
type ConnectionEnrolledEvent struct {
	BaseEvent
	Provider    string `json:"provider"`
	StorageMode string `json:"storage_mode"` // "direct" or "reference"
}

// DoctorRunEvent is emitted after keylatch doctor completes.
// FailedCheckNames contains the names of failed checks (never user-supplied values).
type DoctorRunEvent struct {
	BaseEvent
	Category         string   `json:"category"`
	Result           string   `json:"result"` // "ok" | "warn" | "fail" | "skip"
	FailedCheckNames []string `json:"failed_check_names,omitempty"`
}
