// Package share sanitizes run receipts before public sharing.
package share

import "github.com/keylatch/keylatch/internal/runner"

// SanitizedReceipt contains only non-sensitive metadata from a RuntimeReceipt.
type SanitizedReceipt struct {
	RuntimeMode   string `json:"runtime_mode"`
	ExitCodeClass string `json:"exit_code_class"` // "success", "failure", or "error"
	ProviderName  string `json:"provider_name"`
	Capability    string `json:"capability"`
}

// Sanitize strips all credential-bearing fields from r and returns a
// SanitizedReceipt safe for sharing. No credential values, token fragments,
// injected env vars, or policy decision raw values are retained.
func Sanitize(r runner.RuntimeReceipt) SanitizedReceipt {
	exitClass := "success"
	if r.ExitCode != 0 {
		exitClass = "failure"
	}
	// Map error sentinel exit codes to "error" class.
	if r.ExitCode < 0 {
		exitClass = "error"
	}
	return SanitizedReceipt{
		RuntimeMode:   r.Runtime,
		ExitCodeClass: exitClass,
		ProviderName:  r.Provider,
		Capability:    r.Capability,
	}
}
