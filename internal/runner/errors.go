// Package runner — errors.go defines structured runtime error types.
//
// Every runtime error in the runner layer uses the
// structured format: "<class>: <provider> + <mode>: <reason>. <fix-hint>"
// so operators and agent-harness authors receive actionable feedback.
package runner

import "fmt"

// RuntimeError is a structured runtime error with class, provider, mode,
// reason, and a fix hint that the CLI can surface directly to the user.
//
// Format: "<class>: <provider> + <mode>: <reason>. <fix-hint>"
type RuntimeError struct {
	// Class is the broad error category (matches exit-code semantics).
	// Examples: "RuntimeNotAvailable", "SecretNotFound", "PolicyDeny", "GatewayNotRunning"
	Class string

	// Provider is the connection slug (e.g. "anthropic", "openrouter").
	Provider string

	// Mode is the runtime mode string (e.g. "gateway_typed", "direct_brokered").
	Mode string

	// Reason is a short human-readable explanation of why the operation failed.
	Reason string

	// Fix is an actionable hint telling the user how to resolve the problem.
	// Empty when the error is not user-recoverable.
	Fix string

	// ExitCode is the numeric exit code the CLI should pass to os.Exit.
	// Matches the exit-code matrix in internal/cli/errors.go.
	// 0 means use the caller's default (OperationFailed).
	ExitCode int

	// Wrapped is the underlying error (may be nil).
	Wrapped error
}

// Error implements the error interface using the structured format.
func (e *RuntimeError) Error() string {
	msg := fmt.Sprintf("%s: %s + %s: %s", e.Class, e.Provider, e.Mode, e.Reason)
	if e.Fix != "" {
		msg += ". " + e.Fix
	}
	return msg
}

// Unwrap returns the underlying error for errors.Is / errors.As chaining.
func (e *RuntimeError) Unwrap() error {
	return e.Wrapped
}

// NewRuntimeError constructs a RuntimeError with the given class, provider, mode, and reason.
func NewRuntimeError(class, provider, mode, reason, fix string, wrapped error) *RuntimeError {
	return &RuntimeError{
		Class:    class,
		Provider: provider,
		Mode:     mode,
		Reason:   reason,
		Fix:      fix,
		ExitCode: classToExitCode(class),
		Wrapped:  wrapped,
	}
}

// classToExitCode maps a RuntimeError class name to the canonical CLI exit code.
// Matches the exit-code matrix in internal/cli/errors.go.
func classToExitCode(class string) int {
	switch class {
	case "UsageError":
		return 1
	case "SecurityBlock":
		return 2
	case "PolicyDeny":
		return 3
	case "ApprovalRequired", "BackendUnavailable":
		return 4
	case "RuntimeNotAvailable", "GatewayNotRunning":
		return 5
	case "SecretNotFound":
		return 6
	case "BootstrapMissing":
		return 7
	case "InsecureArgv":
		return 8
	case "InternalError":
		return 9
	default:
		return 5 // OperationFailed as safe fallback
	}
}

// Convenience constructors for common error classes.

// ErrGatewayNotRunningStructured returns a structured RuntimeError for the
// "gateway not running" case that includes an actionable fix hint.
func ErrGatewayNotRunningStructured(provider, mode string) *RuntimeError {
	return NewRuntimeError(
		"RuntimeNotAvailable",
		provider,
		mode,
		"gateway is not running",
		"Try: keylatch gateway up",
		ErrGatewayNotRunning,
	)
}

// ErrSecretNotFound returns a structured RuntimeError for missing credentials.
func ErrSecretNotFound(provider, mode string, wrapped error) *RuntimeError {
	return NewRuntimeError(
		"SecretNotFound",
		provider,
		mode,
		"no credential found for this connection",
		fmt.Sprintf("Try: keylatch connect %s --field api_key=@prompt", provider),
		wrapped,
	)
}

// ErrTokenMintFailed returns a structured RuntimeError for token minting failures.
func ErrTokenMintFailed(provider, mode string, wrapped error) *RuntimeError {
	return NewRuntimeError(
		"RuntimeNotAvailable",
		provider,
		mode,
		"failed to mint session token",
		"Run: keylatch doctor --category runtime",
		wrapped,
	)
}

// ErrBrokerExchange returns a structured RuntimeError for broker exchange failures.
// Class is "RuntimeNotAvailable" (exit 5) — semantically the broker is a runtime
// service dependency; "BrokerError" has no explicit classToExitCode mapping.
func ErrBrokerExchange(provider, mode string, wrapped error) *RuntimeError {
	return NewRuntimeError(
		"RuntimeNotAvailable",
		provider,
		mode,
		"broker exchange failed",
		"Run: keylatch doctor --category runtime",
		wrapped,
	)
}
