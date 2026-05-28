package cli

import (
	"fmt"

	"github.com/keylatch/keylatch/internal/exitcode"
)

// CLIError is a typed error that carries both a human-readable message and the
// exit code that the CLI should emit via os.Exit when this error propagates to
// the top-level Execute handler.
//
// Class names map to exit-code constants in internal/exitcode (see exit-code matrix below).
// Every RunE handler that can produce a typed failure SHOULD return a CLIError
// rather than a plain fmt.Errorf so that cmd/keylatch/main.go can call
// os.Exit with the correct code and print a structured error to stderr.
//
// Exit-code matrix (EPIC-02 Task 2):
//
//	Class             Code  Constant
//	OK                0     exitcode.OK
//	UsageError        1     exitcode.UserError
//	SecurityBlock     2     exitcode.SecurityBlock
//	PolicyDeny        3     exitcode.PolicyDeny
//	ApprovalRequired  4     exitcode.ApprovalRequired
//	RuntimeNotAvail.  5     exitcode.RuntimeNotAvailable
//	SecretNotFound    6     (no existing alias — introduced here)
//	BootstrapMissing  7     exitcode.BootstrapMissing
//	InsecureArgv      8     exitcode.InsecureArgv
//	InternalError     9     (introduced here)
//
// Note: ApprovalRequired and BackendUnavailable share exit code 4 — distinguish by err.Class
type CLIError struct {
	// Class is a machine-readable error category string (e.g. "UsageError").
	Class string
	// Code is the numeric exit code for os.Exit.
	Code int
	// Message is the human-readable error description printed to stderr.
	Message string
}

// Error implements the error interface.
func (e *CLIError) Error() string {
	return fmt.Sprintf("%s (exit %d): %s", e.Class, e.Code, e.Message)
}

// Stderr returns the string that should be written to stderr by the CLI runner.
// Format: "error[<Class>]: <Message>"
func (e *CLIError) Stderr() string {
	return fmt.Sprintf("error[%s]: %s\n", e.Class, e.Message)
}

// --- Constructors ---

// NewUsageError returns a CLIError for invalid user input (exit 1).
func NewUsageError(format string, args ...interface{}) *CLIError {
	return &CLIError{Class: "UsageError", Code: exitcode.UserError, Message: fmt.Sprintf(format, args...)}
}

// NewSecurityBlock returns a CLIError when an LLM session guard blocks a call (exit 2).
func NewSecurityBlock(format string, args ...interface{}) *CLIError {
	return &CLIError{Class: "SecurityBlock", Code: exitcode.SecurityBlock, Message: fmt.Sprintf(format, args...)}
}

// NewPolicyDeny returns a CLIError when policy explicitly denies the request (exit 3).
func NewPolicyDeny(format string, args ...interface{}) *CLIError {
	return &CLIError{Class: "PolicyDeny", Code: exitcode.PolicyDeny, Message: fmt.Sprintf(format, args...)}
}

// NewApprovalRequired returns a CLIError when a policy decision requires human approval (exit 4).
func NewApprovalRequired(format string, args ...interface{}) *CLIError {
	return &CLIError{Class: "ApprovalRequired", Code: exitcode.ApprovalRequired, Message: fmt.Sprintf(format, args...)}
}

// NewRuntimeNotAvailable returns a CLIError when a runtime mode is unavailable (exit 5).
func NewRuntimeNotAvailable(format string, args ...interface{}) *CLIError {
	return &CLIError{Class: "RuntimeNotAvailable", Code: exitcode.RuntimeNotAvailable, Message: fmt.Sprintf(format, args...)}
}

// NewSecretNotFound returns a CLIError when a requested secret does not exist (exit 6).
// Exit code 6 is not aliased in the exitcode package — it is introduced by EPIC-02.
func NewSecretNotFound(format string, args ...interface{}) *CLIError {
	return &CLIError{Class: "SecretNotFound", Code: exitCodeSecretNotFound, Message: fmt.Sprintf(format, args...)}
}

// NewInsecureArgv returns a CLIError when a sensitive value is detected in argv (exit 8).
func NewInsecureArgv(format string, args ...interface{}) *CLIError {
	return &CLIError{Class: "InsecureArgv", Code: exitcode.InsecureArgv, Message: fmt.Sprintf(format, args...)}
}

// NewBootstrapMissing returns a CLIError when bootstrap has not been run (exit 7).
func NewBootstrapMissing(format string, args ...interface{}) *CLIError {
	return &CLIError{Class: "BootstrapMissing", Code: exitcode.BootstrapMissing, Message: fmt.Sprintf(format, args...)}
}

// NewBackendUnavailable returns a CLIError when the backend or service is unavailable (exit 4).
// Maps to exitcode.BackendUnavailable (4) which is also aliased as ApprovalRequired.
func NewBackendUnavailable(format string, args ...interface{}) *CLIError {
	return &CLIError{Class: "BackendUnavailable", Code: exitcode.BackendUnavailable, Message: fmt.Sprintf(format, args...)}
}

// NewInternalError returns a CLIError for unexpected internal failures (exit 9).
// Exit code 9 is introduced by EPIC-02.
func NewInternalError(format string, args ...interface{}) *CLIError {
	return &CLIError{Class: "InternalError", Code: exitCodeInternalError, Message: fmt.Sprintf(format, args...)}
}

// exitCodeSecretNotFound is exit code 6 (secret not found).
// Introduced in EPIC-02; not yet in the exitcode package.
const exitCodeSecretNotFound = 6

// exitCodeInternalError is exit code 9 (internal / unexpected error).
// Introduced in EPIC-02; not yet in the exitcode package.
const exitCodeInternalError = 9
