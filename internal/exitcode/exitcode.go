// Package exitcode defines exit code constants for the keylatch CLI.
// These values are part of the public interface — changing them is a breaking change.
package exitcode

// Exit code constants for the keylatch CLI.
// Every command that exits non-zero must use one of these constants.
// These values are part of the public interface — changing them is a breaking change.
const (
	OK                 = 0
	UserError          = 1 // general user / usage error
	SecurityBlock      = 2 // LLM session guard blocked the call
	Missing            = 3 // resource not found (policy, connection, etc.)
	BackendUnavailable = 4 // backend or service not available
	OperationFailed    = 5 // runtime mode removed or unavailable; general op failure

	// PolicyDeny is returned when policy.Check returns an explicit deny.
	PolicyDeny = 3 // alias for Missing; distinct semantic use

	// ApprovalRequired is returned when a policy decision requires human approval.
	ApprovalRequired = 4 // alias for BackendUnavailable; distinct semantic use

	// RuntimeNotAvailable is returned when a runtime mode is removed or unavailable.
	RuntimeNotAvailable = 5 // alias for OperationFailed; distinct semantic use

	// BootstrapMissing is returned when keylatch bootstrap has not been run.
	BootstrapMissing = 7

	// InsecureArgv is returned when a sensitive value is passed via argv (shell history leak).
	InsecureArgv = 8
)
