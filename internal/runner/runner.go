// Package runner defines the interface for executing commands under a named
// credential connection. S0-9: allowlist-only; no blocklist exists.
package runner

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrCommandNotAllowed is returned by Runner.Run when the command does not
// match any entry in Connection.AllowedCommandPrefixes.
var ErrCommandNotAllowed = errors.New("command not in connection allowlist")

// ErrUnknownRuntime is returned when no Driver is registered for the resolved
// runtime mode.
var ErrUnknownRuntime = errors.New("runner: no driver registered for runtime mode")

// ErrGuardDenied is returned when the LLM session guard blocks the execution.
var ErrGuardDenied = errors.New("runner: guard denied execution")

// ErrModeNotAvailable is returned by a placeholder Driver registered for a mode
// that is declared but not yet implemented in this release (e.g.
// direct_classic_sandboxed in 0.1.0).
var ErrModeNotAvailable = errors.New("runner: runtime mode not available in this release")

// Connection describes a named credential connection and the commands
// allowed to run under it. AllowedCommandPrefixes must be non-empty for
// any command to be permitted; an empty slice denies all execution.
// S0-9 / FIND-004: per-template allowlist — empty = run REJECTED.
type Connection struct {
	Name                   string
	AllowedCommandPrefixes []string // FIND-004: per-template allowlist; empty = run REJECTED
}

// RunOptions carries per-invocation options.
type RunOptions struct {
	Env   map[string]string
	Stdin io.Reader
}

// ExecRequest carries all context for a single execution attempt.
type ExecRequest struct {
	// Connection is the provider slug identifying which stored credential to use.
	ConnectionSlug string
	// Command is the argv to execute.
	Command []string
	// WorkingDir is the subprocess working directory ("" inherits the current dir).
	WorkingDir string
	// Actor is the identity requesting execution (inferred from env when empty).
	Actor string
	// Capability is the requested operation (default: "inject").
	Capability string
	// TTL caps the subprocess and any issued tokens.
	TTL time.Duration
	// Runtime is the requested RuntimeMode. Empty triggers automatic selection.
	Runtime string
	// ApprovalJWT is the hardware/two-person approval token for sandboxed modes.
	ApprovalJWT string
	// Stdin, Stdout, Stderr allow tests to capture subprocess I/O.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// ExtraAllowedPrefixes are additional command prefixes allowed for this
	// invocation only. They are prepended to the template's AllowedCommandPrefixes
	// before the allowlist check in DispatchRunner. Use for CLI --allow flag.
	ExtraAllowedPrefixes []string
	// FeatureFlags carries per-request feature gate flags. Drivers may require
	// specific flags to be true before executing (e.g. "direct_classic_sandboxed").
	FeatureFlags map[string]bool
	// CleanEnv, when true, instructs the driver to start the child process with
	// a minimal environment rather than inheriting os.Environ(). The minimal set
	// is: PATH, HOME, USER, LOGNAME, SHELL, TERM, LANG, LC_* plus all explicitly
	// injected credential vars and any vars listed in ExtraEnvVars.
	// T-08-02: --clean-env flag implementation.
	CleanEnv bool
	// ExtraEnvVars lists additional env var names to preserve when CleanEnv is true.
	// Ignored when CleanEnv is false.
	ExtraEnvVars []string
}

// RuntimeReceipt is the value-free record emitted for every execution path
// including errors (S-RM-9). It never contains credential bytes.
type RuntimeReceipt struct {
	Runtime         string        `json:"runtime"`
	Provider        string        `json:"provider"`
	Capability      string        `json:"capability"`
	PolicyDecision  string        `json:"policy_decision"`
	CredentialShape string        `json:"credential_shape"`
	ExitCode        int           `json:"exit_code,omitempty"`
	TTL             time.Duration `json:"ttl,omitempty"`
}

// Runner executes commands under a named connection's allowed prefix list.
type Runner interface {
	Run(ctx context.Context, conn Connection, command []string, opts RunOptions) (Receipt, error)
}
