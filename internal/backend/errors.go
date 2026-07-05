package backend

import (
	"errors"
	"sync"
)

// Sentinel errors for the Backend interface. Tests use errors.Is.
// Exit code comments indicate the expected CLI exit code for each error.
var (
	// ErrUnavailable indicates the backend is not available on this platform
	// or is not yet implemented. → exit 4 (BackendUnavailable)
	ErrUnavailable = errors.New("backend unavailable")

	// ErrNotFound indicates the requested secret path does not exist.
	// → exit 3 (Missing)
	ErrNotFound = errors.New("secret not found")

	// ErrLocked indicates the backend is locked and cannot return plaintext
	// (e.g. LLM session guard, keychain locked, missing passphrase).
	// → exit 2 (SecurityBlock)
	ErrLocked = errors.New("backend locked")

	// ErrACLMismatch indicates a keychain ACL mismatch: the stored binary path
	// or code-signing identity differs from the current binary.
	// → exit 4 (BackendUnavailable) with a fix hint
	ErrACLMismatch = errors.New("ACL mismatch")

	// ErrManifestCorrupt indicates the manifest file or keychain manifest item
	// cannot be parsed. → exit 1 (UserError)
	ErrManifestCorrupt = errors.New("manifest corrupt")

	// ErrNotSupported is returned by backends that do not implement optional
	// versioned-storage methods (GetMeta, SetMeta, ListMeta,
	// GetVersioned, SetVersioned, DeleteVersioned).
	ErrNotSupported = errors.New("backend: operation not supported")

	// ErrUnsupportedFormat is returned when an on-disk record has an
	// incompatible schema_version (e.g. a pre-v1.0.0 record with fingerprint_sha256).
	// → exit 1 (UserError) with a re-enrollment hint
	ErrUnsupportedFormat = errors.New("format not supported: run 'keylatch bootstrap' to re-enroll")

	// ErrBootstrapRequired is returned by the file backend when no keyring is
	// available (the system has not been bootstrapped). Callers should exit
	// with exitcode.BootstrapMissing (7).
	// → exit 7 (BootstrapMissing)
	ErrBootstrapRequired = errors.New("keylatch bootstrap required: run 'keylatch bootstrap' first")
)

var (
	registrationMu  sync.Mutex
	registrationErr []error
)

// AppendRegistrationError records a backend registration failure from an
// init() side-effect. Backends call this instead of panicking so that the
// startup gate in PersistentPreRunE can surface the error with an actionable
// message.
func AppendRegistrationError(err error) {
	registrationMu.Lock()
	registrationErr = append(registrationErr, err)
	registrationMu.Unlock()
}

// RegistrationErrors returns all init-time backend registration failures.
func RegistrationErrors() []error {
	registrationMu.Lock()
	defer registrationMu.Unlock()
	return registrationErr
}
