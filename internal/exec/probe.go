// Package exec provides an abstraction for locating and querying external
// binaries. Using the Probe interface in doctor and backend checks allows
// tests to inject mock probes without real exec.LookPath calls.
package exec

import "context"

// Probe abstracts external-binary detection and version querying.
type Probe interface {
	// Find locates bin in the system PATH (or via an explicit override).
	// Returns (path, true, nil) when found, ("", false, nil) when absent,
	// and ("", false, err) on unexpected errors.
	Find(ctx context.Context, bin string) (path string, ok bool, err error)

	// Version runs path --version (or equivalent) and returns the first line
	// of output trimmed. Returns an error if the binary cannot be executed.
	Version(ctx context.Context, path string) (string, error)
}
