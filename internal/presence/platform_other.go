//go:build !linux && !windows && !(darwin && cgo)

package presence

// platformMethod returns nil where no platform confirmation exists; the
// terminal step still applies.
func platformMethod() Method { return nil }
