// Package proc hardens the running process against inspection by other
// processes of the same user: no core dumps, no memory or environment reads
// through /proc, no debugger attach. The gateway and the daemon call Harden at
// start because they hold unwrapped keys and credentials in memory.
package proc

// Harden applies every protection the platform offers. It stops at nothing:
// the first failure is returned after all of them were attempted, so a
// partially hardened process is never silently treated as fully hardened.
func Harden() error { return harden() }
