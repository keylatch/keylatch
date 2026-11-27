//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package customsecret

// lockFile is a no-op where advisory file locks are unavailable.
func lockFile(string) (func(), error) { return func() {}, nil }
