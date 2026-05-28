//go:build darwin

package exec

// securityBin is the resolved path to /usr/bin/security on macOS.
// MustResolve panics at package init if the binary is absent — this is
// intentional: if /usr/bin/security is missing, the keychain backend cannot
// function and we fail fast.
var securityBin = MustResolve("/usr/bin/security") //nolint:unused // planned: used by keychain KEK operations in Phase 6 to replace inline command strings
