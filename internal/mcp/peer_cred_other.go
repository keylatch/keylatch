//go:build !linux && !darwin

package mcp

// getPeerUID rejects all connections on unsupported platforms (neither Linux nor macOS).
// Linux uses SO_PEERCRED; macOS uses LOCAL_PEERCRED (peer_cred_darwin.go).
func getPeerUID(_ int, _ int) int {
	return -1
}
