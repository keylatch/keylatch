//go:build !linux && !darwin

package callerkind

// SharesNamespaces is false where peers cannot be inspected, so they are never
// classified as human.
func SharesNamespaces(int) bool { return false }
