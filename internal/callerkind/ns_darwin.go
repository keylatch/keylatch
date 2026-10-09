//go:build darwin

package callerkind

// SharesNamespaces is true: macOS has no namespaces to compare, so a caller
// is told apart from a human by its signals and ancestry.
func SharesNamespaces(int) bool { return true }
