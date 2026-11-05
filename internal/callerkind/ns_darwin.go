//go:build darwin

package callerkind

// SharesNamespaces is true for any known peer: macOS has no namespaces to
// compare, so a caller is told apart from a human by its signals and ancestry.
// An unknown peer (pid 0 or below) never shares them.
func SharesNamespaces(pid int) bool { return pid > 0 }
