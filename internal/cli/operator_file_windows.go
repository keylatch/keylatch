package cli

import "os"

// readOperatorFile reads the operator's default config file. Windows has no
// mode bits to check; the path itself is the default one.
func readOperatorFile(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: path is the operator's default config file
}
