package control

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

var systemBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/ca-bundle.pem",
	"/etc/ssl/cert.pem",
	"/usr/local/share/certs/ca-root-nss.crt",
}

var errNoSystemRoots = errors.New("no system certificate bundle found")

// systemRoots returns the PEM of the caller's trusted roots: the bundle its
// own environment names, else the first well-known system bundle.
func systemRoots(lookup llmcontext.Lookup) ([]byte, error) {
	candidates := systemBundles
	if own := lookup("SSL_CERT_FILE"); own != "" {
		candidates = append([]string{own}, candidates...)
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err == nil && bytes.Contains(data, []byte("BEGIN CERTIFICATE")) {
			return data, nil
		}
	}
	return nil, errNoSystemRoots
}

// writeCABundle writes the system roots followed by the session CA to a
// private temporary file and returns its path and a function that removes it.
// Without system roots the bundle holds the session CA alone and warn says so.
func writeCABundle(lookup llmcontext.Lookup, sessionPEM string) (path string, cleanup func(), warn error, err error) {
	roots, warn := systemRoots(lookup)
	dir, err := os.MkdirTemp("", "keylatch-ca-")
	if err != nil {
		return "", nil, nil, fmt.Errorf("create CA bundle directory: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	path = filepath.Join(dir, "ca-bundle.pem")
	data := append(bytes.TrimRight(roots, "\n"), '\n')
	data = append(data, sessionPEM...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		cleanup()
		return "", nil, nil, fmt.Errorf("write CA bundle: %w", err)
	}
	return path, cleanup, warn, nil
}
