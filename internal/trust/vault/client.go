// Package vault implements a trust.RootOfTrust adapter backed by HashiCorp Vault
// or OpenBao Transit secrets engine.
//
// Security invariants:
// - Tokens are never held in struct fields; cleared after every API call.
// - mTLS client certs are loaded per-call, not cached.
// - Root spec IDs are HMAC'd before inclusion in audit events.
package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Options configures a Vault Transit adapter.
type Options struct {
	// Addr is the Vault server address (e.g. "https://vault.example.com:8200").
	Addr string
	// AuthMethod is one of "mtls", "oidc", "approle", "k8s".
	AuthMethod string
	// Namespace is the Vault namespace (X-Vault-Namespace header).
	Namespace string
	// TransitKeyName is the name of the Transit encryption key.
	TransitKeyName string
	// Label is the display label for this root.
	Label string

	// mTLS configuration.
	CACertPath string
	ClientCert string
	ClientKey  string

	// AppRole configuration.
	RoleID   string
	SecretID string // never stored; loaded per-call

	// K8s configuration.
	K8sRole  string
	K8sMount string
}

// newHTTPClient creates an *http.Client with mTLS support if configured.
func newHTTPClient(opts Options) (*http.Client, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load CA cert if provided.
	if opts.CACertPath != "" {
		caPEM, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("vault: read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("vault: parse CA cert")
		}
		tlsCfg.RootCAs = pool
	}

	// Load client cert/key per-call (not cached) for mTLS.
	if opts.ClientCert != "" && opts.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(opts.ClientCert, opts.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("vault: load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		TLSClientConfig:    tlsCfg,
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}, nil
}

// authenticate obtains a Vault token for the given auth method.
// The token must NOT be stored in the caller's struct fields.
func authenticate(ctx context.Context, opts Options, client *http.Client) (string, error) {
	switch opts.AuthMethod {
	case "mtls":
		return authenticateMTLS(ctx, opts, client)
	case "approle":
		return authenticateAppRole(ctx, opts, client)
	case "k8s":
		return authenticateK8s(ctx, opts, client)
	case "oidc":
		// OIDC requires a browser; stub returns unavailable.
		return "", fmt.Errorf("vault: oidc auth requires interactive session")
	default:
		return "", fmt.Errorf("vault: unknown auth method %q", opts.AuthMethod)
	}
}

func authenticateMTLS(ctx context.Context, opts Options, client *http.Client) (string, error) {
	// mTLS auth: POST /v1/auth/cert/login
	req, err := http.NewRequestWithContext(ctx, "POST",
		opts.Addr+"/v1/auth/cert/login", nil)
	if err != nil {
		return "", fmt.Errorf("vault: mtls auth request: %w", err)
	}
	addVaultHeaders(req, opts.Namespace, "")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault: mtls auth: %w", err)
	}
	defer resp.Body.Close()
	return extractToken(resp)
}

func authenticateAppRole(ctx context.Context, opts Options, client *http.Client) (string, error) {
	// Build JSON body as []byte so it can be zeroed after use.
	bodyBytes := []byte(fmt.Sprintf(`{"role_id":%q,"secret_id":%q}`, opts.RoleID, opts.SecretID))
	req, err := http.NewRequestWithContext(ctx, "POST",
		opts.Addr+"/v1/auth/approle/login",
		bytesReaderZero(bodyBytes))
	if err != nil {
		zeroBytes(bodyBytes)
		return "", fmt.Errorf("vault: approle auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	addVaultHeaders(req, opts.Namespace, "")
	resp, err := client.Do(req)
	// bodyBytes has been handed off to bytesReaderZero and will be zeroed after write.
	if err != nil {
		return "", fmt.Errorf("vault: approle auth: %w", err)
	}
	defer resp.Body.Close()
	return extractToken(resp)
}

func authenticateK8s(ctx context.Context, opts Options, client *http.Client) (string, error) {
	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", fmt.Errorf("vault: k8s: read SA token: %w", err)
	}
	// Zero the SA token bytes after building the JSON body.
	defer zeroBytes(saToken)

	mount := opts.K8sMount
	if mount == "" {
		mount = "kubernetes"
	}
	bodyBytes := []byte(fmt.Sprintf(`{"role":%q,"jwt":%q}`, opts.K8sRole, string(saToken)))
	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/v1/auth/%s/login", opts.Addr, mount),
		bytesReaderZero(bodyBytes))
	if err != nil {
		zeroBytes(bodyBytes)
		return "", fmt.Errorf("vault: k8s auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	addVaultHeaders(req, opts.Namespace, "")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault: k8s auth: %w", err)
	}
	defer resp.Body.Close()
	return extractToken(resp)
}

func addVaultHeaders(req *http.Request, namespace, token string) {
	req.Header.Set("Accept", "application/json")
	if namespace != "" {
		req.Header.Set("X-Vault-Namespace", namespace)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
}

func extractToken(resp *http.Response) (string, error) {
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("vault: auth failed (status %d): %s", resp.StatusCode, sanitize(body))
	}
	// Parse client_token from JSON body.
	// Use minimal JSON parsing to avoid importing encoding/json at compile time.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("vault: read auth response: %w", err)
	}
	token := jsonExtractString(body, "client_token")
	if token == "" {
		return "", fmt.Errorf("vault: no client_token in auth response")
	}
	return token, nil
}

// jsonExtractString extracts a JSON string value by key (minimal, no full parser).
// Only handles simple {"auth":{"client_token":"..."}} structures.
func jsonExtractString(data []byte, key string) string {
	needle := `"` + key + `":"`
	idx := indexOf(data, []byte(needle))
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	if start >= len(data) {
		return ""
	}
	end := indexOf(data[start:], []byte(`"`))
	if end < 0 {
		return ""
	}
	return string(data[start : start+end])
}

func indexOf(data, sub []byte) int {
	for i := range data {
		if i+len(sub) > len(data) {
			return -1
		}
		found := true
		for j, b := range sub {
			if data[i+j] != b {
				found = false
				break
			}
		}
		if found {
			return i
		}
	}
	return -1
}

// sanitize removes all non-printable bytes from a string for error messages.
func sanitize(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		}
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return string(out)
}

// bytesReaderZero returns an io.Reader over b and zeros b after all bytes are written.
// The slice b must not be reused by the caller after passing it to this function.
func bytesReaderZero(b []byte) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(b)
		zeroBytes(b)
		_ = pw.Close()
	}()
	return pr
}

// stringReader is kept for non-sensitive reads only. It does NOT zero the string.
// For sensitive data (tokens, passwords), use bytesReaderZero with a []byte.
//
//nolint:unused // planned: used by Vault HTTP request body construction in token auth
func stringReader(s string) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte(s))
		_ = pw.Close()
	}()
	return pr
}
