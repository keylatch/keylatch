// Package store implements URI dispatch for external credential store references.
//
// T-05-01 (EPIC-05): resolves provider-managed secret URIs in the form:
//
//	op://vault/item/field      — 1Password CLI (op)
//	aws-sm://region/secret-id  — AWS Secrets Manager (aws secretsmanager get-secret-value)
//	hashivault://path          — HashiCorp Vault (vault kv get)
//
// Each scheme shells out to the appropriate CLI tool (op, aws, vault). The
// implementations are intentionally thin stubs that shell out so they remain
// testable via mock runners. Full native SDK integration is planned for v1.1.0.
//
// Security invariants:
//   - S-EXT-1: plaintext bytes are returned to the caller, never written to disk.
//   - S-EXT-2: CLI binaries are resolved from PATH; absolute paths may be injected for testing.
//   - S-EXT-3: only the requested field/key is extracted; no bulk exports.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
)

// validIdent matches safe KV path segments and field names for hashivault.
// Only alphanumeric characters, underscores, hyphens, dots, and forward-slashes
// are permitted — anything else could be an injection vector.
var validIdent = regexp.MustCompile(`^[A-Za-z0-9_\-/.]+$`)

// ErrUnsupportedScheme is returned when the URI scheme is not recognised.
var ErrUnsupportedScheme = errors.New("store: unsupported URI scheme")

// ErrEmptyRef is returned when the ref string is empty or blank.
var ErrEmptyRef = errors.New("store: empty provider-ref URI")

// ErrBinaryNotFound is returned when the required CLI binary is not on PATH.
var ErrBinaryNotFound = errors.New("store: required CLI binary not found on PATH")

// ErrInvalidURI is returned when the URI format is not recognised.
var ErrInvalidURI = errors.New("store: invalid provider-ref URI")

// validSchemes are the supported provider-ref URI schemes.
var validSchemes = map[string]bool{
	"op":         true,
	"aws-sm":     true,
	"hashivault": true,
}

// IsProviderRefURI reports whether val begins with a supported external-store
// URI scheme. It is used by the runtime injection path to detect fields that
// require resolution before being injected into a subprocess environment.
func IsProviderRefURI(val []byte) bool {
	return bytes.HasPrefix(val, []byte("op://")) ||
		bytes.HasPrefix(val, []byte("aws-sm://")) ||
		bytes.HasPrefix(val, []byte("hashivault://"))
}

// ValidateProviderRefURI performs a dry-run check on a provider-ref URI before
// any store write occurs. It returns ErrInvalidURI when the scheme is not supported
// or the URI is structurally invalid, without invoking any external binary.
//
// EPIC-10 (T-10-01): used by the CLI --provider-ref flag to gate persistence.
func ValidateProviderRefURI(uri string) error {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return fmt.Errorf("%w: empty URI", ErrInvalidURI)
	}
	idx := strings.Index(uri, "://")
	if idx < 0 {
		return fmt.Errorf("%w: no scheme in %q", ErrInvalidURI, uri)
	}
	if idx == 0 {
		return fmt.Errorf("%w: empty scheme in %q", ErrInvalidURI, uri)
	}
	scheme := uri[:idx]
	rest := uri[idx+3:]
	if !validSchemes[scheme] {
		return fmt.Errorf("%w: unsupported scheme %q (supported: op, aws-sm, hashivault)", ErrInvalidURI, scheme)
	}
	// Require at least "something/something" after the scheme.
	if !strings.Contains(rest, "/") || strings.HasSuffix(rest, "/") {
		return fmt.Errorf("%w: %q must be %s://vault-or-region/item-or-secret[/field]", ErrInvalidURI, uri, scheme)
	}
	return nil
}

// CommandRunner abstracts exec.Command so implementations are testable.
// It mirrors the interface used elsewhere in keylatch (internal/exec).
type CommandRunner interface {
	Run(ctx context.Context, bin string, args []string, stdin []byte) (stdout []byte, stderr []byte, exitCode int, err error)
}

// Resolver dispatches provider-ref URIs to the appropriate external store.
type Resolver struct {
	runner CommandRunner
	// binOverrides allows tests to inject fake binary paths.
	// Key: scheme (e.g. "op"), value: absolute path to the binary.
	binOverrides map[string]string
}

// NewResolver returns a Resolver using the given CommandRunner.
// Pass a real exec runner (e.g. exec.DefaultRunner) in production.
func NewResolver(runner CommandRunner) *Resolver {
	return &Resolver{
		runner:       runner,
		binOverrides: make(map[string]string),
	}
}

// WithBinOverride replaces the binary resolved from PATH for a given scheme.
// Used in integration tests to inject a mock binary.
func (r *Resolver) WithBinOverride(scheme, binPath string) *Resolver {
	r.binOverrides[scheme] = binPath
	return r
}

// Resolve resolves a provider-ref URI and returns the plaintext bytes.
//
// Supported schemes:
//   - op://vault/item/field
//   - aws-sm://region/secret-id[#key]   (key is optional; returns the full JSON value if absent)
//   - hashivault://mount/path#field      (field defaults to "value" when absent)
func (r *Resolver) Resolve(ctx context.Context, ref string) ([]byte, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, ErrEmptyRef
	}

	// Normalise: aws-sm:// uses a hyphen that url.Parse handles via Opaque.
	// We parse the scheme manually to avoid url.Parse quirks with non-standard schemes.
	idx := strings.Index(ref, "://")
	if idx < 0 {
		return nil, fmt.Errorf("%w: no scheme in %q", ErrUnsupportedScheme, ref)
	}
	scheme := ref[:idx]
	rest := ref[idx+3:]

	switch scheme {
	case "op":
		return r.resolveOP(ctx, rest)
	case "aws-sm":
		return r.resolveAWSSM(ctx, rest)
	case "hashivault":
		return r.resolveHashiVault(ctx, rest)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedScheme, scheme)
	}
}

// --- 1Password (op://) ---

// resolveOP resolves op://vault/item/field using `op read`.
//
// URI format: op://vault-name/item-title/field-name
// Maps directly to: op read "op://vault-name/item-title/field-name"
func (r *Resolver) resolveOP(ctx context.Context, path string) ([]byte, error) {
	bin, err := r.resolveBin("op", "op")
	if err != nil {
		return nil, err
	}
	ref := "op://" + path
	stdout, stderr, exitCode, err := r.runner.Run(ctx, bin, []string{"read", "--no-newline", ref}, nil)
	if err != nil {
		return nil, fmt.Errorf("op read: runner error: %w", err)
	}
	if exitCode != 0 {
		// S-EXT-2: never echo full stderr (may contain session info).
		hint := classifyOPError(string(stderr))
		return nil, fmt.Errorf("op read exited %d: %s", exitCode, hint)
	}
	if len(stdout) == 0 {
		return nil, fmt.Errorf("op read: empty output for %q", ref)
	}
	return stdout, nil
}

// classifyOPError returns a sanitised hint string from op CLI stderr.
func classifyOPError(stderr string) string {
	lower := strings.ToLower(stderr)
	switch {
	case strings.Contains(lower, "not found") || strings.Contains(lower, "no item"):
		return "item or field not found"
	case strings.Contains(lower, "unauthorized") || strings.Contains(lower, "authentication"):
		return "authentication error — check OP_SERVICE_ACCOUNT_TOKEN or run: op signin"
	case strings.Contains(lower, "not signed in") || strings.Contains(lower, "sign in"):
		return "not signed in — run: op signin"
	default:
		return "op CLI error (run 'op read <ref>' manually to diagnose)"
	}
}

// --- AWS Secrets Manager (aws-sm://) ---

// resolveAWSSM resolves aws-sm://region/secret-id[#key] using `aws secretsmanager get-secret-value`.
//
// URI format: aws-sm://region/secret-id   → returns SecretString
//
//	aws-sm://region/secret-id#key → returns JSON field "key" from SecretString
func (r *Resolver) resolveAWSSM(ctx context.Context, path string) ([]byte, error) {
	bin, err := r.resolveBin("aws-sm", "aws")
	if err != nil {
		return nil, err
	}

	// Split fragment (key within JSON secret).
	secretPath := path
	jsonKey := ""
	if idx := strings.LastIndex(path, "#"); idx >= 0 {
		secretPath = path[:idx]
		jsonKey = path[idx+1:]
	}

	// Split region/secret-id.
	region, secretID, err := splitRegionSecret(secretPath)
	if err != nil {
		return nil, err
	}

	args := []string{
		"secretsmanager", "get-secret-value",
		"--region", region,
		"--secret-id", secretID,
		"--query", "SecretString",
		"--output", "text",
	}
	stdout, stderr, exitCode, runErr := r.runner.Run(ctx, bin, args, nil)
	if runErr != nil {
		return nil, fmt.Errorf("aws secretsmanager: runner error: %w", runErr)
	}
	if exitCode != 0 {
		hint := classifyAWSError(string(stderr))
		return nil, fmt.Errorf("aws secretsmanager exited %d: %s", exitCode, hint)
	}

	raw := strings.TrimRight(string(stdout), "\n")
	if jsonKey == "" {
		return []byte(raw), nil
	}

	// Extract the named key from the JSON secret.
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("aws-sm: secret is not JSON — cannot extract key %q", jsonKey)
	}
	v, ok := m[jsonKey]
	if !ok {
		return nil, fmt.Errorf("aws-sm: key %q not found in secret JSON", jsonKey)
	}
	// Unwrap JSON string if the value is a quoted string.
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return []byte(s), nil
	}
	// Return raw JSON for non-string values.
	return []byte(v), nil
}

// splitRegionSecret splits "region/secret-id" or returns an error.
func splitRegionSecret(path string) (region, secretID string, err error) {
	// Use the first segment as the region; the rest is the secret ID.
	// Secret IDs may contain slashes (ARN paths).
	idx := strings.Index(path, "/")
	if idx < 0 {
		return "", "", fmt.Errorf("aws-sm: URI must be aws-sm://region/secret-id (got %q)", path)
	}
	region = path[:idx]
	secretID = path[idx+1:]
	if region == "" || secretID == "" {
		return "", "", fmt.Errorf("aws-sm: region and secret-id must be non-empty in %q", path)
	}
	return region, secretID, nil
}

// classifyAWSError returns a sanitised hint from aws CLI stderr.
func classifyAWSError(stderr string) string {
	lower := strings.ToLower(stderr)
	switch {
	case strings.Contains(lower, "resourcenotfoundexception") || strings.Contains(lower, "not found"):
		return "secret not found"
	case strings.Contains(lower, "accessdenied") || strings.Contains(lower, "unauthorized"):
		return "access denied — check AWS credentials and IAM policy"
	case strings.Contains(lower, "no credentials") || strings.Contains(lower, "unable to locate credentials"):
		return "no AWS credentials — configure AWS_ACCESS_KEY_ID / AWS_PROFILE or instance role"
	default:
		return "aws CLI error (run 'aws secretsmanager get-secret-value' manually to diagnose)"
	}
}

// --- HashiCorp Vault (hashivault://) ---

// resolveHashiVault resolves hashivault://mount/path#field using `vault kv get`.
//
// URI format: hashivault://secret/myapp/config#api_key
//
//	mount/path defaults to "secret/myapp/config"
//	field defaults to "value" when the fragment is absent
func (r *Resolver) resolveHashiVault(ctx context.Context, ref string) ([]byte, error) {
	bin, err := r.resolveBin("hashivault", "vault")
	if err != nil {
		return nil, err
	}

	// Parse with standard URL parser (fragment is the field name).
	// We add a fake scheme so url.Parse works correctly.
	u, err := url.Parse("fake://" + ref)
	if err != nil {
		return nil, fmt.Errorf("hashivault: invalid URI %q: %w", ref, err)
	}

	// Reconstruct path: host + path (url.Parse splits on first /).
	kvPath := u.Host
	if u.Path != "" && u.Path != "/" {
		kvPath += u.Path
	}
	if kvPath == "" {
		return nil, fmt.Errorf("hashivault: empty KV path in %q", ref)
	}
	if !validIdent.MatchString(kvPath) {
		return nil, fmt.Errorf("hashivault: invalid KV path %q", kvPath)
	}

	field := "value"
	if u.Fragment != "" {
		field = u.Fragment
	}
	if !validIdent.MatchString(field) {
		return nil, fmt.Errorf("hashivault: invalid field name %q", field)
	}

	args := []string{"kv", "get", "-field=" + field, "-format=raw", kvPath}
	stdout, stderr, exitCode, runErr := r.runner.Run(ctx, bin, args, nil)
	if runErr != nil {
		return nil, fmt.Errorf("vault kv get: runner error: %w", runErr)
	}
	if exitCode != 0 {
		hint := classifyVaultError(string(stderr))
		return nil, fmt.Errorf("vault kv get exited %d: %s", exitCode, hint)
	}
	out := strings.TrimRight(string(stdout), "\n")
	if out == "" {
		return nil, fmt.Errorf("vault kv get: empty output for %q field=%q", kvPath, field)
	}
	return []byte(out), nil
}

// classifyVaultError returns a sanitised hint from vault CLI stderr.
func classifyVaultError(stderr string) string {
	lower := strings.ToLower(stderr)
	switch {
	case strings.Contains(lower, "no secret") || strings.Contains(lower, "not found"):
		return "path not found"
	case strings.Contains(lower, "permission denied") || strings.Contains(lower, "403"):
		return "permission denied — check VAULT_TOKEN and policy"
	case strings.Contains(lower, "no value found at") && strings.Contains(lower, "field"):
		return "field not found in secret"
	case strings.Contains(lower, "vault_addr") || strings.Contains(lower, "server misbehaving"):
		return "cannot reach Vault server — check VAULT_ADDR"
	default:
		return "vault CLI error (run 'vault kv get' manually to diagnose)"
	}
}

// resolveBin returns the absolute binary path for the given scheme.
// Checks binOverrides first (test injection), then resolves from PATH.
// Returns ErrBinaryNotFound when LookPath fails and no override is set.
func (r *Resolver) resolveBin(scheme, defaultBin string) (string, error) {
	if override, ok := r.binOverrides[scheme]; ok {
		return override, nil
	}
	// Resolve to an absolute path so the exec runner's relative-path guard passes.
	abs, err := exec.LookPath(defaultBin)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrBinaryNotFound, defaultBin)
	}
	return abs, nil
}
