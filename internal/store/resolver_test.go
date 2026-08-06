package store_test

// resolver_test.go — tests for URI dispatch.
//
// Tests cover:
//   - op:// → resolveOP calls `op read --no-newline op://...`
//   - aws-sm:// → resolveAWSSM calls `aws secretsmanager get-secret-value`
//   - hashivault:// → resolveHashiVault calls `vault kv get -field=...`
//   - Unknown scheme → ErrUnsupportedScheme
//   - Empty ref → ErrEmptyRef
//   - CLI exit non-zero → error with sanitised hint

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	internalexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/store"
)

// Compile-time assertion: mockRunner must satisfy the same CommandRunner interface
// as internal/exec.CommandRunner, confirming the two interfaces are in sync (S-03).
var _ internalexec.CommandRunner = (*mockRunner)(nil)

// --- Mock CommandRunner ---

// capturedCall records one execution.
type capturedCall struct {
	bin  string
	args []string
}

// mockRunner records calls and returns preconfigured responses.
type mockRunner struct {
	mu       sync.Mutex
	calls    []capturedCall
	stdout   []byte
	stderr   []byte
	exitCode int
	err      error
}

func (m *mockRunner) Run(ctx context.Context, bin string, args []string, stdin []byte) ([]byte, []byte, int, error) {
	return m.RunEnv(ctx, bin, args, stdin, nil)
}

// RunEnv satisfies store.CommandRunner's mirrored RunEnv method. extraEnv is
// ignored — no resolver_test.go case exercises env injection.
func (m *mockRunner) RunEnv(_ context.Context, bin string, args []string, _ []byte, _ []string) ([]byte, []byte, int, error) {
	m.mu.Lock()
	m.calls = append(m.calls, capturedCall{bin: bin, args: args})
	m.mu.Unlock()
	return m.stdout, m.stderr, m.exitCode, m.err
}

func (m *mockRunner) lastCall() (capturedCall, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.calls) == 0 {
		return capturedCall{}, false
	}
	return m.calls[len(m.calls)-1], true
}

// --- Helper ---

func resolverWithMock(t *testing.T, scheme string, mockBin string, r *mockRunner) *store.Resolver {
	t.Helper()
	return store.NewResolver(r).WithBinOverride(scheme, mockBin)
}

// --- op:// tests ---

func TestResolver_OP_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{
		stdout:   []byte("sk-ant-test-api-key-value"),
		exitCode: 0,
	}

	r := resolverWithMock(t, "op", "/fake/op", runner)
	got, err := r.Resolve(ctx, "op://MyVault/MyItem/api_key")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "sk-ant-test-api-key-value" {
		t.Errorf("got %q, want %q", got, "sk-ant-test-api-key-value")
	}

	// Verify the op command received the correct arguments.
	call, ok := runner.lastCall()
	if !ok {
		t.Fatal("no calls captured")
	}
	if call.bin != "/fake/op" {
		t.Errorf("bin = %q, want /fake/op", call.bin)
	}
	wantRef := "op://MyVault/MyItem/api_key"
	found := false
	for _, arg := range call.args {
		if arg == wantRef {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("op command args %v do not contain %q", call.args, wantRef)
	}
	// Must use "read" subcommand.
	if len(call.args) == 0 || call.args[0] != "read" {
		t.Errorf("first op arg must be 'read', got %v", call.args)
	}
}

func TestResolver_OP_NonZeroExit_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{
		stderr:   []byte("not found: item does not exist"),
		exitCode: 1,
	}

	r := resolverWithMock(t, "op", "/fake/op", runner)
	_, err := r.Resolve(ctx, "op://MyVault/BadItem/api_key")
	if err == nil {
		t.Fatal("expected error for non-zero exit, got nil")
	}
}

func TestResolver_OP_EmptyOutput_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{
		stdout:   []byte(""),
		exitCode: 0,
	}

	r := resolverWithMock(t, "op", "/fake/op", runner)
	_, err := r.Resolve(ctx, "op://MyVault/Item/field")
	if err == nil {
		t.Fatal("expected error for empty output, got nil")
	}
}

// --- aws-sm:// tests ---

func TestResolver_AWSSM_HappyPath_PlainSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{
		stdout:   []byte("my-plain-secret-value\n"),
		exitCode: 0,
	}

	r := resolverWithMock(t, "aws-sm", "/fake/aws", runner)
	got, err := r.Resolve(ctx, "aws-sm://us-east-1/my-secret")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "my-plain-secret-value" {
		t.Errorf("got %q, want %q", got, "my-plain-secret-value")
	}

	call, ok := runner.lastCall()
	if !ok {
		t.Fatal("no calls captured")
	}
	// Verify region and secret-id are passed.
	argStr := fmt.Sprintf("%v", call.args)
	if !containsAll(call.args, "--region", "us-east-1", "--secret-id", "my-secret") {
		t.Errorf("aws args %s missing expected flags", argStr)
	}
}

func TestResolver_AWSSM_HappyPath_JSONKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// SecretString contains JSON; we request the "api_key" field.
	runner := &mockRunner{
		stdout:   []byte(`{"api_key":"sk-openai-abc123","model":"gpt-4"}` + "\n"),
		exitCode: 0,
	}

	r := resolverWithMock(t, "aws-sm", "/fake/aws", runner)
	got, err := r.Resolve(ctx, "aws-sm://eu-west-1/myapp/config#api_key")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "sk-openai-abc123" {
		t.Errorf("got %q, want %q", got, "sk-openai-abc123")
	}
}

func TestResolver_AWSSM_MissingJSONKey_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{
		stdout:   []byte(`{"other_field":"value"}` + "\n"),
		exitCode: 0,
	}

	r := resolverWithMock(t, "aws-sm", "/fake/aws", runner)
	_, err := r.Resolve(ctx, "aws-sm://us-east-1/myapp#missing_key")
	if err == nil {
		t.Fatal("expected error for missing JSON key, got nil")
	}
}

func TestResolver_AWSSM_NonZeroExit_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{
		stderr:   []byte("ResourceNotFoundException: Secrets Manager can't find the specified secret"),
		exitCode: 254,
	}

	r := resolverWithMock(t, "aws-sm", "/fake/aws", runner)
	_, err := r.Resolve(ctx, "aws-sm://us-east-1/nonexistent-secret")
	if err == nil {
		t.Fatal("expected error for non-zero exit, got nil")
	}
}

func TestResolver_AWSSM_BadURI_MissingRegion_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{}

	r := resolverWithMock(t, "aws-sm", "/fake/aws", runner)
	_, err := r.Resolve(ctx, "aws-sm://nosecrethere")
	if err == nil {
		t.Fatal("expected error for missing region/secret separation, got nil")
	}
}

// --- hashivault:// tests ---

func TestResolver_HashiVault_HappyPath_DefaultField(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{
		stdout:   []byte("vault-secret-value\n"),
		exitCode: 0,
	}

	r := resolverWithMock(t, "hashivault", "/fake/vault", runner)
	got, err := r.Resolve(ctx, "hashivault://secret/myapp/config")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "vault-secret-value" {
		t.Errorf("got %q, want %q", got, "vault-secret-value")
	}

	call, ok := runner.lastCall()
	if !ok {
		t.Fatal("no calls captured")
	}
	// Default field is "value".
	found := false
	for _, a := range call.args {
		if a == "-field=value" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("vault args %v must contain -field=value for default field", call.args)
	}
}

func TestResolver_HashiVault_HappyPath_ExplicitField(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{
		stdout:   []byte("ghp_test_token\n"),
		exitCode: 0,
	}

	r := resolverWithMock(t, "hashivault", "/fake/vault", runner)
	got, err := r.Resolve(ctx, "hashivault://kv/myapp/github#token")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "ghp_test_token" {
		t.Errorf("got %q, want %q", got, "ghp_test_token")
	}

	call, ok := runner.lastCall()
	if !ok {
		t.Fatal("no calls captured")
	}
	found := false
	for _, a := range call.args {
		if a == "-field=token" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("vault args %v must contain -field=token", call.args)
	}
}

func TestResolver_HashiVault_NonZeroExit_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{
		stderr:   []byte("Error making API request: No secret at path"),
		exitCode: 2,
	}

	r := resolverWithMock(t, "hashivault", "/fake/vault", runner)
	_, err := r.Resolve(ctx, "hashivault://secret/missing/path")
	if err == nil {
		t.Fatal("expected error for non-zero exit, got nil")
	}
}

// --- Scheme / validation tests ---

func TestResolver_UnknownScheme_ReturnsErrUnsupportedScheme(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{}

	r := store.NewResolver(runner)
	_, err := r.Resolve(ctx, "unknown-store://path/to/secret")
	if err == nil {
		t.Fatal("expected error for unknown scheme, got nil")
	}
	if !errors.Is(err, store.ErrUnsupportedScheme) {
		t.Errorf("expected ErrUnsupportedScheme, got %v", err)
	}
}

func TestResolver_EmptyRef_ReturnsErrEmptyRef(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{}

	r := store.NewResolver(runner)
	_, err := r.Resolve(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty ref, got nil")
	}
	if !errors.Is(err, store.ErrEmptyRef) {
		t.Errorf("expected ErrEmptyRef, got %v", err)
	}
}

func TestResolver_NoScheme_ReturnsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runner := &mockRunner{}

	r := store.NewResolver(runner)
	_, err := r.Resolve(ctx, "just-a-plain-value")
	if err == nil {
		t.Fatal("expected error for ref without scheme, got nil")
	}
}

// --- Binary-not-found tests (C-01) ---

// TestResolver_BinaryNotFound_SentinelWrapped verifies that when a binary cannot be
// found on PATH, Resolve returns an error wrapping ErrBinaryNotFound.
// PATH is cleared via t.Setenv so LookPath reliably fails.
func TestResolver_BinaryNotFound_SentinelWrapped(t *testing.T) {
	// Not parallel: t.Setenv is not safe with t.Parallel.
	ctx := context.Background()

	// Clear PATH so exec.LookPath cannot find any binary.
	t.Setenv("PATH", "")

	runner := &mockRunner{}

	schemes := []struct {
		uri string
	}{
		{"op://Vault/Item/field"},
		{"aws-sm://us-east-1/my-secret"},
		{"hashivault://secret/myapp#field"},
	}

	for _, tc := range schemes {
		// A resolver with no override falls through to LookPath, which will fail
		// because PATH is empty.
		r := store.NewResolver(runner)
		_, err := r.Resolve(ctx, tc.uri)
		if err == nil {
			t.Errorf("Resolve(%q): expected ErrBinaryNotFound, got nil", tc.uri)
			continue
		}
		if !errors.Is(err, store.ErrBinaryNotFound) {
			t.Errorf("Resolve(%q): expected error wrapping ErrBinaryNotFound, got: %v", tc.uri, err)
		}
	}
}

func containsAll(args []string, wants ...string) bool {
	for _, w := range wants {
		found := false
		for _, a := range args {
			if a == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
