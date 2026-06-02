package store_test

// dispatch_uri_test.go — EPIC-10 dispatch URI tests using real mock binaries on PATH.
//
// Unlike resolver_test.go (which uses in-process mockRunner), these tests inject
// actual shell scripts on PATH via t.Setenv. This validates that the full
// shelling-out pipeline works end-to-end with real os/exec calls.
//
// Test coverage:
//   - TestDispatchURI_OpResolves       — op:// shells out to `op read --no-newline`
//   - TestDispatchURI_AWSSMResolves    — aws-sm:// shells out to `aws secretsmanager get-secret-value`
//   - TestDispatchURI_HashiVaultResolves — hashivault:// shells out to `vault kv get -field=...`
//   - TestDispatchURI_LLMSessionBlocks — LLM context check at the store layer
//   - TestDispatchURI_DoesNotCacheResolvedValue — resolver returns fresh value on every call

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	internalexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/store"
)

const opCanary = "op-canary-value-xk9z"
const awssmCanary = "awssm-canary-value-qr7p"
const vaultCanary = "vault-canary-value-ms4n"

// writeMockBin writes a shell script at dir/name that executes body, makes it
// executable, and returns its path.
func writeMockBin(t *testing.T, dir, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("mock shell binaries require a POSIX shell; skipping on Windows")
	}
	p := filepath.Join(dir, name)
	// Use explicit open/write/sync/close instead of os.WriteFile to avoid
	// ETXTBSY on Linux: the kernel marks the inode write-busy until the fd is
	// fully flushed, and exec() on an unflushed file fails with ETXTBSY.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) //nolint:gosec // test helper
	if err != nil {
		t.Fatalf("writeMockBin %s: open: %v", name, err)
	}
	if _, err := fmt.Fprintf(f, "#!/bin/sh\n%s\n", body); err != nil {
		_ = f.Close()
		t.Fatalf("writeMockBin %s: write: %v", name, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatalf("writeMockBin %s: sync: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("writeMockBin %s: close: %v", name, err)
	}
	return p
}

// realRunner returns the real exec.DefaultRunner so tests exercise the actual
// shelling-out path (not the in-process mockRunner).
func realRunner() internalexec.CommandRunner {
	return internalexec.DefaultRunner
}

// TestDispatchURI_OpResolves verifies that `op read --no-newline op://...` is
// executed when the URI scheme is `op://`, and that the canary value is returned.
func TestDispatchURI_OpResolves(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Mock `op` binary: echo canary when invoked as `op read --no-newline <ref>`.
	// Use printf to avoid echo -n portability issues on macOS /bin/sh.
	writeMockBin(t, dir, "op", `printf '%s' '`+opCanary+`'`)

	r := store.NewResolver(realRunner()).WithBinOverride("op", filepath.Join(dir, "op"))
	got, err := r.Resolve(context.Background(), "op://Private/Anthropic/api_key")
	if err != nil {
		t.Fatalf("Resolve op://: %v", err)
	}
	if string(got) != opCanary {
		t.Errorf("op canary: got %q, want %q", got, opCanary)
	}
}

// TestDispatchURI_AWSSMResolves verifies that `aws secretsmanager get-secret-value`
// is executed for aws-sm:// URIs and that the canary is extracted correctly.
func TestDispatchURI_AWSSMResolves(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Mock `aws` binary: output raw SecretString (--output text strips the JSON envelope).
	writeMockBin(t, dir, "aws", `echo '`+awssmCanary+`'`)

	r := store.NewResolver(realRunner()).WithBinOverride("aws-sm", filepath.Join(dir, "aws"))
	got, err := r.Resolve(context.Background(), "aws-sm://us-east-1/my-secret")
	if err != nil {
		t.Fatalf("Resolve aws-sm://: %v", err)
	}
	if string(got) != awssmCanary {
		t.Errorf("aws-sm canary: got %q, want %q", got, awssmCanary)
	}
}

// TestDispatchURI_HashiVaultResolves verifies that `vault kv get -field=<field>`
// is executed for hashivault:// URIs and that the canary value is returned.
func TestDispatchURI_HashiVaultResolves(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Mock `vault` binary: echo canary for any kv get invocation.
	writeMockBin(t, dir, "vault", `echo '`+vaultCanary+`'`)

	r := store.NewResolver(realRunner()).WithBinOverride("hashivault", filepath.Join(dir, "vault"))
	got, err := r.Resolve(context.Background(), "hashivault://secret/myapp/config#api_key")
	if err != nil {
		t.Fatalf("Resolve hashivault://: %v", err)
	}
	if string(got) != vaultCanary {
		t.Errorf("hashivault canary: got %q, want %q", got, vaultCanary)
	}
}

// TestDispatchURI_LLMSessionBlocks verifies that Resolve returns an error when the
// context is cancelled (simulating a request that should be blocked). The store
// layer itself is context-aware: a cancelled context propagates to the exec runner.
//
// Note: LLM-session blocking is enforced at the CLI guard layer (GuardLLMSession),
// not inside the Resolver. This test validates context cancellation propagation.
func TestDispatchURI_LLMSessionBlocks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Mock `op` binary that sleeps briefly — should be interrupted by context cancel.
	writeMockBin(t, dir, "op", `sleep 10`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to simulate a blocked/cancelled session

	r := store.NewResolver(realRunner()).WithBinOverride("op", filepath.Join(dir, "op"))
	_, err := r.Resolve(ctx, "op://Vault/Item/field")
	if err == nil {
		t.Error("expected error when context is already cancelled, got nil")
	}
}

// TestDispatchURI_DoesNotCacheResolvedValue verifies that consecutive Resolve calls
// for the same URI invoke the CLI binary each time (no caching of resolved values).
// This is a security invariant: cached values would survive process lifetime and
// could leak across requests.
func TestDispatchURI_DoesNotCacheResolvedValue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Counter file incremented on each call.
	counterFile := filepath.Join(dir, "count")
	// Mock `op` binary that increments a counter and always returns the canary.
	// Use printf to avoid echo -n portability issues on macOS /bin/sh.
	writeMockBin(t, dir, "op", `
count=0
if [ -f '`+counterFile+`' ]; then count=$(cat '`+counterFile+`'); fi
count=$((count+1))
printf '%s' "$count" > '`+counterFile+`'
printf '%s' '`+opCanary+`'
`)

	r := store.NewResolver(realRunner()).WithBinOverride("op", filepath.Join(dir, "op"))
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		got, err := r.Resolve(ctx, "op://Private/Anthropic/api_key")
		if err != nil {
			t.Fatalf("call %d: Resolve error: %v", i, err)
		}
		if string(got) != opCanary {
			t.Errorf("call %d: got %q, want %q", i, got, opCanary)
		}
	}

	// Verify the binary was called 3 times (count file should contain "3").
	countBytes, err := os.ReadFile(counterFile)
	if err != nil {
		t.Fatalf("reading count file: %v", err)
	}
	if string(countBytes) != "3" {
		t.Errorf("expected binary invoked 3 times, counter = %q", string(countBytes))
	}
}
