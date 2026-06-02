package store_test

// dispatch_uri_test.go — EPIC-10 dispatch URI tests using real mock binaries on PATH.
//
// Unlike resolver_test.go (which uses in-process mockRunner), these tests inject
// actual shell scripts via WithBinOverride. This validates that the full
// shelling-out pipeline works end-to-end with real os/exec calls.
//
// ETXTBSY note (Linux / GitHub Actions):
//   On Linux, freshly-written shell scripts can yield ETXTBSY from execve even
//   after explicit close+fsync. The root cause is a race in the kernel's VFS
//   write-count bookkeeping when files are created and executed in rapid
//   succession. To sidestep this entirely, the three "resolver" tests use the
//   pre-existing scripts in tests/mocks/ (already on disk, never freshly
//   written). The two custom-behaviour mocks (sleep, counter) are created once
//   in TestMain before any test runs, giving the kernel time to settle.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	internalexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/store"
)

// Canary values must match tests/mocks/*-mock.sh.
const opCanary = "OP_MOCK_CANARY_VALUE_TEST"
const awssmCanary = "AWSSM_MOCK_CANARY_VALUE_TEST"
const vaultCanary = "VAULT_MOCK_CANARY_VALUE_TEST"

// Package-level paths to mock binaries created in TestMain.
var (
	mockOpBin      string // tests/mocks/op-mock.sh
	mockAwsBin     string // tests/mocks/aws-sm-mock.sh
	mockVaultBin   string // tests/mocks/vault-mock.sh
	mockSleepOpBin string // sleep 10 mock for LLMSessionBlocks
	mockCountOpBin string // counter mock for DoesNotCacheResolvedValue
)

func TestMain(m *testing.M) {
	if runtime.GOOS == "windows" {
		// Shell-script mocks require a POSIX shell; skip setup on Windows.
		os.Exit(m.Run())
	}

	// Locate the repo root from the package directory (internal/store → ../..).
	wd, err := os.Getwd()
	if err != nil {
		panic("TestMain: getwd: " + err.Error())
	}
	repoRoot := findRepoRoot(wd)

	mockOpBin = filepath.Join(repoRoot, "tests/mocks/op-mock.sh")
	mockAwsBin = filepath.Join(repoRoot, "tests/mocks/aws-sm-mock.sh")
	mockVaultBin = filepath.Join(repoRoot, "tests/mocks/vault-mock.sh")

	// Create custom mocks ONCE before any test runs.
	// Writing before m.Run() means these files are "old" by the time a test
	// calls execve, eliminating the kernel ETXTBSY race.
	tmpDir, err := os.MkdirTemp("", "keylatch-store-mocks-*")
	if err != nil {
		panic("TestMain: mkdirtemp: " + err.Error())
	}
	defer os.RemoveAll(tmpDir)

	mockSleepOpBin = writeMockBinGlobal(filepath.Join(tmpDir, "op-sleep"), "sleep 10")
	mockCountOpBin = writeMockBinGlobal(filepath.Join(tmpDir, "op-counter"), `
count=0
if [ -n "$MOCK_COUNTER_FILE" ] && [ -f "$MOCK_COUNTER_FILE" ]; then
  count=$(cat "$MOCK_COUNTER_FILE")
fi
count=$((count+1))
if [ -n "$MOCK_COUNTER_FILE" ]; then
  printf '%s' "$count" > "$MOCK_COUNTER_FILE"
fi
printf '%s' '`+opCanary+`'
`)

	os.Exit(m.Run())
}

// writeMockBinGlobal writes a shell script at path p and returns p.
// Called from TestMain only — panic on error since we have no *testing.T.
func writeMockBinGlobal(p, body string) string {
	content := []byte("#!/bin/sh\n" + body + "\n")
	if err := os.WriteFile(p, content, 0o755); err != nil { //nolint:gosec // test helper
		panic("writeMockBinGlobal " + p + ": " + err.Error())
	}
	return p
}

// findRepoRoot walks up from dir until it finds a go.mod file.
func findRepoRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("findRepoRoot: could not locate go.mod from " + dir)
		}
		dir = parent
	}
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
	if runtime.GOOS == "windows" {
		t.Skip("mock shell binaries require a POSIX shell; skipping on Windows")
	}

	r := store.NewResolver(realRunner()).WithBinOverride("op", mockOpBin)
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
	if runtime.GOOS == "windows" {
		t.Skip("mock shell binaries require a POSIX shell; skipping on Windows")
	}

	r := store.NewResolver(realRunner()).WithBinOverride("aws-sm", mockAwsBin)
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
	if runtime.GOOS == "windows" {
		t.Skip("mock shell binaries require a POSIX shell; skipping on Windows")
	}

	r := store.NewResolver(realRunner()).WithBinOverride("hashivault", mockVaultBin)
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
	if runtime.GOOS == "windows" {
		t.Skip("mock shell binaries require a POSIX shell; skipping on Windows")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to simulate a blocked/cancelled session

	r := store.NewResolver(realRunner()).WithBinOverride("op", mockSleepOpBin)
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
	// Not parallel: uses t.Setenv which is incompatible with t.Parallel().
	if runtime.GOOS == "windows" {
		t.Skip("mock shell binaries require a POSIX shell; skipping on Windows")
	}

	// Counter file: each exec of mockCountOpBin increments it via $MOCK_COUNTER_FILE.
	counterFile := filepath.Join(t.TempDir(), "count")
	t.Setenv("MOCK_COUNTER_FILE", counterFile)

	r := store.NewResolver(realRunner()).WithBinOverride("op", mockCountOpBin)
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
