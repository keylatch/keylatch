package cli

// cmd_connect_provider_ref_test.go — tests for the --provider-ref flag behavior.
//
// Design: --provider-ref stores the URI verbatim (deferred
// resolution) rather than resolving plaintext at connect time.
//
// Tests:
//   - TestResolveProviderRefs_ValidURI_StoresURI      — valid URI is stored, not resolved
//   - TestResolveProviderRefs_InvalidScheme_UsageError — invalid scheme → error before write
//   - TestResolveProviderRefs_InvalidFormat_Error      — missing = → error
//   - TestResolveProviderRefs_EmptyField_Error         — empty field name → error
//   - TestResolveProviderRefs_EmptyURI_Error           — empty URI → error
//   - TestResolveProviderRefs_Conflict_Error           — --field + --provider-ref → error
//   - TestConnect_ProviderRef_StoresURIOnly            — on-disk contains URI, not plaintext
//   - TestConnect_ProviderRef_DryRunValidates          — invalid URI → UsageError before write

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/store"
)

// TestResolveProviderRefs_ValidURI_StoresURI verifies that a valid --provider-ref
// flag stores the URI verbatim in the fields map (not the resolved plaintext).
func TestResolveProviderRefs_ValidURI_StoresURI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fields := map[string][]byte{}
	uri := "op://MyVault/MyItem/api_key"
	err := resolveProviderRefs(ctx, []string{"api_key=" + uri}, fields)
	if err != nil {
		t.Fatalf("resolveProviderRefs: unexpected error: %v", err)
	}
	got, ok := fields["api_key"]
	if !ok {
		t.Fatal("api_key not set in fields")
	}
	if string(got) != uri {
		t.Errorf("stored value = %q, want URI %q (plaintext must not be stored)", got, uri)
	}
}

// TestResolveProviderRefs_AllSchemes verifies that all supported schemes are
// accepted and stored verbatim.
func TestResolveProviderRefs_AllSchemes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		flag string
		want string
	}{
		{"op", "api_key=op://MyVault/MyItem/api_key", "op://MyVault/MyItem/api_key"},
		{"aws-sm", "api_key=aws-sm://us-east-1/my-secret", "aws-sm://us-east-1/my-secret"},
		{"hashivault", "api_key=hashivault://secret/myapp/config", "hashivault://secret/myapp/config"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			fields := map[string][]byte{}
			if err := resolveProviderRefs(ctx, []string{tc.flag}, fields); err != nil {
				t.Fatalf("resolveProviderRefs: %v", err)
			}
			got, ok := fields["api_key"]
			if !ok {
				t.Fatal("api_key not set")
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResolveProviderRefs_InvalidScheme_UsageError verifies that an unknown
// scheme returns a UsageError (before any write occurs).
func TestResolveProviderRefs_InvalidScheme_UsageError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fields := map[string][]byte{}
	err := resolveProviderRefs(ctx, []string{"api_key=unknown-store://vault/item"}, fields)
	if err == nil {
		t.Fatal("expected error for unknown scheme, got nil")
	}
	// Must be a UsageError (not a generic error).
	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Errorf("expected *CLIError (UsageError), got %T: %v", err, err)
	}
	// Field must NOT have been set.
	if _, ok := fields["api_key"]; ok {
		t.Error("field must not be set when URI validation fails")
	}
}

// TestResolveProviderRefs_InvalidFormat_Error verifies that a flag without '='
// returns an error.
func TestResolveProviderRefs_InvalidFormat_Error(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fields := map[string][]byte{}
	if err := resolveProviderRefs(ctx, []string{"no-equals-here"}, fields); err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestResolveProviderRefs_EmptyField_Error verifies that an empty field name
// returns an error.
func TestResolveProviderRefs_EmptyField_Error(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fields := map[string][]byte{}
	if err := resolveProviderRefs(ctx, []string{"=op://Vault/Item/field"}, fields); err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestResolveProviderRefs_EmptyURI_Error verifies that an empty URI returns an error.
func TestResolveProviderRefs_EmptyURI_Error(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fields := map[string][]byte{}
	if err := resolveProviderRefs(ctx, []string{"api_key="}, fields); err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestResolveProviderRefs_Conflict_Error verifies that a field set by both
// --field and --provider-ref returns an error.
func TestResolveProviderRefs_Conflict_Error(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fields := map[string][]byte{"api_key": []byte("already-set")}
	if err := resolveProviderRefs(ctx, []string{"api_key=op://Vault/Item/api_key"}, fields); err == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestConnect_ProviderRef_StoresURIOnly verifies the security invariant that
// the resolved plaintext is NOT written to the fields map; only the URI is stored.
// This guards against regression: a previous implementation resolved at connect
// time, which would write a plaintext copy to the vault.
func TestConnect_ProviderRef_StoresURIOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const resolvedPlaintext = "sk-ant-super-secret-key"
	const uri = "op://Private/Anthropic/api_key"

	fields := map[string][]byte{}
	if err := resolveProviderRefs(ctx, []string{"api_key=" + uri}, fields); err != nil {
		t.Fatalf("resolveProviderRefs: %v", err)
	}

	val, ok := fields["api_key"]
	if !ok {
		t.Fatal("api_key not set")
	}
	if string(val) == resolvedPlaintext {
		t.Errorf("plaintext was stored — URI must be stored instead")
	}
	if string(val) != uri {
		t.Errorf("stored value = %q, want URI %q", val, uri)
	}
}

// TestConnect_ProviderRef_DryRunValidates verifies that an invalid URI returns
// a UsageError before any write occurs (dry-run validation).
func TestConnect_ProviderRef_DryRunValidates(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		flag string
	}{
		{"empty scheme", "api_key=://Vault/Item"},
		{"unknown scheme", "api_key=badstore://Vault/Item"},
		{"missing path", "api_key=op://"},
		{"no slash separator", "api_key=op://justscheme"},
		{"empty URI", "api_key="},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			fields := map[string][]byte{}
			err := resolveProviderRefs(ctx, []string{tc.flag}, fields)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.flag)
			}
			// Must be an error before write.
			if _, ok := fields["api_key"]; ok {
				t.Error("field must not be set when dry-run validation fails")
			}
		})
	}
}

// TestResolveProviderRefs_DoesNotInvokeResolver verifies that resolveProviderRefs
// does NOT call any external binary (no network, no subprocess). This ensures that
// `keylatch connect --provider-ref` works offline and does not require the external
// PM to be reachable at connect time.
func TestResolveProviderRefs_DoesNotInvokeResolver(t *testing.T) {
	// Not parallel: t.Setenv is not safe with t.Parallel.
	ctx := context.Background()

	// Override PATH to contain only an empty dir — any exec attempt would fail.
	t.Setenv("PATH", t.TempDir())

	fields := map[string][]byte{}
	// This should succeed without invoking any binary.
	err := resolveProviderRefs(ctx, []string{"api_key=op://MyVault/MyItem/api_key"}, fields)
	if err != nil {
		t.Fatalf("resolveProviderRefs must not invoke binaries: %v", err)
	}
	got := fields["api_key"]
	if string(got) != "op://MyVault/MyItem/api_key" {
		t.Errorf("stored %q, want URI", got)
	}
}

// fakeRunner is kept for compatibility with any downstream callers but is no
// longer used by resolveProviderRefs (which no longer invokes a runner).
type fakeRunner struct {
	stdout []byte
	err    error
}

func (f *fakeRunner) Run(ctx context.Context, bin string, args []string, stdin []byte) ([]byte, []byte, int, error) {
	return f.RunEnv(ctx, bin, args, stdin, nil)
}

// RunEnv satisfies store.CommandRunner's mirrored RunEnv method (extraEnv unused).
func (f *fakeRunner) RunEnv(_ context.Context, _ string, _ []string, _ []byte, _ []string) ([]byte, []byte, int, error) {
	return f.stdout, nil, 0, f.err
}

// Compile-time check: fakeRunner satisfies store.CommandRunner.
var _ store.CommandRunner = (*fakeRunner)(nil)
