package runner_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	internalexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/store"
	"github.com/keylatch/keylatch/internal/vault/meta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBackend is an in-memory Backend for tests.
type mockBackend struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMockBackend() *mockBackend {
	return &mockBackend{data: map[string][]byte{}}
}

func (m *mockBackend) Name() string { return "mock" }

func (m *mockBackend) Capabilities() []backend.Capability { return nil }

func (m *mockBackend) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, backend.Meta{Path: path, Backend: "mock", Version: 1}, nil
}

func (m *mockBackend) Set(_ context.Context, path string, value []byte, _ backend.Meta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[path] = cp
	return nil
}

func (m *mockBackend) Delete(_ context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[path]; !ok {
		return backend.ErrNotFound
	}
	delete(m.data, path)
	return nil
}

func (m *mockBackend) List(_ context.Context, _ string) ([]backend.Entry, error) {
	return nil, nil
}

func (m *mockBackend) GetMeta(_ context.Context, _ string) (meta.Meta, error) {
	return meta.Meta{}, backend.ErrNotSupported
}

func (m *mockBackend) SetMeta(_ context.Context, _ string, _ meta.Meta) error {
	return backend.ErrNotSupported
}

func (m *mockBackend) ListMeta(_ context.Context, _ string) ([]meta.Meta, error) {
	return nil, backend.ErrNotSupported
}

func (m *mockBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

func (m *mockBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

func (m *mockBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

func (m *mockBackend) ID() string { return "mock" }

func (m *mockBackend) Close() error { return nil }

// secretPath mirrors the canonical lookup path used by ProcessRunner.
// Format: namespace/category/provider/field. The account segment is dropped in v1.0.0.
func secretPath(namespace, category, provider, field string) string {
	if category == "" {
		category = "ai"
	}
	return fmt.Sprintf("%s/%s/%s/%s", namespace, category, provider, field)
}

// TestProcessRunner_EmptyAllowlistDenies verifies that ErrCommandNotAllowed is
// returned when AllowedCommandPrefixes is empty.
func TestProcessRunner_EmptyAllowlistDenies(t *testing.T) {
	b := newMockBackend()
	pr := runner.ProcessRunner{Backend: b}

	conn := runner.Connection{
		Name:                   "openrouter",
		AllowedCommandPrefixes: []string{},
	}

	_, err := pr.Run(context.Background(), conn, []string{"env"}, runner.RunOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, runner.ErrCommandNotAllowed, "empty allowlist must deny all commands")
}

// TestProcessRunner_CredentialEnvVarPresent verifies that the injected
// credential env var is visible in the subprocess environment and that its
// value appears in the captured output.
func TestProcessRunner_CredentialEnvVarPresent(t *testing.T) {
	b := newMockBackend()

	// Store the credential at the path ProcessRunner will look up.
	credValue := "test-api-key-xyz"
	path := secretPath("default", "ai", "openrouter", "api_key")
	err := b.Set(context.Background(), path, []byte(credValue), backend.Meta{
		Path:    path,
		Backend: "mock",
		Version: 1,
	})
	require.NoError(t, err)

	var buf strings.Builder
	pr := runner.ProcessRunner{
		Backend: b,
		Stdout:  &buf,
	}

	conn := runner.Connection{
		Name:                   "openrouter",
		AllowedCommandPrefixes: []string{"sh ", "env"},
	}

	// Run `sh -c 'echo $OPENROUTER_API_KEY'` and check that the credential
	// value appears in the captured output.
	_, err = pr.Run(
		context.Background(),
		conn,
		[]string{"sh", "-c", "echo $OPENROUTER_API_KEY"},
		runner.RunOptions{},
	)
	require.NoError(t, err)
	assert.True(t,
		strings.Contains(buf.String(), credValue),
		"expected output to contain credential value %q, got: %q", credValue, buf.String(),
	)
}

// TestProcessRunner_AllowlistExactMatch verifies the allowlist bypass fix (C-1):
//   - "node" in allowlist → "node" allowed, "node_modules/.bin/evil" denied, "nodejs" denied
//   - "python3" in allowlist → "python3.12" allowed (dot-suffix rule)
func TestProcessRunner_AllowlistExactMatch(t *testing.T) {
	b := newMockBackend()
	// Store a credential so the allowlist check is the deciding factor.
	path := secretPath("default", "ai", "openrouter", "api_key")
	err := b.Set(context.Background(), path, []byte("sk-or-test-value"), backend.Meta{
		Path: path, Backend: "mock", Version: 1,
	})
	require.NoError(t, err)

	cases := []struct {
		name      string
		allowlist []string
		command   []string
		wantAllow bool
	}{
		{
			name:      "exact match allowed",
			allowlist: []string{"node"},
			command:   []string{"node", "app.js"},
			wantAllow: true,
		},
		{
			name:      "bypass attempt denied - node_modules",
			allowlist: []string{"node"},
			command:   []string{"node_modules/.bin/evil"},
			wantAllow: false,
		},
		{
			name:      "prefix-only match denied - nodejs vs node",
			allowlist: []string{"node"},
			command:   []string{"nodejs", "app.js"},
			wantAllow: false,
		},
		{
			name:      "dot-suffix allowed - python3.12 matches python3",
			allowlist: []string{"python3"},
			command:   []string{"python3.12", "script.py"},
			wantAllow: true,
		},
		{
			name:      "trailing space in allowlist entry trimmed correctly",
			allowlist: []string{"node "},
			command:   []string{"node", "app.js"},
			wantAllow: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			pr := runner.ProcessRunner{
				Backend: b,
				Stdout:  &buf,
				Stderr:  &strings.Builder{},
			}
			conn := runner.Connection{
				Name:                   "openrouter",
				AllowedCommandPrefixes: tc.allowlist,
			}
			_, err := pr.Run(context.Background(), conn, tc.command, runner.RunOptions{})
			if tc.wantAllow {
				// The command may fail for reasons unrelated to the allowlist
				// (e.g. binary not found), but it must not be ErrCommandNotAllowed.
				if err != nil {
					assert.False(t, errors.Is(err, runner.ErrCommandNotAllowed),
						"command %v should not be denied by allowlist", tc.command)
				}
			} else {
				require.Error(t, err)
				assert.ErrorIs(t, err, runner.ErrCommandNotAllowed,
					"command %v should be denied by allowlist %v", tc.command, tc.allowlist)
			}
		})
	}
}

// TestProcessRunner_RedactionAppliedToOutput verifies H-3: credential values in
// subprocess output are replaced with "****" by the redactingWriter.
// Uses the "openrouter" provider whose redaction pattern is sk-or-[A-Za-z0-9\-_]{20,}.
func TestProcessRunner_RedactionAppliedToOutput(t *testing.T) {
	b := newMockBackend()

	// The credential value matches the openrouter redaction pattern.
	credValue := "sk-or-v1-abcdefghijklmnopqrstuvwxyz12"
	path := secretPath("default", "ai", "openrouter", "api_key")
	err := b.Set(context.Background(), path, []byte(credValue), backend.Meta{
		Path: path, Backend: "mock", Version: 1,
	})
	require.NoError(t, err)

	var outBuf, errBuf strings.Builder
	pr := runner.ProcessRunner{
		Backend: b,
		Stdout:  &outBuf,
		Stderr:  &errBuf,
	}

	conn := runner.Connection{
		Name:                   "openrouter",
		AllowedCommandPrefixes: []string{"sh"},
	}

	// Print the credential value via the subprocess — the redacting writer should mask it.
	_, err = pr.Run(
		context.Background(),
		conn,
		[]string{"sh", "-c", fmt.Sprintf("printf '%%s' '%s'", credValue)},
		runner.RunOptions{},
	)
	require.NoError(t, err)

	output := outBuf.String()
	assert.NotContains(t, output, credValue,
		"raw credential value must not appear in subprocess output (H-3)")
	assert.Contains(t, output, "****",
		"redacted placeholder must appear in subprocess output")
}

// TestProcessRunner_BackendNotFound verifies that backend.ErrNotFound is
// returned (wrapped) when the credential is absent from the backend.
func TestProcessRunner_BackendNotFound(t *testing.T) {
	b := newMockBackend()
	// Do NOT store any credential — backend will return ErrNotFound.

	pr := runner.ProcessRunner{Backend: b}

	conn := runner.Connection{
		Name:                   "openrouter",
		AllowedCommandPrefixes: []string{"sh "},
	}

	_, err := pr.Run(
		context.Background(),
		conn,
		[]string{"sh", "-c", "echo hello"},
		runner.RunOptions{},
	)

	require.Error(t, err)
	assert.True(t,
		errors.Is(err, backend.ErrNotFound),
		"expected wrapped backend.ErrNotFound, got: %v", err)
	assert.False(t,
		strings.Contains(err.Error(), "test-api-key"),
		"error message must not contain credential value",
	)
}

// TestProcessRunner_URIResolution verifies that when a credential field contains
// a provider-ref URI (e.g. op://...), the runtime resolves it via the injected
// resolver and injects the resolved value into the subprocess environment —
// not the raw URI string.
func TestProcessRunner_URIResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test requires #!/bin/sh executable — not supported on Windows")
	}
	// Build a tiny mock binary that prints a fixed resolved value to stdout.
	// We use a real subprocess so the resolver actually shells out.
	dir := t.TempDir()
	mockBin := filepath.Join(dir, "op")
	resolvedValue := "resolved-op-api-key-value"

	// Write a script that prints the resolved value regardless of args.
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\n", resolvedValue)
	require.NoError(t, os.WriteFile(mockBin, []byte(script), 0o755))

	// Sanity-check that the mock binary is executable.
	out, err := exec.Command(mockBin).Output()
	require.NoError(t, err, "mock binary must be executable")
	require.Equal(t, resolvedValue, string(out))

	// Set up the backend with a URI-valued credential.
	b := newMockBackend()
	uri := "op://MyVault/MyItem/api_key"
	path := secretPath("default", "ai", "openrouter", "api_key")
	require.NoError(t, b.Set(context.Background(), path, []byte(uri), backend.Meta{
		Path: path, Backend: "mock", Version: 1,
	}))

	// Build a resolver with the mock binary injected for the "op" scheme.
	// Use a real exec runner (internalexec.DefaultRunner) because the mock
	// binary is a real executable that requires os/exec to run.
	resolver := store.NewResolver(internalexec.DefaultRunner).WithBinOverride("op", mockBin)

	var outBuf strings.Builder
	pr := runner.ProcessRunner{
		Backend:  b,
		Stdout:   &outBuf,
		Stderr:   &strings.Builder{},
		Resolver: resolver,
	}

	conn := runner.Connection{
		Name:                   "openrouter",
		AllowedCommandPrefixes: []string{"sh"},
	}

	// Run a subprocess that prints the injected OPENROUTER_API_KEY value.
	_, err = pr.Run(
		context.Background(),
		conn,
		[]string{"sh", "-c", "printf '%s' \"$OPENROUTER_API_KEY\""},
		runner.RunOptions{},
	)
	require.NoError(t, err)

	got := outBuf.String()
	assert.Equal(t, resolvedValue, got,
		"subprocess must receive the resolved value, not the URI")
	assert.NotContains(t, got, "op://",
		"URI must not be injected verbatim into the subprocess environment")
}
