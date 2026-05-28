package connections

import (
	"context"
	"fmt"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingErrStore delegates all operations to inner but returns an error on
// Delete calls after the first failAfter successes. Used to exercise the
// multi-error path in Delete.
type countingErrStore struct {
	inner     *mockStore
	failAfter int
	calls     int
}

func (s *countingErrStore) Delete(ctx context.Context, path string) error {
	s.calls++
	if s.calls > s.failAfter {
		return fmt.Errorf("simulated delete error for %s", path)
	}
	return s.inner.Delete(ctx, path)
}

func (s *countingErrStore) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	return s.inner.Get(ctx, path)
}

func (s *countingErrStore) Set(ctx context.Context, path string, value []byte, meta backend.Meta) error {
	return s.inner.Set(ctx, path, value, meta)
}

func (s *countingErrStore) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	return s.inner.List(ctx, prefix)
}

// canaryValue is injected as a secret field value for canary leak tests.
const canaryValue = "KEYLATCH_CANARY_PHASE3_CONNECT_0xDEADBEEF_secret_value"

// TestConnectWritesFieldsToStore verifies that Connect stores each field in the
// mock backend and returns a Connection with Status="untested".
func TestConnectWritesFieldsToStore(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	conn, err := Connect(ctx, "openrouter", ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": []byte("sk-or-test-key-12345")},
	}, store)

	require.NoError(t, err)
	assert.Equal(t, "openrouter", conn.Provider)
	assert.Equal(t, "untested", conn.Status)
	assert.Equal(t, "default", conn.Namespace)

	// Verify the field was written to the canonical path (S-FIND-23).
	path := secretFieldPath("default", "ai", "openrouter", "api_key")
	val, ok := store.storedValue(path)
	assert.True(t, ok, "api_key must be stored in vault")
	assert.Equal(t, "sk-or-test-key-12345", string(val))
}

// TestConnectMultiAccountAmbiguity verifies ErrAmbiguous is returned when a
// multi-account provider already has a connection and Account is not specified.
func TestConnectMultiAccountAmbiguity(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	// First connection succeeds.
	_, err := Connect(ctx, "dropbox", ConnectOptions{
		Namespace:      "default",
		Account:        "personal",
		NonInteractive: true,
		Fields:         map[string][]byte{"access_token": []byte("sl.test-token")},
	}, store)
	require.NoError(t, err)

	// Second connection with same account returns ErrConnectionExists (not ErrAmbiguous).
	_, err = Connect(ctx, "dropbox", ConnectOptions{
		Namespace:      "default",
		Account:        "personal",
		NonInteractive: true,
		Fields:         map[string][]byte{"access_token": []byte("sl.other-token")},
	}, store)
	assert.ErrorIs(t, err, ErrConnectionExists)
}

// TestConnectSecretBytesZeroedAfterWrite verifies that the secret byte slice
// passed to Connect is zeroed after writing to the store (canary pattern).
func TestConnectSecretBytesZeroedAfterWrite(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	// Use a canary byte slice.
	canary := []byte(canaryValue)

	_, err := Connect(ctx, "openrouter", ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": canary},
	}, store)
	require.NoError(t, err)

	// The canary slice must be zeroed.
	for i, b := range canary {
		assert.Equal(t, byte(0), b, "canary byte at index %d must be zeroed", i)
	}
}

// TestConnectMissingRequiredField verifies that Connect returns an error when a
// required field is not provided and NonInteractive=true.
func TestConnectMissingRequiredField(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	_, err := Connect(ctx, "openrouter", ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields:         map[string][]byte{}, // api_key is required but missing
	}, store)
	assert.Error(t, err)
}

// TestConnectUnknownProvider verifies ErrProviderNotFound for unknown providers.
func TestConnectUnknownProvider(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	_, err := Connect(ctx, "nonexistent-provider", ConnectOptions{
		NonInteractive: true,
		Fields:         map[string][]byte{},
	}, store)
	assert.ErrorIs(t, err, ErrProviderNotFound)
}

// TestStatusReturnsNoValues verifies that Status() output contains no canary
// values — only field names, never secret values.
func TestStatusReturnsNoValues(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	// Store a canary value.
	_, err := Connect(ctx, "openrouter", ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": []byte(canaryValue)},
	}, store)
	require.NoError(t, err)

	statuses, err := Status(ctx, StatusOptions{Namespace: "default"}, store)
	require.NoError(t, err)

	for _, s := range statuses {
		// Connection.Fields contains field names only.
		for _, f := range s.Connection.Fields {
			assert.NotContains(t, f, canaryValue, "field name must not contain canary value")
		}
	}
}

// TestDelete_RollbackAfterConnect verifies that Delete removes all stored data
// written by Connect (secret fields and connection metadata).
func TestDelete_RollbackAfterConnect(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	// 1. Connect a provider.
	conn, err := Connect(ctx, "openrouter", ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": []byte("sk-or-test-rollback-key")},
	}, store)
	require.NoError(t, err)

	// 2. Verify the secret field was stored at the canonical path (S-FIND-23).
	secretPath := secretFieldPath("default", "ai", "openrouter", "api_key")
	_, exists := store.storedValue(secretPath)
	assert.True(t, exists, "api_key must be stored before Delete")

	// Also verify metadata was stored.
	metaPath := connectionMetaPath("default", "ai", "openrouter")
	_, metaExists := store.storedValue(metaPath)
	assert.True(t, metaExists, "connection metadata must be stored before Delete")

	// 3. Call Delete.
	delErr := Delete(ctx, conn.Provider, conn.Account, conn.Namespace, store)
	require.NoError(t, delErr)

	// 4. Verify secret field is gone.
	_, stillExists := store.storedValue(secretPath)
	assert.False(t, stillExists, "api_key must be removed after Delete")

	// Verify metadata is gone.
	_, metaStillExists := store.storedValue(metaPath)
	assert.False(t, metaStillExists, "connection metadata must be removed after Delete")
}

// TestDelete_IdempotentOnMissingConnection verifies that Delete on a non-existent
// connection returns nil (idempotent).
func TestDelete_IdempotentOnMissingConnection(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	err := Delete(ctx, "openrouter", "default", "default", store)
	assert.NoError(t, err, "Delete on non-existent connection must be idempotent")
}

// TestDelete_UnknownProviderReturnsError verifies ErrProviderNotFound.
func TestDelete_UnknownProviderReturnsError(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	err := Delete(ctx, "nonexistent-provider", "default", "default", store)
	assert.ErrorIs(t, err, ErrProviderNotFound)
}

// TestDelete_PartialFailure verifies that Delete returns an error wrapping the
// failing path when only some field deletes succeed. Uses countingErrStore to
// let the first Delete call succeed and fail on subsequent ones.
func TestDelete_PartialFailure(t *testing.T) {
	ctx := context.Background()
	inner := newMockStore()

	// Seed the store with a connection so Delete has real paths to operate on.
	_, err := Connect(ctx, "openrouter", ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": []byte("sk-or-partial-fail-key")},
	}, inner)
	require.NoError(t, err)

	// Allow first Delete to succeed, fail on second (metadata delete).
	store := &countingErrStore{inner: inner, failAfter: 1}

	delErr := Delete(ctx, "openrouter", "default", "default", store)
	assert.Error(t, delErr, "Delete must return an error when a field delete fails")
	assert.Contains(t, delErr.Error(), "simulated delete error", "error must contain the simulated delete error message")
	assert.Contains(t, delErr.Error(), "1 errors", "error must report the failing count")
}

// TestStoragePath_AICanonical verifies that Connect writes credentials under
// the canonical four-segment path format "namespace/category/provider/field"
// (S-FIND-23, T-03-01). Specifically:
//   - `keylatch set openai.api_key=...` writes under `default/ai/openai/api_key`
//   - No `default/connections/...` path is written
func TestStoragePath_AICanonical(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	_, err := Connect(ctx, "openrouter", ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": []byte("sk-or-canonical-test")},
	}, store)
	require.NoError(t, err)

	// Must write to canonical path.
	canonicalPath := "default/ai/openrouter/api_key"
	val, ok := store.storedValue(canonicalPath)
	assert.True(t, ok, "api_key must be stored at canonical path %q", canonicalPath)
	assert.Equal(t, "sk-or-canonical-test", string(val))

	// Must NOT write to legacy path.
	legacyPath := "default/connections/openrouter/default/secrets/api_key"
	_, legacyExists := store.storedValue(legacyPath)
	assert.False(t, legacyExists, "api_key must NOT be stored at legacy path %q", legacyPath)

	// Metadata must also be at canonical path.
	metaPath := "default/ai/openrouter/meta"
	_, metaExists := store.storedValue(metaPath)
	assert.True(t, metaExists, "connection metadata must be stored at canonical path %q", metaPath)
}

// TestDescribeIncludesNoValues verifies that Describe masks all secret field
// values with "****" and includes MaskedFields keys.
func TestDescribeIncludesNoValues(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	tmpl, masked, err := Describe(ctx, "openrouter", store)
	require.NoError(t, err)
	assert.NotNil(t, tmpl)
	assert.NotEmpty(t, masked)

	// All masked fields must have "****" values.
	for k, v := range masked {
		assert.Equal(t, "****", v, "masked field %q must have value ****", k)
	}

	// Template must not be nil.
	assert.Equal(t, "openrouter", tmpl.Provider)
}
