package gcpsm_test

import (
	"context"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/gcpsm"
)

// mockGCPClient is a test double for SecretManagerClient.
type mockGCPClient struct {
	secrets map[string][]byte
}

func newMockGCPClient(secrets map[string][]byte) *mockGCPClient {
	if secrets == nil {
		secrets = make(map[string][]byte)
	}
	return &mockGCPClient{secrets: secrets}
}

func (m *mockGCPClient) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	// Extract secret name from path like "projects/proj/secrets/name/versions/latest"
	parts := splitName(req.Name)
	if len(parts) < 4 {
		return nil, status.Errorf(codes.NotFound, "not found")
	}
	name := parts[3]
	val, ok := m.secrets[name]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "secret not found")
	}
	return &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: val},
	}, nil
}

func (m *mockGCPClient) AddSecretVersion(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	parts := splitName(req.Parent)
	if len(parts) < 4 {
		return nil, status.Errorf(codes.NotFound, "not found")
	}
	name := parts[3]
	if _, ok := m.secrets[name]; !ok {
		return nil, status.Errorf(codes.NotFound, "secret not found")
	}
	if req.Payload != nil {
		m.secrets[name] = req.Payload.Data
	}
	return &secretmanagerpb.SecretVersion{}, nil
}

func (m *mockGCPClient) CreateSecret(_ context.Context, req *secretmanagerpb.CreateSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	m.secrets[req.SecretId] = nil
	return &secretmanagerpb.Secret{
		Name: "projects/" + req.Parent + "/secrets/" + req.SecretId,
	}, nil
}

func (m *mockGCPClient) DeleteSecret(_ context.Context, req *secretmanagerpb.DeleteSecretRequest, _ ...gax.CallOption) error {
	parts := splitName(req.Name)
	if len(parts) < 4 {
		return status.Errorf(codes.NotFound, "not found")
	}
	name := parts[3]
	if _, ok := m.secrets[name]; !ok {
		return status.Errorf(codes.NotFound, "secret not found")
	}
	delete(m.secrets, name)
	return nil
}

func (m *mockGCPClient) ListSecrets(_ context.Context, _ *secretmanagerpb.ListSecretsRequest, _ ...gax.CallOption) *secretmanager.SecretIterator {
	// We can't easily create a *secretmanager.SecretIterator in tests.
	// Return nil to signal no iteration support in mock.
	return nil
}

func (m *mockGCPClient) Close() error { return nil }

// splitName splits a resource name by "/".
func splitName(name string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '/' {
			parts = append(parts, name[start:i])
			start = i + 1
		}
	}
	parts = append(parts, name[start:])
	return parts
}

func TestGCPGet(t *testing.T) {
	mock := newMockGCPClient(map[string][]byte{
		"myapp-key": []byte("gcp-secret"),
	})
	b, err := gcpsm.Open(context.Background(), gcpsm.Options{
		ProjectID: "my-project",
		Client:    mock,
	})
	require.NoError(t, err)

	val, meta, err := b.Get(context.Background(), "myapp-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("gcp-secret"), val)
	assert.Equal(t, "gcp-sm", meta.Backend)
}

func TestGCPGet_NotFound(t *testing.T) {
	mock := newMockGCPClient(nil)
	b, err := gcpsm.Open(context.Background(), gcpsm.Options{
		ProjectID: "my-project",
		Client:    mock,
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "missing-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestGCPCapabilities(t *testing.T) {
	mock := newMockGCPClient(nil)
	b, err := gcpsm.Open(context.Background(), gcpsm.Options{
		ProjectID: "my-project",
		Client:    mock,
	})
	require.NoError(t, err)

	caps := b.Capabilities()
	found := false
	for _, c := range caps {
		if c == backend.CapNetworkedFetch {
			found = true
			break
		}
	}
	assert.True(t, found, "gcp-sm must report CapNetworkedFetch")
}

func TestGCPSet_CreateAndUpdate(t *testing.T) {
	mock := newMockGCPClient(nil)
	b, err := gcpsm.Open(context.Background(), gcpsm.Options{
		ProjectID: "my-project",
		Client:    mock,
	})
	require.NoError(t, err)

	// Create new secret.
	err = b.Set(context.Background(), "new-secret", []byte("value1"), backend.Meta{})
	require.NoError(t, err)

	// Update existing secret.
	err = b.Set(context.Background(), "new-secret", []byte("value2"), backend.Meta{})
	require.NoError(t, err)
}
