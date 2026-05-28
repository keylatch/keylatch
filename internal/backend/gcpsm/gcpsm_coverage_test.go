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
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

func openMockGCPBackend(t *testing.T, secrets map[string][]byte) *gcpsm.GCPSecretManagerBackend {
	t.Helper()
	mock := newMockGCPClient(secrets)
	b, err := gcpsm.Open(context.Background(), gcpsm.Options{
		ProjectID: "my-project",
		Client:    mock,
	})
	require.NoError(t, err)
	return b
}

func TestGCPName(t *testing.T) {
	b := openMockGCPBackend(t, nil)
	assert.Equal(t, "gcp-sm", b.Name())
}

func TestGCPID(t *testing.T) {
	b := openMockGCPBackend(t, nil)
	assert.Contains(t, b.ID(), "gcp-sm")
	assert.Contains(t, b.ID(), "my-project")
}

func TestGCPClose(t *testing.T) {
	b := openMockGCPBackend(t, nil)
	assert.NoError(t, b.Close())
}

func TestGCPDelete_Success(t *testing.T) {
	b := openMockGCPBackend(t, map[string][]byte{"del-key": []byte("val")})
	err := b.Delete(context.Background(), "del-key")
	require.NoError(t, err)
}

func TestGCPDelete_NotFound(t *testing.T) {
	b := openMockGCPBackend(t, nil)
	err := b.Delete(context.Background(), "missing-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestGCPOpen_MissingProjectID(t *testing.T) {
	_, err := gcpsm.Open(context.Background(), gcpsm.Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project_id")
}

func TestGCPGetMeta_NotSupported(t *testing.T) {
	b := openMockGCPBackend(t, nil)
	_, err := b.GetMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestGCPSetMeta_NotSupported(t *testing.T) {
	b := openMockGCPBackend(t, nil)
	err := b.SetMeta(context.Background(), "any/path", vmeta.Meta{})
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestGCPListMeta_NotSupported(t *testing.T) {
	b := openMockGCPBackend(t, nil)
	_, err := b.ListMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestGCPGetVersioned_NotSupported(t *testing.T) {
	b := openMockGCPBackend(t, nil)
	_, err := b.GetVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestGCPSetVersioned_NotSupported(t *testing.T) {
	b := openMockGCPBackend(t, nil)
	err := b.SetVersioned(context.Background(), "any/path", 1, []byte("val"))
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestGCPDeleteVersioned_NotSupported(t *testing.T) {
	b := openMockGCPBackend(t, nil)
	err := b.DeleteVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestGCPGet_NilPayload(t *testing.T) {
	mock := &nilPayloadGCPClient{}
	b, err := gcpsm.Open(context.Background(), gcpsm.Options{
		ProjectID: "my-project",
		Client:    mock,
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "any-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

// nilPayloadGCPClient returns AccessSecretVersion with nil payload.
type nilPayloadGCPClient struct{}

func (m *nilPayloadGCPClient) AccessSecretVersion(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return &secretmanagerpb.AccessSecretVersionResponse{Payload: nil}, nil
}
func (m *nilPayloadGCPClient) AddSecretVersion(_ context.Context, _ *secretmanagerpb.AddSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	return &secretmanagerpb.SecretVersion{}, nil
}
func (m *nilPayloadGCPClient) CreateSecret(_ context.Context, _ *secretmanagerpb.CreateSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	return &secretmanagerpb.Secret{}, nil
}
func (m *nilPayloadGCPClient) DeleteSecret(_ context.Context, _ *secretmanagerpb.DeleteSecretRequest, _ ...gax.CallOption) error {
	return nil
}
func (m *nilPayloadGCPClient) ListSecrets(_ context.Context, _ *secretmanagerpb.ListSecretsRequest, _ ...gax.CallOption) *secretmanager.SecretIterator {
	return nil
}
func (m *nilPayloadGCPClient) Close() error { return nil }

func TestGCPGet_OtherError(t *testing.T) {
	mock := &alwaysErrGCPClient{}
	b, err := gcpsm.Open(context.Background(), gcpsm.Options{
		ProjectID: "my-project",
		Client:    mock,
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "some-key")
	require.Error(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
}

func TestGCPDelete_OtherError(t *testing.T) {
	mock := &alwaysErrGCPClient{}
	b, err := gcpsm.Open(context.Background(), gcpsm.Options{
		ProjectID: "my-project",
		Client:    mock,
	})
	require.NoError(t, err)

	err = b.Delete(context.Background(), "some-key")
	require.Error(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
}

// alwaysErrGCPClient returns a generic (non-not-found) error from every method.
type alwaysErrGCPClient struct{}

func (m *alwaysErrGCPClient) AccessSecretVersion(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return nil, status.Errorf(codes.Internal, "internal error")
}
func (m *alwaysErrGCPClient) AddSecretVersion(_ context.Context, _ *secretmanagerpb.AddSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	return nil, status.Errorf(codes.Internal, "internal error")
}
func (m *alwaysErrGCPClient) CreateSecret(_ context.Context, _ *secretmanagerpb.CreateSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	return nil, status.Errorf(codes.Internal, "internal error")
}
func (m *alwaysErrGCPClient) DeleteSecret(_ context.Context, _ *secretmanagerpb.DeleteSecretRequest, _ ...gax.CallOption) error {
	return status.Errorf(codes.Internal, "internal error")
}
func (m *alwaysErrGCPClient) ListSecrets(_ context.Context, _ *secretmanagerpb.ListSecretsRequest, _ ...gax.CallOption) *secretmanager.SecretIterator {
	return nil
}
func (m *alwaysErrGCPClient) Close() error { return nil }

func TestGCPCapabilities_HasCapList(t *testing.T) {
	b := openMockGCPBackend(t, nil)
	caps := b.Capabilities()
	found := false
	for _, c := range caps {
		if c == backend.CapList {
			found = true
			break
		}
	}
	assert.True(t, found, "gcp-sm must report CapList")
}

func TestGCPSet_AddVersionFails_CreateFails(t *testing.T) {
	// AddSecretVersion returns NotFound (secret doesn't exist), then CreateSecret also fails.
	mock := &addVersionNotFoundCreateErrClient{}
	b, err := gcpsm.Open(context.Background(), gcpsm.Options{
		ProjectID: "my-project",
		Client:    mock,
	})
	require.NoError(t, err)

	err = b.Set(context.Background(), "key", []byte("val"), backend.Meta{})
	require.Error(t, err)
}

// addVersionNotFoundCreateErrClient: AddSecretVersion → NotFound, CreateSecret → error.
type addVersionNotFoundCreateErrClient struct{}

func (m *addVersionNotFoundCreateErrClient) AccessSecretVersion(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return nil, status.Errorf(codes.NotFound, "not found")
}
func (m *addVersionNotFoundCreateErrClient) AddSecretVersion(_ context.Context, _ *secretmanagerpb.AddSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	return nil, status.Errorf(codes.NotFound, "secret not found")
}
func (m *addVersionNotFoundCreateErrClient) CreateSecret(_ context.Context, _ *secretmanagerpb.CreateSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	return nil, status.Errorf(codes.Internal, "create failed")
}
func (m *addVersionNotFoundCreateErrClient) DeleteSecret(_ context.Context, _ *secretmanagerpb.DeleteSecretRequest, _ ...gax.CallOption) error {
	return nil
}
func (m *addVersionNotFoundCreateErrClient) ListSecrets(_ context.Context, _ *secretmanagerpb.ListSecretsRequest, _ ...gax.CallOption) *secretmanager.SecretIterator {
	return nil
}
func (m *addVersionNotFoundCreateErrClient) Close() error { return nil }
