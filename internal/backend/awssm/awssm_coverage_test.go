package awssm_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/awssm"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// errSMClient always returns an error from every method.
type errSMClient struct {
	err error
}

func (e *errSMClient) GetSecretValue(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return nil, e.err
}
func (e *errSMClient) ListSecrets(_ context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	return nil, e.err
}
func (e *errSMClient) CreateSecret(_ context.Context, _ *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	return nil, e.err
}
func (e *errSMClient) PutSecretValue(_ context.Context, _ *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	return nil, e.err
}
func (e *errSMClient) DeleteSecret(_ context.Context, _ *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
	return nil, e.err
}
func (e *errSMClient) DescribeSecret(_ context.Context, _ *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	return nil, e.err
}

func openMockAWSBackend(t *testing.T, secrets map[string]string) *awssm.AWSSecretsManagerBackend {
	t.Helper()
	mock := newMockSMClient(secrets)
	b, err := awssm.Open(context.Background(), awssm.Options{
		Region:   "us-east-1",
		SMClient: mock,
	})
	require.NoError(t, err)
	return b
}

func TestAWSName(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	assert.Equal(t, "aws-sm", b.Name())
}

func TestAWSID(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	assert.Contains(t, b.ID(), "aws-sm")
	assert.Contains(t, b.ID(), "us-east-1")
}

func TestAWSClose(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	assert.NoError(t, b.Close())
	// idempotent
	assert.NoError(t, b.Close())
}

func TestAWSSet_CreateNew(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	err := b.Set(context.Background(), "myapp/new-key", []byte("new-value"), backend.Meta{})
	require.NoError(t, err)

	// Verify it was created.
	val, meta, err := b.Get(context.Background(), "myapp/new-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("new-value"), val)
	assert.Equal(t, "aws-sm", meta.Backend)
}

func TestAWSSet_UpdateExisting(t *testing.T) {
	b := openMockAWSBackend(t, map[string]string{"myapp/key": "original"})
	err := b.Set(context.Background(), "myapp/key", []byte("updated"), backend.Meta{})
	require.NoError(t, err)

	val, _, err := b.Get(context.Background(), "myapp/key")
	require.NoError(t, err)
	assert.Equal(t, []byte("updated"), val)
}

func TestAWSDelete_Success(t *testing.T) {
	b := openMockAWSBackend(t, map[string]string{"myapp/key": "val"})
	err := b.Delete(context.Background(), "myapp/key")
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "myapp/key")
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestAWSDelete_NotFound(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	err := b.Delete(context.Background(), "nonexistent/key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestAWSGet_BinarySecret(t *testing.T) {
	// Mock client that returns binary data.
	mock := &binarySMClient{data: []byte{0x01, 0x02, 0x03}}
	b, err := awssm.Open(context.Background(), awssm.Options{
		Region:   "us-east-1",
		SMClient: mock,
	})
	require.NoError(t, err)

	val, _, err := b.Get(context.Background(), "binary/key")
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, val)
}

// binarySMClient returns binary secret data.
type binarySMClient struct {
	data []byte
}

func (m *binarySMClient) GetSecretValue(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return &secretsmanager.GetSecretValueOutput{
		SecretBinary: m.data,
		ARN:          aws.String("arn:aws:secretsmanager:us-east-1:123:secret:" + aws.ToString(params.SecretId)),
	}, nil
}
func (m *binarySMClient) ListSecrets(_ context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	return &secretsmanager.ListSecretsOutput{}, nil
}
func (m *binarySMClient) CreateSecret(_ context.Context, _ *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	return &secretsmanager.CreateSecretOutput{}, nil
}
func (m *binarySMClient) PutSecretValue(_ context.Context, _ *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	return &secretsmanager.PutSecretValueOutput{}, nil
}
func (m *binarySMClient) DeleteSecret(_ context.Context, _ *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
	return &secretsmanager.DeleteSecretOutput{}, nil
}
func (m *binarySMClient) DescribeSecret(_ context.Context, _ *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	return &secretsmanager.DescribeSecretOutput{}, nil
}

func TestAWSGet_Error(t *testing.T) {
	mock := &errSMClient{err: &types.InternalServiceError{Message: aws.String("internal error")}}
	b, err := awssm.Open(context.Background(), awssm.Options{
		Region:   "us-east-1",
		SMClient: mock,
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "some/key")
	require.Error(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
}

func TestAWSSet_DescribeError(t *testing.T) {
	// Describe returns an unexpected error (not not-found).
	mock := &errSMClient{err: &types.InternalServiceError{Message: aws.String("internal error")}}
	b, err := awssm.Open(context.Background(), awssm.Options{
		Region:   "us-east-1",
		SMClient: mock,
	})
	require.NoError(t, err)

	err = b.Set(context.Background(), "some/key", []byte("val"), backend.Meta{})
	require.Error(t, err)
}

func TestAWSDelete_Error(t *testing.T) {
	mock := &errSMClient{err: &types.InternalServiceError{Message: aws.String("internal error")}}
	b, err := awssm.Open(context.Background(), awssm.Options{
		Region:   "us-east-1",
		SMClient: mock,
	})
	require.NoError(t, err)

	err = b.Delete(context.Background(), "some/key")
	require.Error(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
}

func TestAWSGetMeta_NotSupported(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	_, err := b.GetMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAWSSetMeta_NotSupported(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	err := b.SetMeta(context.Background(), "any/path", vmeta.Meta{})
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAWSListMeta_NotSupported(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	_, err := b.ListMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAWSGetVersioned_NotSupported(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	_, err := b.GetVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAWSSetVersioned_NotSupported(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	err := b.SetVersioned(context.Background(), "any/path", 1, []byte("val"))
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAWSDeleteVersioned_NotSupported(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	err := b.DeleteVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAWSList_NoPrefix(t *testing.T) {
	b := openMockAWSBackend(t, map[string]string{
		"key1": "val1",
		"key2": "val2",
	})
	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	for _, e := range entries {
		assert.True(t, e.Exists)
	}
}

func TestAWSCapabilities_HasCapList(t *testing.T) {
	b := openMockAWSBackend(t, nil)
	caps := b.Capabilities()
	found := false
	for _, c := range caps {
		if c == backend.CapList {
			found = true
			break
		}
	}
	assert.True(t, found, "aws-sm must report CapList")
}
