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
)

// mockSMClient is a test double for SecretsManagerClient.
type mockSMClient struct {
	secrets map[string]string
}

func newMockSMClient(secrets map[string]string) *mockSMClient {
	if secrets == nil {
		secrets = make(map[string]string)
	}
	return &mockSMClient{secrets: secrets}
}

func (m *mockSMClient) GetSecretValue(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	name := aws.ToString(params.SecretId)
	val, ok := m.secrets[name]
	if !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("not found")}
	}
	return &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(val),
		ARN:          aws.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:" + name),
	}, nil
}

func (m *mockSMClient) ListSecrets(_ context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	var list []types.SecretListEntry
	for name := range m.secrets {
		n := name
		list = append(list, types.SecretListEntry{
			Name: aws.String(n),
			ARN:  aws.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:" + n),
		})
	}
	return &secretsmanager.ListSecretsOutput{SecretList: list}, nil
}

func (m *mockSMClient) CreateSecret(_ context.Context, params *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	name := aws.ToString(params.Name)
	m.secrets[name] = aws.ToString(params.SecretString)
	return &secretsmanager.CreateSecretOutput{
		ARN:  aws.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:" + name),
		Name: aws.String(name),
	}, nil
}

func (m *mockSMClient) PutSecretValue(_ context.Context, params *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	name := aws.ToString(params.SecretId)
	m.secrets[name] = aws.ToString(params.SecretString)
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func (m *mockSMClient) DeleteSecret(_ context.Context, params *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error) {
	name := aws.ToString(params.SecretId)
	if _, ok := m.secrets[name]; !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("not found")}
	}
	delete(m.secrets, name)
	return &secretsmanager.DeleteSecretOutput{}, nil
}

func (m *mockSMClient) DescribeSecret(_ context.Context, params *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	name := aws.ToString(params.SecretId)
	if _, ok := m.secrets[name]; !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("not found")}
	}
	return &secretsmanager.DescribeSecretOutput{Name: aws.String(name)}, nil
}

func TestAWSGet(t *testing.T) {
	mock := newMockSMClient(map[string]string{"myapp/key": "supersecret"})
	b, err := awssm.Open(context.Background(), awssm.Options{
		Region:   "us-east-1",
		SMClient: mock,
	})
	require.NoError(t, err)

	val, meta, err := b.Get(context.Background(), "myapp/key")
	require.NoError(t, err)
	assert.Equal(t, []byte("supersecret"), val)
	assert.Equal(t, "aws-sm", meta.Backend)
}

func TestAWSGet_NotFound(t *testing.T) {
	mock := newMockSMClient(nil)
	b, err := awssm.Open(context.Background(), awssm.Options{
		Region:   "us-east-1",
		SMClient: mock,
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "missing/key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestAWSList(t *testing.T) {
	mock := newMockSMClient(map[string]string{
		"myapp/key1": "val1",
		"myapp/key2": "val2",
		"other/key":  "val3",
	})
	b, err := awssm.Open(context.Background(), awssm.Options{
		Region:   "us-east-1",
		SMClient: mock,
	})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "myapp")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestAWSCapabilities(t *testing.T) {
	mock := newMockSMClient(nil)
	b, err := awssm.Open(context.Background(), awssm.Options{
		Region:   "us-east-1",
		SMClient: mock,
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
	assert.True(t, found, "aws-sm backend must report CapNetworkedFetch")
}
