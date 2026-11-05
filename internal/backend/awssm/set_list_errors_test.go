package awssm_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/awssm"
)

// bkAWSScripted embeds the map-backed mock and overrides individual calls.
type bkAWSScripted struct {
	*mockSMClient
	getOut      *secretsmanager.GetSecretValueOutput
	describeErr error
	createErr   error
	putErr      error
	list        []types.SecretListEntry
}

func (m *bkAWSScripted) GetSecretValue(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m.getOut, nil
}

func (m *bkAWSScripted) DescribeSecret(_ context.Context, _ *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	return &secretsmanager.DescribeSecretOutput{}, m.describeErr
}

func (m *bkAWSScripted) CreateSecret(_ context.Context, _ *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	return &secretsmanager.CreateSecretOutput{}, m.createErr
}

func (m *bkAWSScripted) PutSecretValue(_ context.Context, _ *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	return &secretsmanager.PutSecretValueOutput{}, m.putErr
}

func (m *bkAWSScripted) ListSecrets(_ context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	return &secretsmanager.ListSecretsOutput{SecretList: m.list}, nil
}

func bkAWSOpenScripted(t *testing.T, m *bkAWSScripted) *awssm.AWSSecretsManagerBackend {
	t.Helper()
	m.mockSMClient = newMockSMClient(nil)
	b, err := awssm.Open(context.Background(), awssm.Options{Region: "r", SMClient: m})
	require.NoError(t, err)
	return b
}

func TestAWSGet_EmptyValueIsNotFound(t *testing.T) {
	b := bkAWSOpenScripted(t, &bkAWSScripted{getOut: &secretsmanager.GetSecretValueOutput{}})
	_, _, err := b.Get(context.Background(), "empty")
	require.ErrorIs(t, err, backend.ErrNotFound)
	assert.Contains(t, err.Error(), "no value")
}

func TestAWSGet_NoARNLeavesAccessorEmpty(t *testing.T) {
	b := bkAWSOpenScripted(t, &bkAWSScripted{getOut: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("v")}})
	val, meta, err := b.Get(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), val)
	assert.Empty(t, meta.Accessor)
}

func TestAWSSet_ErrorPathsDoNotLeakValue(t *testing.T) {
	notFound := &types.ResourceNotFoundException{Message: aws.String("missing")}
	boom := errors.New("upstream failure")
	secret := []byte("value-that-must-stay-private")

	cases := []struct {
		name    string
		m       *bkAWSScripted
		wantSub string
	}{
		{"create fails", &bkAWSScripted{describeErr: notFound, createErr: boom}, "(create)"},
		{"put fails", &bkAWSScripted{putErr: boom}, "(put)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := bkAWSOpenScripted(t, tc.m)
			err := b.Set(context.Background(), "k", secret, backend.Meta{})
			require.Error(t, err)
			require.ErrorIs(t, err, boom)
			assert.Contains(t, err.Error(), tc.wantSub)
			assert.NotContains(t, err.Error(), string(secret))
		})
	}
}

func TestAWSList_SkipsNamelessAndFiltersPrefix(t *testing.T) {
	b := bkAWSOpenScripted(t, &bkAWSScripted{list: []types.SecretListEntry{
		{ARN: aws.String("arn:nameless")},
		{Name: aws.String("app/one")},
		{Name: aws.String("other"), ARN: aws.String("arn:other")},
	}})

	entries, err := b.List(context.Background(), "app/")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "app/one", entries[0].Path)
	assert.Empty(t, entries[0].Accessor)

	all, err := b.List(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, all, 2)
}
