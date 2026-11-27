package ci_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/ci"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	gcpProvider = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ci/providers/github"
	guid        = "11111111-2222-3333-4444-555555555555"
)

func TestValidateCloud(t *testing.T) {
	good := []config.CICloud{
		{Provider: "aws", RoleARN: "arn:aws:iam::123456789012:role/ci"},
		{Provider: "gcp", WorkloadIdentityProvider: gcpProvider},
		{Provider: "gcp", WorkloadIdentityProvider: gcpProvider, ServiceAccount: "ci@proj.iam.gserviceaccount.com"},
		{Provider: "azure", TenantID: guid, ClientID: guid},
	}
	for _, c := range good {
		assert.NoError(t, ci.ValidateCloud(c), "%+v", c)
	}
	bad := []config.CICloud{
		{},
		{Provider: "oracle"},
		{Provider: "aws", RoleARN: "arn:aws:iam::123456789012:user/bob"},
		{Provider: "gcp", WorkloadIdentityProvider: "projects/123"},
		{Provider: "gcp", WorkloadIdentityProvider: gcpProvider, ServiceAccount: "not-an-email"},
		{Provider: "azure", TenantID: guid},
		{Provider: "azure", TenantID: "------------------------------------", ClientID: guid},
	}
	for _, c := range bad {
		assert.ErrorIs(t, ci.ValidateCloud(c), ci.ErrCloud, "%+v", c)
	}
}

func TestCloudExchangesKeepSeparateTokenFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := config.CICloud{Provider: "aws", RoleARN: "arn:aws:iam::123456789012:role/ci"}
	first, err := ci.WriteCloudEnv(dir, cfg, "first-job-token")
	require.NoError(t, err)
	second, err := ci.WriteCloudEnv(dir, cfg, "second-job-token")
	require.NoError(t, err)
	key := "AWS_WEB_IDENTITY_TOKEN_FILE"
	assert.NotEqual(t, first[key], second[key])
	data, err := os.ReadFile(first[key])
	require.NoError(t, err)
	assert.Equal(t, "first-job-token", string(data))
	data, err = os.ReadFile(second[key])
	require.NoError(t, err)
	assert.Equal(t, "second-job-token", string(data))
}

func TestWriteCloudEnv(t *testing.T) {
	const idToken = "header.payload.signature"
	read := func(env map[string]string, key string) string {
		data, err := os.ReadFile(env[key])
		require.NoError(t, err)
		return string(data)
	}

	t.Run("aws", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "nested")
		env, err := ci.WriteCloudEnv(dir, config.CICloud{Provider: "aws", RoleARN: "arn:aws:iam::123456789012:role/ci", Region: "eu-west-1"}, idToken)
		require.NoError(t, err)
		assert.Equal(t, idToken, read(env, "AWS_WEB_IDENTITY_TOKEN_FILE"))
		assert.Equal(t, "arn:aws:iam::123456789012:role/ci", env["AWS_ROLE_ARN"])
		assert.Equal(t, "eu-west-1", env["AWS_REGION"])
		assert.NotContains(t, env, "AWS_ACCESS_KEY_ID", "no long-lived key is involved")
		if runtime.GOOS != "windows" {
			info, err := os.Stat(env["AWS_WEB_IDENTITY_TOKEN_FILE"])
			require.NoError(t, err)
			assert.Zero(t, info.Mode().Perm()&0o077, "the token file is private")
		}
	})
	t.Run("azure", func(t *testing.T) {
		env, err := ci.WriteCloudEnv(t.TempDir(), config.CICloud{Provider: "azure", TenantID: guid, ClientID: guid}, idToken)
		require.NoError(t, err)
		assert.Equal(t, idToken, read(env, "AZURE_FEDERATED_TOKEN_FILE"))
		assert.Equal(t, guid, env["AZURE_TENANT_ID"])
		assert.Equal(t, guid, env["AZURE_CLIENT_ID"])
	})
	t.Run("gcp", func(t *testing.T) {
		env, err := ci.WriteCloudEnv(t.TempDir(), config.CICloud{Provider: "gcp", WorkloadIdentityProvider: gcpProvider, ServiceAccount: "ci@proj.iam.gserviceaccount.com"}, idToken)
		require.NoError(t, err)
		var cred map[string]any
		require.NoError(t, json.Unmarshal([]byte(read(env, "GOOGLE_APPLICATION_CREDENTIALS")), &cred))
		assert.Equal(t, "external_account", cred["type"])
		assert.Equal(t, gcpProvider, cred["audience"])
		assert.Contains(t, cred["service_account_impersonation_url"], "ci@proj.iam.gserviceaccount.com:generateAccessToken")
		src := cred["credential_source"].(map[string]any)
		data, err := os.ReadFile(src["file"].(string))
		require.NoError(t, err)
		assert.Equal(t, idToken, string(data))

		env, err = ci.WriteCloudEnv(t.TempDir(), config.CICloud{Provider: "gcp", WorkloadIdentityProvider: gcpProvider}, idToken)
		require.NoError(t, err)
		assert.NotContains(t, read(env, "GOOGLE_APPLICATION_CREDENTIALS"), "impersonation")
	})
	t.Run("invalid identity writes nothing", func(t *testing.T) {
		dir := t.TempDir()
		_, err := ci.WriteCloudEnv(dir, config.CICloud{Provider: "aws"}, idToken)
		require.ErrorIs(t, err, ci.ErrCloud)
		entries, _ := os.ReadDir(dir)
		assert.Empty(t, entries)
	})
}
