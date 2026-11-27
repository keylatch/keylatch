package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/ci"
	"github.com/keylatch/keylatch/internal/ci/citest"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/exitcode"
)

func setCloud(t *testing.T, cloud *config.CICloud) {
	t.Helper()
	path := os.Getenv("KEYLATCH_CONFIG")
	cfg, err := config.Load(path)
	require.NoError(t, err)
	cfg.CI.Trust[0].Cloud = cloud
	require.NoError(t, config.Save(path, cfg))
}

func TestExchangeExportsCloudFederation(t *testing.T) {
	job := setupCIJob(t, citest.GitHubClaims(ciTestAudience, "acme/app", "refs/heads/main"))
	setCloud(t, &config.CICloud{Provider: "aws", RoleARN: "arn:aws:iam::123456789012:role/ci", Region: "eu-west-1"})

	stdout, stderr, code := runCI(t, "exchange", "--provider", ci.GitHubActions)
	require.Equal(t, exitcode.OK, code, stderr)
	for _, out := range []string{stdout, stderr} {
		assert.NotContains(t, out, job.token)
	}

	exported, err := os.ReadFile(job.envFile)
	require.NoError(t, err)
	vars := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(exported)), "\n") {
		k, v, _ := strings.Cut(l, "=")
		vars[k] = v
	}
	assert.Equal(t, "arn:aws:iam::123456789012:role/ci", vars["AWS_ROLE_ARN"])
	assert.Equal(t, "eu-west-1", vars["AWS_REGION"])
	assert.NotEmpty(t, vars[ci.SessionEnv])
	assert.NotContains(t, string(exported), job.token, "the token goes to a private file, not the env file")
	file, err := os.ReadFile(vars["AWS_WEB_IDENTITY_TOKEN_FILE"])
	require.NoError(t, err)
	assert.Equal(t, job.token, string(file))
}

func TestExchangeDeniesAnInvalidCloudIdentity(t *testing.T) {
	job := setupCIJob(t, citest.GitHubClaims(ciTestAudience, "acme/app", "refs/heads/main"))
	setCloud(t, &config.CICloud{Provider: "aws", RoleARN: "not-an-arn"})

	_, stderr, code := runCI(t, "exchange", "--provider", ci.GitHubActions)
	assert.Equal(t, exitcode.PolicyDeny, code)
	assert.Contains(t, stderr, "cloud_identity_invalid")
	_, err := os.Stat(job.envFile)
	assert.True(t, os.IsNotExist(err), "nothing is exported")
}
