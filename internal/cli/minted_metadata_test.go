package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/keylatch/keylatch/internal/cloudcreds"
	"github.com/keylatch/keylatch/internal/providermint"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/keylatch/keylatch/templates/providers"
)

const metadataTestToken = "minted-cloud-access-token"

func TestMetadataChild(t *testing.T) {
	provider := os.Getenv("METADATA_TEST_CHILD")
	if provider == "" {
		return
	}
	for _, entry := range os.Environ() {
		require.NotContains(t, entry, metadataTestToken)
		require.NotContains(t, entry, "ambient-cloud-secret")
	}
	for _, name := range []string{"GOOGLE_OAUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN", "AZURE_ACCESS_TOKEN", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS"} {
		require.Empty(t, os.Getenv(name))
	}
	endpoint := "http://" + os.Getenv("GCE_METADATA_HOST") + "/computeMetadata/v1/instance/service-accounts/default/token"
	if provider == "azure" {
		endpoint = os.Getenv("IDENTITY_ENDPOINT") + "?api-version=2019-08-01&resource=" + url.QueryEscape("https://management.azure.com/")
	}
	require.Contains(t, endpoint, "127.0.0.1:")
	require.Contains(t, endpoint, "klph_")
	r, err := http.NewRequest("GET", endpoint, nil)
	require.NoError(t, err)
	if provider == "gcp" {
		r.Header.Set("Metadata-Flavor", "Google")
	} else {
		r.Header.Set("X-IDENTITY-HEADER", os.Getenv("IDENTITY_HEADER"))
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(r)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, 200, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, metadataTestToken, body["access_token"])
	fmt.Println("endpoint-only")
	fmt.Println(body["access_token"])
}

func TestMintedMetadataChildEnvironmentAndCleanup(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	for _, provider := range []string{"gcp", "azure"} {
		t.Run(provider, func(t *testing.T) {
			data, err := providers.EmbeddedFS.ReadFile("core/" + provider + ".yaml")
			require.NoError(t, err)
			var tmpl registry.ConnectionTemplate
			require.NoError(t, yaml.Unmarshal(data, &tmpl))
			cfg := cloudcreds.Config{Provider: provider, Connection: provider, Account: "app@project.iam.gserviceaccount.com", Scopes: []string{"scope"}, Resource: "https://management.azure.com/", Audit: &testutil.AuditRecorder{}}
			scope := map[string][]string{"scope": cfg.Scopes}
			if provider == "azure" {
				scope = map[string][]string{"resource": {cfg.Resource}}
			}
			cfg.Initial = &providermint.Secret{Fields: map[string][]byte{"access_token": []byte(metadataTestToken)}, ExpiresAt: time.Now().Add(5 * time.Minute), Scope: scope}
			credential, err := openMetadataCredential(context.Background(), cfg)
			require.NoError(t, err)
			t.Cleanup(credential.Close)
			_, err = credential.Value(context.Background(), "access_token")
			assert.ErrorIs(t, err, runner.ErrMintedFieldAbsent)
			field := "metadata_host"
			if provider == "azure" {
				field = "identity_endpoint"
			}
			value, err := credential.Value(context.Background(), field)
			require.NoError(t, err)
			endpoint := string(value)
			if provider == "gcp" {
				endpoint = "http://" + endpoint
			}
			t.Setenv("AZURE_CLIENT_SECRET", "ambient-cloud-secret")
			t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "ambient-cloud-secret")
			var out, stderr bytes.Buffer
			driver := runner.NewMintedDriver(func(context.Context, registry.ConnectionTemplate, runner.MintOpenRequest) (runner.MintedCredential, error) {
				return credential, nil
			})
			receipt, err := driver.Run(context.Background(), runner.ExecRequest{ConnectionSlug: provider, Command: []string{executable, "-test.run=^TestMetadataChild$"}, WorkingDir: t.TempDir(), LocalEnv: []string{"METADATA_TEST_CHILD=" + provider}, Stdout: &out, Stderr: &stderr}, tmpl)
			require.NoError(t, err, stderr.String())
			require.Zero(t, receipt.ExitCode, out.String()+stderr.String())
			assert.Contains(t, out.String(), "endpoint-only")
			assert.NotContains(t, out.String(), metadataTestToken)
			resp, err := http.Get(endpoint)
			if resp != nil {
				_ = resp.Body.Close()
			}
			assert.Error(t, err, "child exit closes the endpoint")
		})
	}
}

func TestMetadataStartFailureWipesMintedToken(t *testing.T) {
	value := []byte(metadataTestToken)
	_, err := openMetadataCredential(context.Background(), cloudcreds.Config{Provider: "gcp", Initial: &providermint.Secret{Fields: map[string][]byte{"access_token": value}}})
	require.Error(t, err)
	assert.Equal(t, strings.Repeat("\x00", len(value)), string(value))
}
