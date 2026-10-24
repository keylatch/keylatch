package ci

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/keylatch/keylatch/internal/config"
)

// ErrCloud is wrapped when a trust entry's cloud identity is invalid.
var ErrCloud = errors.New("ci: invalid cloud identity")

var (
	roleARNRe   = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$`)
	gcpProvRe   = regexp.MustCompile(`^//iam\.googleapis\.com/projects/[^/]+/locations/global/workloadIdentityPools/[^/]+/providers/[^/]+$`)
	gcpSARe     = regexp.MustCompile(`^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$`)
	azureGUIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

const tokenFile = "keylatch-ci-oidc-token" //nolint:gosec // G101 false positive: a file name, not a credential

// ValidateCloud checks a trust entry's cloud identity.
func ValidateCloud(c config.CICloud) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrCloud, fmt.Sprintf(format, args...))
	}
	switch c.Provider {
	case "aws":
		if !roleARNRe.MatchString(c.RoleARN) {
			return bad("aws needs role_arn, the ARN of an IAM role")
		}
	case "gcp":
		if !gcpProvRe.MatchString(c.WorkloadIdentityProvider) {
			return bad("gcp needs workload_identity_provider, //iam.googleapis.com/projects/<n>/locations/global/workloadIdentityPools/<pool>/providers/<provider>")
		}
		if c.ServiceAccount != "" && !gcpSARe.MatchString(c.ServiceAccount) {
			return bad("gcp service_account must be a service account email")
		}
	case "azure":
		if !azureGUIDRe.MatchString(c.TenantID) || !azureGUIDRe.MatchString(c.ClientID) {
			return bad("azure needs tenant_id and client_id (GUIDs)")
		}
	default:
		return bad("provider %q must be aws, gcp or azure", c.Provider)
	}
	return nil
}

// WriteCloudEnv writes the job's already verified OIDC token to a private file
// in dir and returns the environment variables that make the cloud SDKs
// federate with it: AssumeRoleWithWebIdentity for AWS, an external-account
// credential file for GCP and the federated token file for Azure. The aws-sm,
// gcp-sm and azure-kv backends read their default credential chain, so they
// authenticate as the workload without any stored secret.
func WriteCloudEnv(dir string, c config.CICloud, idToken string) (map[string]string, error) {
	if err := ValidateCloud(c); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	privateDir, err := os.MkdirTemp(dir, "cloud-")
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(privateDir)
		}
	}()
	tokenPath := filepath.Join(privateDir, tokenFile)
	if err := writePrivate(tokenPath, []byte(idToken)); err != nil {
		return nil, err
	}
	switch c.Provider {
	case "aws":
		env := map[string]string{
			"AWS_WEB_IDENTITY_TOKEN_FILE": tokenPath,
			"AWS_ROLE_ARN":                c.RoleARN,
			"AWS_ROLE_SESSION_NAME":       "keylatch-ci",
		}
		if c.Region != "" {
			env["AWS_REGION"] = c.Region
		}
		complete = true
		return env, nil
	case "azure":
		complete = true
		return map[string]string{"AZURE_FEDERATED_TOKEN_FILE": tokenPath, "AZURE_TENANT_ID": c.TenantID, "AZURE_CLIENT_ID": c.ClientID}, nil
	}
	cred := map[string]any{ //nolint:gosec // G101 false positive: SDK metadata and a token-file path, not a credential
		"type":               "external_account",
		"audience":           c.WorkloadIdentityProvider,
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"token_url":          "https://sts.googleapis.com/v1/token",
		"credential_source":  map[string]any{"file": tokenPath},
	}
	if c.ServiceAccount != "" {
		cred["service_account_impersonation_url"] = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + c.ServiceAccount + ":generateAccessToken"
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	credPath := filepath.Join(privateDir, "keylatch-ci-gcp-credentials.json")
	if err := writePrivate(credPath, data); err != nil {
		return nil, err
	}
	complete = true
	return map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": credPath}, nil
}

func writePrivate(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ci-cloud-*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
