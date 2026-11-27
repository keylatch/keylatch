package dispatch

import (
	"errors"
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/backend/credref"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// envCredential is one credential setting and the environment variables that
// used to supply it.
type envCredential struct {
	field string
	names []string
}

// envCredentials lists, per backend, the settings that are credentials.
var envCredentials = map[string][]envCredential{
	"op":         {{"service_account_token", []string{"OP_SERVICE_ACCOUNT_TOKEN"}}},
	"op-connect": {{"token", []string{"KEYLATCH_OP_CONNECT_TOKEN", "OP_CONNECT_TOKEN"}}},
	"vault": {
		{"token", []string{"KEYLATCH_VAULT_TOKEN", "VAULT_TOKEN"}},
		{"role_id", []string{"KEYLATCH_VAULT_ROLE_ID"}},
		{"secret_id", []string{"KEYLATCH_VAULT_SECRET_ID"}},
	},
	"aws-sm": {
		{"access_key_id", []string{"KEYLATCH_AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"}},
		{"secret_access_key", []string{"KEYLATCH_AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"}},
	},
	"gcp-sm":   {{"credentials_json", []string{"KEYLATCH_GCP_CREDENTIALS_JSON", "GOOGLE_APPLICATION_CREDENTIALS"}}},
	"azure-kv": {{"client_secret", []string{"KEYLATCH_AZURE_CLIENT_SECRET", "AZURE_CLIENT_SECRET"}}},
	"doppler":  {{"token", []string{"KEYLATCH_DOPPLER_TOKEN", "DOPPLER_TOKEN"}}},
	"infisical": {
		{"client_id", []string{"KEYLATCH_INFISICAL_CLIENT_ID", "INFISICAL_CLIENT_ID"}},
		{"client_secret", []string{"KEYLATCH_INFISICAL_CLIENT_SECRET", "INFISICAL_CLIENT_SECRET"}},
	},
	"bws":  {{"access_token", []string{"KEYLATCH_BWS_ACCESS_TOKEN", "BWS_ACCESS_TOKEN"}}},
	"sops": {{"age_key", []string{"KEYLATCH_SOPS_AGE_KEY", "SOPS_AGE_KEY"}}},
}

// ErrEnvCredentials means a backend's credentials are in the environment but
// the config does not allow that.
var ErrEnvCredentials = errors.New("backend credentials found in the environment")

// credentialKEK opens the KEK the stored credentials are wrapped by, without
// asking the user for anything; replaced in tests.
var credentialKEK = func(env llmcontext.Lookup) (kek.KEK, error) {
	return file.LoadKeyringKEK(paths.ResolveKeyringPath(env))
}

// resolveSettings builds the backend's settings and fills in its credentials:
// from the credential_ref when the config names one, from the environment
// only when allow_env_credentials is set. Credentials in the environment
// without that opt-in are refused rather than silently used.
func resolveSettings(name string, cfg config.Config, env llmcontext.Lookup) (map[string]interface{}, error) {
	s := buildSettings(name, cfg, env)
	creds := envCredentials[name]
	if len(creds) == 0 {
		return s, nil
	}
	id := config.BackendID(name)
	bc := cfg.Backends[id]

	switch {
	case bc.CredentialRef != "":
		k, err := credentialKEK(env)
		if err != nil {
			return nil, fmt.Errorf("backend %s: open the KEK for credential_ref %q: %w", id, bc.CredentialRef, err)
		}
		fields, err := credref.Load(env, k, bc.CredentialRef)
		if err != nil {
			return nil, fmt.Errorf("backend %s: %w", id, err)
		}
		for _, c := range creds {
			setCredential(s, name, c, fields[c.field], env)
		}
	case bc.AllowEnvCredentials:
		for _, c := range creds {
			if env == nil {
				break
			}
			for _, n := range c.names {
				if v := env(n); v != "" {
					setCredential(s, name, c, v, env)
					break
				}
			}
		}
	default:
		var present []string
		for _, c := range creds {
			for _, n := range c.names {
				if env != nil && env(n) != "" {
					present = append(present, n)
				}
			}
		}
		if len(present) > 0 {
			return nil, fmt.Errorf("%w: %s. Store them with 'keylatch backend login %s' and set backends.%s.credential_ref, or set backends.%s.allow_env_credentials to true",
				ErrEnvCredentials, strings.Join(present, ", "), id, id, id)
		}
	}
	return s, nil
}

// setCredential puts one credential into the settings. The 1Password CLI
// reads its service account token from the environment, so for op the value
// goes into the lookup the backend runs its CLI with.
func setCredential(s map[string]interface{}, backendName string, c envCredential, value string, env llmcontext.Lookup) {
	if backendName == "op" {
		base := env
		s["env"] = llmcontext.Lookup(func(k string) string {
			if k == "OP_SERVICE_ACCOUNT_TOKEN" {
				return value
			}
			if base == nil {
				return ""
			}
			return base(k)
		})
		return
	}
	if value != "" {
		s[c.field] = value
	}
}
