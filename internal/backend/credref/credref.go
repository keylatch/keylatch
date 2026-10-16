// Package credref stores the credentials remote backends authenticate with
// (a Vault token, an AWS key pair, a Doppler token, ...) wrapped by the KEK,
// so nothing has to sit in an environment variable.
package credref

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// ErrNotFound means no credential is stored under the reference.
var ErrNotFound = errors.New("credref: no credential stored under this reference")

// Fields lists, per backend id, the settings that are credentials and so come
// from a stored reference (or, with allow_env_credentials, the environment).
var Fields = map[string][]string{
	"op":        {"service_account_token"},
	"opconnect": {"token"},
	"vault":     {"token", "role_id", "secret_id"},
	"awssm":     {"access_key_id", "secret_access_key"},
	"gcpsm":     {"credentials_json"},
	"azurekv":   {"client_secret"},
	"doppler":   {"token"},
	"infisical": {"client_id", "client_secret"},
	"bws":       {"access_token"},
	"sops":      {"age_key"},
}

// Path returns where the credential for ref is stored.
func Path(env llmcontext.Lookup, ref string) string {
	return filepath.Join(paths.ConfigDir(env), "backend-credentials", ref+".enc")
}

// Save stores fields under ref, wrapped by k, replacing an earlier value.
func Save(env llmcontext.Lookup, k kek.KEK, ref string, fields map[string]string) error {
	if !config.ValidCredentialRef(ref) {
		return fmt.Errorf("credref: invalid reference %q", ref)
	}
	blob, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("credref: encode: %w", err)
	}
	defer clear(blob)
	return kek.WriteSecret(Path(env, ref), k, blob)
}

// Load returns the fields stored under ref.
func Load(env llmcontext.Lookup, k kek.KEK, ref string) (map[string]string, error) {
	if !config.ValidCredentialRef(ref) {
		return nil, fmt.Errorf("credref: invalid reference %q", ref)
	}
	wrapped, err := os.ReadFile(Path(env, ref)) //nolint:gosec // G304: a validated reference under the config directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %q (run 'keylatch backend login')", ErrNotFound, ref)
	}
	if err != nil {
		return nil, fmt.Errorf("credref: read: %w", err)
	}
	blob, err := k.Unwrap(wrapped)
	if err != nil {
		return nil, fmt.Errorf("credref: unwrap %q: %w", ref, err)
	}
	defer clear(blob)
	var fields map[string]string
	if err := json.Unmarshal(blob, &fields); err != nil {
		return nil, fmt.Errorf("credref: decode %q: %w", ref, err)
	}
	return fields, nil
}
