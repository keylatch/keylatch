// Package file implements the filesystem backend for keylatch.
// register.go self-registers the file backend in backend.Default via init().
package file

import (
	"context"
	"fmt"
	"os"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// FileConfig holds the typed configuration for the file backend.
type FileConfig struct {
	// DataDir is the root vault directory. Required.
	DataDir string `mapstructure:"data_dir"`

	// KeyringPath overrides the default keyring.json location.
	// Default: <KEYLATCH_CONFIG_DIR>/keyring/keyring.json
	KeyringPath string `mapstructure:"keyring_path"`
}

func init() {
	if err := backend.Default.Register("file", fileFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/file: %w", err))
	}
}

func fileFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	var typed FileConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("file backend: create decoder: %w", err)
	}

	if err := decoder.Decode(cfg.Settings); err != nil {
		return nil, fmt.Errorf("file backend: invalid settings: %w", err)
	}

	if typed.DataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("file backend: resolve data dir: %w", err)
		}
		typed.DataDir = home + "/.keylatch/vault"
	}

	// T-02-01: OpenWithKeyring is the only production path (S-INV-1).
	// If no keyring is configured, fail closed with a bootstrap hint.
	krPath := typed.KeyringPath
	if krPath == "" {
		krPath = paths.KeyringPath(llmcontext.DefaultLookup)
	}

	// Check if the keyring file exists. Absence means bootstrap has not been run.
	if _, err := os.Stat(krPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: keyring not found at %q", backend.ErrBootstrapRequired, krPath)
	} else if err != nil {
		return nil, fmt.Errorf("file backend: stat keyring: %w", err)
	}

	// Load the KEK from the platform keystore.
	// The KEK type is determined by what bootstrap recorded in the keyring file.
	// On error, fail closed with a bootstrap hint.
	k, err := loadPlatformKEK(krPath)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot load keyring KEK: %v — run 'keylatch bootstrap' first", backend.ErrBootstrapRequired, err)
	}

	kr, err := keyring.Open(krPath, k)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open keyring at %q: %v — run 'keylatch bootstrap' first", backend.ErrBootstrapRequired, krPath, err)
	}

	return OpenWithKeyring(Options{Dir: typed.DataDir}, kr)
}

// loadPlatformKEK reads the keyring file header to determine the KEK type and
// returns the appropriate platform KEK. Returns an error if the KEK cannot be
// loaded (platform keystore unavailable, bootstrap not run, etc.).
func loadPlatformKEK(krPath string) (kek.KEK, error) {
	// Read the KEK type from the keyring file without opening the full keyring.
	kf, err := keyring.ReadHeader(krPath)
	if err != nil {
		return nil, fmt.Errorf("read keyring header: %w", err)
	}

	// Phase 11: Roots-based keyrings (SchemaVersion=2) use trust adapters.
	// Phase 5 (legacy): use KEKType field.
	kekType := kf.KEKType
	if kekType == "" && len(kf.Roots) > 0 {
		// Phase 11 keyring — KEKType is embedded per-term and per-root.
		// For now, use the first root's type.
		kekType = string(kf.Roots[0].Spec.Type)
	}

	switch kekType {
	case "keychain":
		return kek.KeychainKEK("keylatch-vault-kek")
	case "passphrase":
		// Passphrase KEK requires interactive input — not supported at factory time.
		// The user must use 'keylatch bootstrap' or provide the passphrase via
		// a non-interactive path. Return a clear error.
		return nil, fmt.Errorf("passphrase KEK requires interactive input: run 'keylatch bootstrap' to configure a platform keystore KEK")
	case "age-env":
		// age-env KEK uses KEYLATCH_AGE_IDENTITY env var; salt from keyring file.
		// If KEYLATCH_AGE_IDENTITY is not set, fall back to the well-known bootstrap
		// identity path (~/.keylatch/keyring/identity) so the factory works without
		// requiring the user to set an env var when bootstrap created the identity.
		identityPath := llmcontext.DefaultLookup("KEYLATCH_AGE_IDENTITY")
		if identityPath == "" {
			identityPath = paths.KeyringIdentityPath(llmcontext.DefaultLookup)
		}
		return kek.AgeIdentityKEKFromPath(identityPath, kf.Salt)
	default:
		return nil, fmt.Errorf("unsupported KEK type %q: run 'keylatch bootstrap' to re-initialize", kekType)
	}
}
