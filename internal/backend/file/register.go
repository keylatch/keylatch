// Package file implements the filesystem backend for keylatch.
// register.go self-registers the file backend in backend.Default via init().
package file

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

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
	// Default: paths.ResolveKeyringPath
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

	// OpenWithKeyring is the only production path.
	// If no keyring is configured, fail closed with a bootstrap hint.
	krPath := typed.KeyringPath
	if krPath == "" {
		krPath = paths.ResolveKeyringPath(llmcontext.DefaultLookup)
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
	k, err := LoadKeyringKEK(krPath)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot load keyring KEK: %v — run 'keylatch bootstrap' first", backend.ErrBootstrapRequired, err)
	}

	kr, err := keyring.Open(krPath, k)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open keyring at %q: %v — run 'keylatch bootstrap' first", backend.ErrBootstrapRequired, krPath, err)
	}

	return OpenWithKeyring(Options{Dir: typed.DataDir}, kr)
}

// LoadKeyringKEK reads the keyring file header to determine the KEK type and
// returns the appropriate platform KEK. Returns an error if the KEK cannot be
// loaded (platform keystore unavailable, bootstrap not run, etc.).
func LoadKeyringKEK(krPath string) (kek.KEK, error) {
	// Read the KEK type from the keyring file without opening the full keyring.
	kf, err := keyring.ReadHeader(krPath)
	if err != nil {
		return nil, fmt.Errorf("read keyring header: %w", err)
	}

	// Roots-based keyrings (SchemaVersion=2) use trust adapters.
	// Legacy keyrings use the KEKType field.
	kekType := kf.KEKType
	if kekType == "" && len(kf.Roots) > 0 {
		// Roots-based keyring — KEKType is embedded per-term and per-root.
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
		// An operator-supplied identity file is used as-is and never migrated.
		if identityPath := llmcontext.DefaultLookup("KEYLATCH_AGE_IDENTITY"); identityPath != "" {
			return kek.AgeIdentityKEKFromPath(identityPath, kf.Salt)
		}
		vi := kek.VaultIdentity{
			Path:  paths.KeyringIdentityPath(llmcontext.DefaultLookup),
			Store: kek.DefaultIdentityStore(),
		}
		secureVaultIdentity(vi, llmcontext.DefaultLookup, os.Stderr)
		return vi.KEK(kf.Salt)
	default:
		return nil, fmt.Errorf("unsupported KEK type %q: run 'keylatch bootstrap' to re-initialize", kekType)
	}
}

var plaintextIdentityWarned sync.Once

// secureVaultIdentity moves a plaintext identity left by an older install into
// the OS keyring. When that is impossible and the user has not opted into
// --insecure-file-kek, it warns once per process.
func secureVaultIdentity(vi kek.VaultIdentity, env llmcontext.Lookup, warn io.Writer) {
	loc, onDisk, err := vi.Location()
	if err != nil || !onDisk {
		return
	}
	if loc != kek.IdentityInKeyring && (loc == kek.IdentityInFileAcknowledged || kek.InsecureFileKEKRequested(env)) {
		return
	}
	moved, err := vi.MigrateToKeyring()
	if moved {
		fmt.Fprintf(warn, "keylatch: moved the vault key into %s and removed the plaintext file %s\n", vi.Store.Name(), vi.Path)
	}
	if err != nil {
		plaintextIdentityWarned.Do(func() {
			fmt.Fprintf(warn, "keylatch: WARNING: the vault key is stored in plaintext at %s and could not be moved into an OS keyring (%v). Any process running as your user can decrypt the vault offline. Run `keylatch doctor` for details, or `keylatch bootstrap --insecure-file-kek` to accept this.\n", vi.Path, err)
		})
	}
}
