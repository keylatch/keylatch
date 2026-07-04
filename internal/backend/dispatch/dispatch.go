// Package dispatch selects and caches the configured backend for the lifetime
// of one keylatch process. Resolution order (first non-empty wins):
//  1. cfg.Backend (from ~/.keylatch/config.json)
//  2. KEYLATCH_BACKEND env var
//  3. default: "file"
//
// Backends are registered via init() side-effects (import the
// internal/backend/all package to pull in all built-in backends).
package dispatch

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// ErrUnknownBackend is returned when the requested backend name is not
// registered in backend.Default. Known lists the registered backend names at
// the time of the error.
type ErrUnknownBackend struct {
	Name  string
	Known []string
}

func (e ErrUnknownBackend) Error() string {
	if len(e.Known) == 0 {
		return fmt.Sprintf("unknown backend %q; no backends registered (import internal/backend/all)", e.Name)
	}
	return fmt.Sprintf("unknown backend %q; valid values: %s", e.Name, strings.Join(e.Known, ", "))
}

// nolint:gochecknoglobals
var (
	mu       sync.Mutex
	once     sync.Once
	instance backend.Backend
	initErr  error
)

// Select returns the configured Backend, instantiated once per process.
// Thread-safe; uses sync.Once for caching.
func Select(ctx context.Context, cfg config.Config, env llmcontext.Lookup) (backend.Backend, error) {
	once.Do(func() {
		instance, initErr = selectBackend(ctx, cfg, env)
	})
	return instance, initErr
}

// ClearCached clears the cached backend instance so the next call to Select
// will re-resolve the backend. Used by production commands that switch the
// active backend (e.g. keylatch keychain, keylatch op, keylatch bw).
//
// NOT goroutine-safe against concurrent Select() calls. Callers must ensure
// no Select() is in flight before calling ClearCached.
func ClearCached() {
	mu.Lock()
	defer mu.Unlock()
	once = sync.Once{} // not goroutine-safe against concurrent Select()
	instance = nil
	initErr = nil
}

// selectBackend performs the actual backend resolution (called once via Once).
func selectBackend(ctx context.Context, cfg config.Config, env llmcontext.Lookup) (backend.Backend, error) {
	// Resolution order: cfg.Backend → env("KEYLATCH_BACKEND") → "file"
	name := cfg.Backend
	if name == "" && env != nil {
		name = env("KEYLATCH_BACKEND")
	}
	if name == "" {
		name = "file"
	}
	canonicalName, ok := backend.CanonicalName(name)
	if !ok {
		return nil, ErrUnknownBackend{Name: name, Known: backend.KnownCanonicalNames()}
	}
	name = canonicalName

	// Build Settings from config fields so factory functions can decode them.
	settings := buildSettings(name, cfg, env)

	factory, ok := backend.Default.Get(name)
	if !ok {
		return nil, ErrUnknownBackend{Name: name, Known: backend.Default.List()}
	}

	return factory(ctx, backend.BackendConfig{Name: name, Settings: settings})
}

// buildSettings constructs the Settings map for the given backend name from
// the config and environment. Factories decode this map into typed structs.
func buildSettings(name string, cfg config.Config, env llmcontext.Lookup) map[string]interface{} {
	s := make(map[string]interface{})

	switch name {
	case "file":
		dir := cfg.DataDir
		if dir == "" && env != nil {
			dir = env("KEYLATCH_VAULT_PATH")
		}
		if dir == "" && env != nil {
			dir = env("KEYLATCH_DATA_DIR")
		}
		if dir == "" && env != nil {
			dir = paths.Vault(env)
		}
		if dir == "" && env == nil {
			dir = paths.Vault(llmcontext.DefaultLookup)
		}
		s["data_dir"] = dir

		// Allow KEYLATCH_KEYRING_PATH env var to override the keyring location.
		// The factory falls back to paths.KeyringPath(DefaultLookup) when this is empty.
		if env != nil {
			if krPath := env("KEYLATCH_KEYRING_PATH"); krPath != "" {
				s["keyring_path"] = krPath
			}
		}

	case "keychain":
		// keychain options are resolved from defaults inside the factory.
		// Pass runner/env references via dedicated keys.
		s["env"] = env

	case "op":
		s["env"] = env
		if cfg.OP != nil {
			s["vault"] = cfg.OP.Vault
			s["bin"] = cfg.OP.Bin
		}
		if env != nil {
			setIfEnv(s, "vault", env, "KEYLATCH_OP_VAULT")
			setIfEnv(s, "bin", env, "KEYLATCH_OP_BIN")
		}

	case "bw":
		s["env"] = env
		if cfg.BW != nil {
			s["server"] = cfg.BW.Server
			s["folder"] = cfg.BW.Folder
			s["collection"] = cfg.BW.Collection
			s["bin"] = cfg.BW.Bin
		}
		if env != nil {
			setIfEnv(s, "server", env, "KEYLATCH_BW_SERVER")
			setIfEnv(s, "folder", env, "KEYLATCH_BW_FOLDER")
			setIfEnv(s, "collection", env, "KEYLATCH_BW_COLLECTION")
			setIfEnv(s, "bin", env, "KEYLATCH_BW_BIN")
		}

	case "proton-pass":
		s["env"] = env
		if env != nil {
			setIfEnv(s, "vault", env, "KEYLATCH_PROTON_PASS_VAULT")
			setIfEnv(s, "bin", env, "KEYLATCH_PROTON_PASS_BIN")
			setIfEnv(s, "item_prefix", env, "KEYLATCH_PROTON_PASS_ITEM_PREFIX")
		}

	case "keeper":
		if env != nil {
			setIfEnv(s, "bin", env, "KEYLATCH_KEEPER_BIN")
			setIfEnv(s, "account_uid", env, "KEYLATCH_KEEPER_ACCOUNT_UID")
		}

	case "lastpass":
		if env != nil {
			setIfEnv(s, "bin", env, "KEYLATCH_LASTPASS_BIN")
			setIfEnv(s, "username", env, "KEYLATCH_LASTPASS_USERNAME")
		}

	case "vault":
		if env != nil {
			setIfEnv(s, "address", env, "KEYLATCH_VAULT_ADDR", "VAULT_ADDR")
			setIfEnv(s, "token", env, "KEYLATCH_VAULT_TOKEN", "VAULT_TOKEN")
			setIfEnv(s, "role_id", env, "KEYLATCH_VAULT_ROLE_ID")
			setIfEnv(s, "secret_id", env, "KEYLATCH_VAULT_SECRET_ID")
			setIfEnv(s, "mount", env, "KEYLATCH_VAULT_MOUNT")
			setIfEnv(s, "kv_version", env, "KEYLATCH_VAULT_KV_VERSION")
			setIfEnv(s, "namespace", env, "KEYLATCH_VAULT_NAMESPACE", "VAULT_NAMESPACE")
		}

	case "aws-sm":
		if env != nil {
			setIfEnv(s, "region", env, "KEYLATCH_AWS_SM_REGION", "AWS_REGION", "AWS_DEFAULT_REGION")
			setIfEnv(s, "access_key_id", env, "KEYLATCH_AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID")
			setIfEnv(s, "secret_access_key", env, "KEYLATCH_AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY")
			setIfEnv(s, "force_delete", env, "KEYLATCH_AWS_SM_FORCE_DELETE")
		}

	case "gcp-sm":
		if env != nil {
			setIfEnv(s, "project_id", env, "KEYLATCH_GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT")
			setIfEnv(s, "credentials_json", env, "KEYLATCH_GCP_CREDENTIALS_JSON", "GOOGLE_APPLICATION_CREDENTIALS")
		}

	case "azure-kv":
		if env != nil {
			setIfEnv(s, "vault_url", env, "KEYLATCH_AZURE_KV_URL", "KEYLATCH_AZURE_VAULT_URL")
			setIfEnv(s, "tenant_id", env, "KEYLATCH_AZURE_TENANT_ID", "AZURE_TENANT_ID")
			setIfEnv(s, "client_id", env, "KEYLATCH_AZURE_CLIENT_ID", "AZURE_CLIENT_ID")
			setIfEnv(s, "client_secret", env, "KEYLATCH_AZURE_CLIENT_SECRET", "AZURE_CLIENT_SECRET")
		}

	case "doppler":
		if env != nil {
			setIfEnv(s, "token", env, "KEYLATCH_DOPPLER_TOKEN", "DOPPLER_TOKEN")
			setIfEnv(s, "project", env, "KEYLATCH_DOPPLER_PROJECT", "DOPPLER_PROJECT")
			setIfEnv(s, "config", env, "KEYLATCH_DOPPLER_CONFIG", "DOPPLER_CONFIG")
			setIfEnv(s, "base_url", env, "KEYLATCH_DOPPLER_BASE_URL")
		}

	case "infisical":
		if env != nil {
			setIfEnv(s, "base_url", env, "KEYLATCH_INFISICAL_BASE_URL", "INFISICAL_API_URL")
			setIfEnv(s, "client_id", env, "KEYLATCH_INFISICAL_CLIENT_ID", "INFISICAL_CLIENT_ID")
			setIfEnv(s, "client_secret", env, "KEYLATCH_INFISICAL_CLIENT_SECRET", "INFISICAL_CLIENT_SECRET")
			setIfEnv(s, "workspace_id", env, "KEYLATCH_INFISICAL_WORKSPACE_ID", "INFISICAL_WORKSPACE_ID")
			setIfEnv(s, "environment", env, "KEYLATCH_INFISICAL_ENVIRONMENT", "INFISICAL_ENVIRONMENT")
			setIfEnv(s, "secret_path", env, "KEYLATCH_INFISICAL_SECRET_PATH", "INFISICAL_SECRET_PATH")
		}

	case "op-connect":
		if env != nil {
			setIfEnv(s, "connect_url", env, "KEYLATCH_OP_CONNECT_URL", "OP_CONNECT_HOST")
			setIfEnv(s, "token", env, "KEYLATCH_OP_CONNECT_TOKEN", "OP_CONNECT_TOKEN")
			setIfEnv(s, "vault_id", env, "KEYLATCH_OP_CONNECT_VAULT_ID", "OP_CONNECT_VAULT_ID")
		}
	}

	return s
}

func setIfEnv(settings map[string]interface{}, key string, env llmcontext.Lookup, names ...string) {
	if existing, ok := settings[key]; ok {
		if v, ok := existing.(string); ok && v != "" {
			return
		}
	}
	for _, name := range names {
		if v := env(name); v != "" {
			settings[key] = v
			return
		}
	}
}
