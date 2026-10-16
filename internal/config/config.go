// Package config handles loading and saving the keylatch configuration file.
// The Config struct contains only non-secret fields — secret values live in
// the backend, never in config.json.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// currentVersion is the schema version this code understands.
const currentVersion = 1

// Config is the on-disk shape of ~/.keylatch/config.json.
// Every field is non-secret. Secret values live in the backend, never here.
type Config struct {
	Version          int    `json:"version"`            // schema version, currently 1
	Backend          string `json:"backend"`            // "file" | "keychain" | "op" | "bw"
	DataDir          string `json:"data_dir,omitempty"` // file backend root; default ~/.keylatch/vault
	DefaultNamespace string `json:"default_namespace"`  // e.g. "default" or "personal"
	// NOTE: DefaultProviderRef is written here; keylatch run will read it to auto-populate --provider-ref.
	DefaultProviderRef string         `json:"default_provider_ref,omitempty"` // provider-ref URI stored by setup reference branch
	Gateway            *GatewayConfig `json:"gateway,omitempty"`              // absent in 0.5
	OP                 *OPConfig      `json:"op,omitempty"`                   // absent in 0.5
	BW                 *BWConfig      `json:"bw,omitempty"`
	Audit              AuditConfig    `json:"audit"`
	UI                 UIConfig       `json:"ui"`
	// Operating mode selection.
	// Valid values: "standard" | "canary" | "custom". Default: "standard".
	Mode   string            `json:"mode,omitempty"`   // operating mode (standard/canary/custom)
	Custom *CustomModeConfig `json:"custom,omitempty"` // custom mode feature overrides

	// AllowUnverifiedSession lets `keylatch get` and `keylatch run` in
	// raw-credential runtime modes expose a raw provider credential. Gateway
	// and proxy modes never do. Default: false (fail closed).
	AllowUnverifiedSession bool `json:"allow_unverified_session,omitempty"`

	// AllowInsecureFileKEK lets bootstrap keep the vault identity in a
	// plaintext file when no OS keyring and no terminal for a passphrase are
	// available. Only the operator's default config file is consulted for it:
	// no flag and no environment variable can switch it on. Default: false.
	AllowInsecureFileKEK bool `json:"allow_insecure_file_kek,omitempty"`

	// Connections holds per-connection policy keyed by connection name.
	// Only the operator's default config file is consulted for it.
	Connections map[string]ConnectionPolicy `json:"connections,omitempty"`

	// Backends holds per-backend credential settings keyed by backend id:
	// op, opconnect, vault, awssm, gcpsm, azurekv, doppler, infisical.
	Backends map[string]BackendCredentials `json:"backends,omitempty"`

	// CI holds the workload identities `keylatch ci exchange` accepts. Only
	// the operator's default config file is consulted for it.
	CI *CIConfig `json:"ci,omitempty"`
}

// CIConfig lists the CI workloads trusted to use connections.
type CIConfig struct {
	Trust []CITrust `json:"trust,omitempty"`
}

// CITrust names one CI workload and the connections it may use. A token must
// match every field that is set; Audience, Repositories and Refs are required.
type CITrust struct {
	// Provider is "github-actions" or "gitlab".
	Provider string `json:"provider"`
	// Issuer overrides the provider's issuer (self-managed GitLab).
	Issuer string `json:"issuer,omitempty"`
	// JWKSURL overrides the key set location, which is otherwise derived from
	// the issuer. It must be https.
	JWKSURL string `json:"jwks_url,omitempty"`
	// Audience is the value the job asks the CI provider to put in the token.
	Audience string `json:"audience"`
	// Repositories are owner/name (project path on GitLab); "*" matches one
	// path segment.
	Repositories []string `json:"repositories"`
	// Refs are full refs such as refs/heads/main or refs/tags/v*. A branch
	// and a tag of the same name are different refs.
	Refs []string `json:"refs"`
	// Environments restricts the deployment environment claim when set.
	Environments []string `json:"environments,omitempty"`
	// JobWorkflowRefs restricts the job_workflow_ref claim (the
	// ci_config_ref_uri claim on GitLab) when set.
	JobWorkflowRefs []string `json:"job_workflow_refs,omitempty"`
	// Connections are the only connections the exchanged session may use.
	Connections []string `json:"connections"`
	// MaxTTL is the session lifetime in seconds, 1-3600. Zero means 3600.
	MaxTTL int `json:"max_ttl,omitempty"`
}

// ConnectionPolicy is the policy attached to one connection.
type ConnectionPolicy struct {
	Mint *MintPolicy `json:"mint,omitempty"`
}

// MintPolicy governs `keylatch mint` for a connection.
type MintPolicy struct {
	GitHubApp *GitHubAppMintPolicy `json:"github_app,omitempty"`
}

// GitHubAppMintPolicy limits the installation tokens a GitHub App
// connection may mint. internal/policy/mint validates and applies it.
type GitHubAppMintPolicy struct {
	// Callers lists the caller kinds allowed to mint ("service", "host",
	// "human"). Empty means service and host. Agent sessions are never allowed.
	Callers []string `json:"callers,omitempty"`
	// PlaceholderCallers lists the caller kinds ("agent", "host", "human",
	// "service") that may run commands whose GitHub credential is a
	// placeholder the daemon's proxy replaces with a minted token. Empty means
	// none. The owner, repository, permission and lifetime limits below apply
	// to these sessions too.
	PlaceholderCallers []string          `json:"placeholder_callers,omitempty"`
	DenyOwners         []string          `json:"deny_owners,omitempty"`
	AllowOwners        []string          `json:"allow_owners,omitempty"`
	AllowRepos         []string          `json:"allow_repos,omitempty"`
	PermissionCeiling  map[string]string `json:"permission_ceiling,omitempty"`
	// MaxTTL is the longest token lifetime in seconds, 1–3600. Zero means 3600.
	MaxTTL int `json:"max_ttl,omitempty"`
}

// CustomModeConfig holds per-feature flags for operating mode "custom".
// It mirrors runtime.CustomModeConfig but uses JSON tags for config persistence.
type CustomModeConfig struct {
	CanaryInjectionEnabled bool `json:"canary_injection_enabled"`
	ExperimentalGated      bool `json:"experimental_gated"`
}

// BackendCredentials says where a remote backend's credential comes from.
// The credential itself never appears in the config.
type BackendCredentials struct {
	// CredentialRef names the credential stored by `keylatch backend login`,
	// wrapped by the KEK. It is read before anything in the environment.
	CredentialRef string `json:"credential_ref,omitempty"`
	// AllowEnvCredentials accepts credentials from environment variables
	// when no credential_ref is set. doctor warns while it is on.
	AllowEnvCredentials bool `json:"allow_env_credentials,omitempty"`
}

// RemoteBackendIDs are the backends that authenticate with a credential and so
// take BackendCredentials.
var RemoteBackendIDs = []string{"op", "opconnect", "vault", "awssm", "gcpsm", "azurekv", "doppler", "infisical"}

// BackendID maps a backend name as the registry spells it (aws-sm) to the id
// used in the config (awssm).
func BackendID(name string) string { return strings.ReplaceAll(name, "-", "") }

// validateBackends checks the credential settings of every configured backend.
func validateBackends(m map[string]BackendCredentials) error {
	for id, b := range m {
		if !slices.Contains(RemoteBackendIDs, id) {
			return fmt.Errorf("backends.%s: not a backend that takes credentials (one of %s)", id, strings.Join(RemoteBackendIDs, ", "))
		}
		if b.CredentialRef != "" && !ValidCredentialRef(b.CredentialRef) {
			return fmt.Errorf("backends.%s.credential_ref %q: use 1-64 letters, digits, '.', '_' or '-'", id, b.CredentialRef)
		}
	}
	return nil
}

// ValidCredentialRef reports whether ref is usable as a credential_ref.
func ValidCredentialRef(ref string) bool {
	if ref == "" || len(ref) > 64 || ref == "." || ref == ".." {
		return false
	}
	for _, r := range ref {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// GatewayConfig holds gateway connection settings.
type GatewayConfig struct {
	Endpoint string `json:"endpoint"` // e.g. http://127.0.0.1:7878
	Mode     string `json:"mode"`     // "local" | "docker" | "hosted" | "off"
	// MaxBody is the largest request body the gateway inspects and forwards,
	// in bytes (default 10 MiB). Larger bodies are rejected.
	MaxBody int64 `json:"max_body,omitempty"`
}

// OPConfig holds 1Password-specific settings.
type OPConfig struct {
	Vault string `json:"vault"` // KEYLATCH_OP_VAULT default value, e.g. "Keylatch"
	Bin   string `json:"bin"`   // explicit op binary path; "" means PATH lookup

	// Forward-compat team-mode fields. Not interpreted in single-user mode.
	ServiceAccountTokenRef string `json:"service_account_token_ref,omitempty"`
	OrgCollection          string `json:"org_collection,omitempty"`
}

// Validate applies defaults and validates the OPConfig fields.
// Returns an error if constraints are violated.
func (c *OPConfig) Validate() error {
	if c.Vault == "" {
		c.Vault = "Keylatch"
	}
	if c.Bin != "" && !strings.HasPrefix(c.Bin, "/") {
		return fmt.Errorf("op.bin must be an absolute path (got %q)", c.Bin)
	}
	return nil
}

// BWConfig holds Bitwarden/Vaultwarden settings.
type BWConfig struct {
	Server     string `json:"server,omitempty"` // Vaultwarden URL; empty for Bitwarden Cloud
	Folder     string `json:"folder,omitempty"`
	Collection string `json:"collection,omitempty"`
	// OrganizationID is the Bitwarden organization the vault belongs to.
	OrganizationID string `json:"organization_id,omitempty"`
	// Namespaces maps a namespace to the name of an organization collection
	// (for example "Work/infra"). A namespace that is not listed is refused.
	// It needs OrganizationID and replaces Folder and Collection.
	Namespaces map[string]string `json:"namespaces,omitempty"`
	// SessionTTL is how long `keylatch bw unlock` keeps a session, as a Go
	// duration (default 1h, at most 8h).
	SessionTTL string `json:"session_ttl,omitempty"`
	Bin        string `json:"bin"`

	// Forward-compat team-mode fields. Not interpreted in single-user mode.
	ServiceAccountTokenRef string `json:"service_account_token_ref,omitempty"`
	OrgCollection          string `json:"org_collection,omitempty"`
}

// ErrBWMutualExclusion is returned when both Folder and Collection are set.
type ErrBWMutualExclusion struct{}

func (e ErrBWMutualExclusion) Error() string {
	return "bw: folder and collection are mutually exclusive; set only one"
}

// Validate validates the BWConfig fields.
func (c *BWConfig) Validate() error {
	if c.Server != "" && !strings.HasPrefix(c.Server, "https://") {
		return fmt.Errorf("bw.server must use https:// (got %q); Keylatch never bypasses TLS verification", c.Server)
	}
	if c.Folder != "" && c.Collection != "" {
		return ErrBWMutualExclusion{}
	}
	if len(c.Namespaces) > 0 {
		if c.OrganizationID == "" {
			return fmt.Errorf("bw.namespaces needs bw.organization_id")
		}
		if c.Folder != "" || c.Collection != "" {
			return fmt.Errorf("bw.namespaces replaces bw.folder and bw.collection; set only one way to place items")
		}
		for ns, coll := range c.Namespaces {
			if strings.TrimSpace(ns) == "" || strings.TrimSpace(coll) == "" {
				return fmt.Errorf("bw.namespaces: a namespace and its collection must both be non-empty")
			}
		}
	}
	if c.SessionTTL != "" {
		d, err := time.ParseDuration(c.SessionTTL)
		if err != nil || d <= 0 {
			return fmt.Errorf("bw.session_ttl %q: use a positive duration such as 1h", c.SessionTTL)
		}
		if d > maxBWSessionTTL {
			return fmt.Errorf("bw.session_ttl %q is above the maximum of %s", c.SessionTTL, maxBWSessionTTL)
		}
	}
	return nil
}

// maxBWSessionTTL is the longest a cached Bitwarden session may live.
const maxBWSessionTTL = 8 * time.Hour

// AuditConfig controls audit logging.
type AuditConfig struct {
	Enabled            bool  `json:"enabled"`
	MaxSize            int64 `json:"max_size_bytes"`       // default 5 MiB
	RetentionDays      int   `json:"retention_days"`       // default: 365; valid range 1–3650
	SweepIntervalHours int   `json:"sweep_interval_hours"` // default: 24; 0 means use default, negative is invalid
	// RetainDays is the preferred name for RetentionDays and wins when both
	// are set.
	RetainDays int `json:"retain_days,omitempty"`
	// RetainFiles is how many rotated log files are kept (default 20).
	RetainFiles int `json:"retain_files,omitempty"`
}

// Validate checks AuditConfig field ranges and returns an actionable error for
// out-of-range values. Zero values are valid (callers treat them as "use default").
func (a *AuditConfig) Validate() error {
	if a.RetentionDays != 0 && (a.RetentionDays < 1 || a.RetentionDays > 3650) {
		return fmt.Errorf(
			"audit.retention_days=%d is out of range; set a value between 1 and 3650 (days), or remove the field to use the default of 365",
			a.RetentionDays,
		)
	}
	if a.RetainDays != 0 && (a.RetainDays < 1 || a.RetainDays > 3650) {
		return fmt.Errorf(
			"audit.retain_days=%d is out of range; set a value between 1 and 3650 (days), or remove the field to use the default of 365",
			a.RetainDays,
		)
	}
	if a.RetainFiles < 0 {
		return fmt.Errorf("audit.retain_files must be ≥ 0 (0 means use default of 20), got %d", a.RetainFiles)
	}
	// Zero means "use the default" (24 h); only negative values are errors.
	if a.SweepIntervalHours < 0 {
		return fmt.Errorf(
			"audit.sweep_interval_hours must be ≥ 0 (0 means use default of 24 hours), got %d",
			a.SweepIntervalHours,
		)
	}
	return nil
}

// UIConfig holds UI server settings.
type UIConfig struct {
	Bind string `json:"bind"` // default "127.0.0.1"
}

// VersionMismatch is returned by Load when the file version does not match
// the current schema version.
type VersionMismatch struct {
	Got  int
	Want int
}

func (e *VersionMismatch) Error() string {
	return fmt.Sprintf("config version mismatch: got %d, want %d", e.Got, e.Want)
}

// migrations maps a source schema version to the function that upgrades a
// Config from that version to the next one. Currently empty: v1 is the only
// version this build understands, so there is nothing to migrate yet. This
// is a scaffold — when currentVersion is bumped, add the v(N)->v(N+1) step
// here rather than reaching for a fresh config.Default() on every mismatch
// (see Migrate and loadConfigOrWarn in internal/cli/setup_cmd.go).
var migrations = map[int]func(Config) (Config, error){}

// Migrate upgrades c to currentVersion by walking the migrations chain.
// Returns an error if no migration is registered for c.Version (including
// when c.Version == currentVersion — callers should check that first via
// Load's *VersionMismatch and only call Migrate on an actual mismatch).
func Migrate(c Config) (Config, error) {
	for c.Version != currentVersion {
		step, ok := migrations[c.Version]
		if !ok {
			return Config{}, fmt.Errorf("no migration path from config version %d to %d", c.Version, currentVersion)
		}
		next, err := step(c)
		if err != nil {
			return Config{}, fmt.Errorf("migrate config from version %d: %w", c.Version, err)
		}
		c = next
	}
	return c, nil
}

// Default returns a Config populated with safe defaults.
func Default() Config {
	return Config{
		Version:          currentVersion,
		Backend:          "file",
		DefaultNamespace: "default",
		Audit: AuditConfig{
			Enabled:            true,
			MaxSize:            5 * 1024 * 1024, // 5 MiB
			RetentionDays:      365,
			SweepIntervalHours: 24,
		},
		UI: UIConfig{
			Bind: "127.0.0.1",
		},
	}
}

// Load reads and parses the config file at path. Unknown fields are rejected.
// Returns *VersionMismatch if version != 1.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	return LoadBytes(path, data)
}

// LoadBytes decodes and validates config content that the caller has already
// read from disk. Split out from Load so callers that must distinguish a
// read/IO failure (permission denied, transient I/O — the bytes were never
// even inspected) from a content-level failure (malformed JSON, unknown
// fields, version mismatch, failed validation — the bytes were read fine but
// are unusable) can read the file themselves first and classify accordingly.
// See internal/cli/setup_cmd.go's loadConfigOrWarn, which needs exactly this
// distinction to avoid silently resetting a config it was merely unable to
// open.
func LoadBytes(path string, data []byte) (Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}

	if c.Version != currentVersion {
		return Config{}, &VersionMismatch{Got: c.Version, Want: currentVersion}
	}

	if err := c.Audit.Validate(); err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	if err := validateBackends(c.Backends); err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}

	return c, nil
}

// Save writes c to path atomically (temp-file + rename) with mode 0o600,
// creating the config directory with mode 0o700 when it does not exist yet.
// Security invariant: all config files must have mode 0o600.
func Save(path string, c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file for config: %w", err)
	}
	tmpName := tmp.Name()

	// Ensure temp file is cleaned up on failure.
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close() // best-effort cleanup in error path
		return fmt.Errorf("chmod temp config: %w", err)
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // best-effort cleanup in error path
		return fmt.Errorf("write temp config: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp config to %q: %w", path, err)
	}

	success = true
	return nil
}
