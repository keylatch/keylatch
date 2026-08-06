// Package config handles loading and saving the keylatch configuration file.
// The Config struct contains only non-secret fields — secret values live in
// the backend, never in config.json.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	DefaultProviderRef string          `json:"default_provider_ref,omitempty"` // provider-ref URI stored by setup reference branch
	Gateway            *GatewayConfig  `json:"gateway,omitempty"`              // absent in 0.5
	OP                 *OPConfig       `json:"op,omitempty"`                   // absent in 0.5
	BW                 *BWConfig       `json:"bw,omitempty"`
	Audit              AuditConfig     `json:"audit"`
	UI                 UIConfig        `json:"ui"`
	Telemetry          TelemetryConfig `json:"telemetry"`
	// Operating mode selection.
	// Valid values: "standard" | "telemetry" | "canary" | "custom". Default: "standard".
	Mode   string            `json:"mode,omitempty"`   // operating mode (standard/telemetry/canary/custom)
	Custom *CustomModeConfig `json:"custom,omitempty"` // custom mode feature overrides

	// AllowUnverifiedSession is the permanent, config-file form of the
	// KEYLATCH_ALLOW_UNVERIFIED_SESSION=1 escape hatch (docker-server-security
	// raw-credential session gate hardening). When true, `keylatch get` and `keylatch run` in
	// direct/brokered runtime modes (the paths that expose a raw provider
	// credential to the child process) no longer require a signed session
	// ticket or a reachable keylatchd before proceeding. Gateway/proxy modes
	// are never affected by this flag either way — they never expose a raw
	// secret to begin with. Default: false (fail closed).
	AllowUnverifiedSession bool `json:"allow_unverified_session,omitempty"`
}

// CustomModeConfig holds per-feature flags for operating mode "custom".
// It mirrors runtime.CustomModeConfig but uses JSON tags for config persistence.
type CustomModeConfig struct {
	TelemetryEnabled       bool `json:"telemetry_enabled"`
	CanaryInjectionEnabled bool `json:"canary_injection_enabled"`
	ExperimentalGated      bool `json:"experimental_gated"`
}

// GatewayConfig holds gateway connection settings.
type GatewayConfig struct {
	Endpoint string `json:"endpoint"` // e.g. http://127.0.0.1:7878
	Mode     string `json:"mode"`     // "local" | "docker" | "hosted" | "off"
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
	return nil
}

// TelemetryConfig controls anonymous usage telemetry. Default: disabled.
// All emitted events are non-sensitive — no secret values, no file paths.
type TelemetryConfig struct {
	Enabled bool   `json:"enabled"`
	Sink    string `json:"sink,omitempty"` // "local" or "remote"
}

// AuditConfig controls audit logging.
type AuditConfig struct {
	Enabled            bool  `json:"enabled"`
	MaxSize            int64 `json:"max_size_bytes"`       // default 5 MiB
	RetentionDays      int   `json:"retention_days"`       // default: 30; valid range 1–3650
	SweepIntervalHours int   `json:"sweep_interval_hours"` // default: 24; 0 means use default, negative is invalid
}

// Validate checks AuditConfig field ranges and returns an actionable error for
// out-of-range values. Zero values are valid (callers treat them as "use default").
func (a *AuditConfig) Validate() error {
	if a.RetentionDays != 0 && (a.RetentionDays < 1 || a.RetentionDays > 3650) {
		return fmt.Errorf(
			"audit.retention_days=%d is out of range; set a value between 1 and 3650 (days), or remove the field to use the default of 30",
			a.RetentionDays,
		)
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
			RetentionDays:      30,
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
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // defer close of config file, error non-actionable in read path

	dec := json.NewDecoder(f)
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

	return c, nil
}

// Save writes c to path atomically (temp-file + rename) with mode 0o600.
// Security invariant: all config files must have mode 0o600.
func Save(path string, c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
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
