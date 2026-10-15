// Package manifest is the single source of truth for what this Keylatch
// build supports. CLI help/doctor, the web UI, packaging and tests consume
// this manifest rather than hardcoding their own copy of the scope table.
package manifest

import "fmt"

// Status is the support level for one manifest entry.
type Status string

const (
	// Supported: enabled in this build. Fully wired, enforced and covered by
	// a live compliance suite.
	Supported Status = "supported"
	// Preview: enabled, but not yet certified on this platform or path.
	Preview Status = "preview"
	// Community: builds and passes fake-based unit tests only. Listed but
	// never enabled by this manifest; use needs an explicit opt-in.
	Community Status = "community"
	// Deprecated: kept for migration only and removed in a later release.
	// Never enabled by this manifest.
	Deprecated Status = "deprecated"
	// Unavailable: gated out of this build. Unreachable via CLI/API/MCP/UI
	// entry points, regardless of feature flags or environment overrides.
	Unavailable Status = "unavailable"
	// Experimental: exists in source but is neither certified nor gated as a
	// release boundary. Never enabled — see Enabled.
	Experimental Status = "experimental"
)

// Category groups related entries.
type Category string

const (
	CategoryManager  Category = "manager"  // password/secret managers and backends
	CategoryRuntime  Category = "runtime"  // agent execution/transport modes
	CategoryFeature  Category = "feature"  // cross-cutting product features
	CategoryPlatform Category = "platform" // deployment OS/packaging targets
)

// Entry describes one manifest-tracked capability.
type Entry struct {
	// ID is a stable, lowercase, machine-readable identifier. For managers
	// and runtimes this matches the identifier used elsewhere in the
	// codebase (e.g. backend registry IDs, runtime mode names) where one
	// exists.
	ID       string
	Category Category
	Status   Status
	// Note explains the disposition in one line — why it's supported,
	// gated, or experimental, and what (if anything) unlocks it later.
	Note string
}

// Manifest is an ordered, immutable set of entries for one build.
type Manifest struct {
	Entries []Entry
}

// Current returns the support manifest of this build.
func Current() Manifest {
	return Manifest{
		Entries: []Entry{
			// Managers — backend registry IDs; tiers follow the backend support policy.
			{ID: "bw", Category: CategoryManager, Status: Supported, Note: "Bitwarden CLI, including Vaultwarden servers"},
			{ID: "op", Category: CategoryManager, Status: Supported, Note: "1Password CLI"},
			{ID: "file", Category: CategoryManager, Status: Supported, Note: "encrypted in-user file store"},
			{ID: "vault", Category: CategoryManager, Status: Community, Note: "HashiCorp Vault KV; no live suite yet"},
			{ID: "awssm", Category: CategoryManager, Status: Community, Note: "AWS Secrets Manager; no live suite yet"},
			{ID: "gcpsm", Category: CategoryManager, Status: Community, Note: "Google Cloud Secret Manager; no live suite"},
			{ID: "azurekv", Category: CategoryManager, Status: Community, Note: "Azure Key Vault; no live suite"},
			{ID: "doppler", Category: CategoryManager, Status: Community, Note: "Doppler; no live suite"},
			{ID: "infisical", Category: CategoryManager, Status: Community, Note: "Infisical; no live suite"},
			{ID: "opconnect", Category: CategoryManager, Status: Community, Note: "1Password Connect server; no live suite"},
			{ID: "keychain", Category: CategoryManager, Status: Deprecated, Note: "macOS Keychain secrets; the Keychain stays as a key store, not as a backend"},
			{ID: "keeper", Category: CategoryManager, Status: Deprecated, Note: "vendor CLI sessions are directly callable by an agent, so it cannot be brokered"},
			{ID: "lastpass", Category: CategoryManager, Status: Deprecated, Note: "vendor CLI sessions are directly callable by an agent, so it cannot be brokered"},
			{ID: "proton-pass", Category: CategoryManager, Status: Deprecated, Note: "vendor CLI sessions are directly callable by an agent, so it cannot be brokered"},

			// Runtimes — internal/runtime, internal/runner driver mode names.
			{ID: "gateway_typed", Category: CategoryRuntime, Status: Supported, Note: "typed gateway actions; certified provider contract"},
			{ID: "gateway_sdk", Category: CategoryRuntime, Status: Supported, Note: "certified provider SDK routes only"},
			{ID: "placeholder", Category: CategoryRuntime, Status: Supported, Note: "tier D3 placeholder substitution; Linux only, proven by the containment tests"},
			{ID: "gateway_proxy", Category: CategoryRuntime, Status: Unavailable, Note: "excluded pending redirect, authority and credential-boundary fixes"},
			{ID: "direct_brokered", Category: CategoryRuntime, Status: Unavailable, Note: "excluded: no exchange strategies are wired"},

			// Platforms.
			{ID: "linux", Category: CategoryPlatform, Status: Supported, Note: "Linux broker plus isolated agent environment"},
			{ID: "macos", Category: CategoryPlatform, Status: Preview, Note: "in-user mode only; no broker daemon yet"},
			{ID: "windows", Category: CategoryPlatform, Status: Preview, Note: "in-user mode only; no broker daemon yet"},
			{ID: "tauri_desktop", Category: CategoryPlatform, Status: Unavailable, Note: "packaged desktop excluded"},

			// Cross-cutting features — explicit exclusions list.
			{ID: "admin", Category: CategoryFeature, Status: Unavailable, Note: "team/admin console excluded"},
			{ID: "team", Category: CategoryFeature, Status: Unavailable, Note: "team policy and delegated identities are not shipped yet"},
			{ID: "sso", Category: CategoryFeature, Status: Unavailable, Note: "OIDC/SSO excluded"},
			{ID: "hardware_attestation", Category: CategoryFeature, Status: Unavailable, Note: "hardware attestation/approval claims excluded"},
			{ID: "approval_inbox", Category: CategoryFeature, Status: Unavailable, Note: "approval inbox/actions/streams excluded; approval-required operations deny honestly"},
			{ID: "hosted_telemetry", Category: CategoryFeature, Status: Unavailable, Note: "hosted telemetry excluded"},
			{ID: "receipt_sharing", Category: CategoryFeature, Status: Unavailable, Note: "hosted receipt sharing excluded"},
			{ID: "community_loading", Category: CategoryFeature, Status: Unavailable, Note: "community template installation/loading excluded"},
			{ID: "manager_mutation", Category: CategoryFeature, Status: Unavailable, Note: "reconnect changes a local reference only; create/update/delete/rotate on the manager itself is excluded"},
		},
	}
}

// Lookup returns the entry with the given ID, if present.
func (m Manifest) Lookup(id string) (Entry, bool) {
	for _, e := range m.Entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// Status returns the status of id, or Unavailable if id is not tracked by
// the manifest. Default-deny: an untracked ID is never treated as usable.
func (m Manifest) Status(id string) Status {
	if e, ok := m.Lookup(id); ok {
		return e.Status
	}
	return Unavailable
}

// Enabled reports whether id may be used by this build. Only Supported and
// Preview entries are enabled — Community, Deprecated and Experimental entries
// are always excluded, so no environment variable, feature flag, or config
// override can turn on an uncertified credential path. This is the sole
// enforcement point consumers should call before allowing an operation to
// proceed.
func (m Manifest) Enabled(id string) bool {
	s := m.Status(id)
	return s == Supported || s == Preview
}

// ByCategory returns entries in category, preserving manifest order.
func (m Manifest) ByCategory(category Category) []Entry {
	var out []Entry
	for _, e := range m.Entries {
		if e.Category == category {
			out = append(out, e)
		}
	}
	return out
}

// String renders an entry as "id: status (note)" for CLI/log output.
func (e Entry) String() string {
	return fmt.Sprintf("%s: %s (%s)", e.ID, e.Status, e.Note)
}
