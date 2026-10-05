// Package manifest is the single source of truth for what this Keylatch
// build supports. CLI help/doctor, the web UI, packaging and tests consume
// this manifest rather than hardcoding their own copy of the scope table.
package manifest

import "fmt"

// Status is the support level for one manifest entry.
type Status string

const (
	// Supported: enabled in this build. Fully wired and enforced.
	Supported Status = "supported"
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
			// Managers — backend registry IDs where one exists.
			{ID: "op", Category: CategoryManager, Status: Supported, Note: "1Password CLI; concurrent with bw in one broker process"},
			{ID: "bw", Category: CategoryManager, Status: Supported, Note: "Bitwarden CLI; concurrent with op in one broker process"},
			{ID: "vaultwarden", Category: CategoryManager, Status: Unavailable, Note: "needs a separately certified Bitwarden server profile"},
			{ID: "opconnect", Category: CategoryManager, Status: Unavailable, Note: "1Password Connect; enabled on demand"},
			{ID: "keeper", Category: CategoryManager, Status: Unavailable, Note: "enabled on demand"},
			{ID: "proton-pass", Category: CategoryManager, Status: Unavailable, Note: "enabled on demand"},
			{ID: "lastpass", Category: CategoryManager, Status: Unavailable, Note: "enabled on demand"},
			{ID: "keychain", Category: CategoryManager, Status: Unavailable, Note: "macOS is not a certified platform yet"},
			{ID: "file", Category: CategoryManager, Status: Unavailable, Note: "encrypted-file secret backend unavailable pending recovery, integrity and migration checks"},

			// Runtimes — internal/runtime, internal/runner driver mode names.
			{ID: "gateway_typed", Category: CategoryRuntime, Status: Supported, Note: "typed gateway actions; certified provider contract"},
			{ID: "gateway_sdk", Category: CategoryRuntime, Status: Supported, Note: "certified provider SDK routes only"},
			{ID: "gateway_proxy", Category: CategoryRuntime, Status: Unavailable, Note: "excluded pending redirect, authority and credential-boundary fixes"},
			{ID: "direct_brokered", Category: CategoryRuntime, Status: Unavailable, Note: "excluded: no exchange strategies are wired"},
			{ID: "direct_classic_sandboxed", Category: CategoryRuntime, Status: Unavailable, Note: "not equivalent to the isolated agent boundary; excluded"},

			// Platforms.
			{ID: "linux", Category: CategoryPlatform, Status: Supported, Note: "Linux broker plus isolated agent environment"},
			{ID: "macos", Category: CategoryPlatform, Status: Unavailable, Note: "not certified yet"},
			{ID: "windows", Category: CategoryPlatform, Status: Unavailable, Note: "not certified yet"},
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

// Enabled reports whether id may be used by this build. Only Supported
// entries are enabled — Experimental entries are always excluded, so no
// environment variable, feature flag, or config override can turn on an
// experimental credential path. This is the sole enforcement
// point consumers should call before allowing an operation to proceed.
func (m Manifest) Enabled(id string) bool {
	return m.Status(id) == Supported
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
