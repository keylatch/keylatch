// Package backend defines the Backend interface and shared types that every
// credential store implementation must satisfy. This is the zero-dependency
// foundation that every other package imports.
package backend

import (
	"context"
	"time"

	"github.com/keylatch/keylatch/internal/vault/meta"
)

// Capability declares what a Backend can do beyond plain read/write.
type Capability int

const (
	CapList     Capability = iota // enumerate stored paths/services
	CapMetadata                   // metadata read without value decrypt
	CapVersions                   // versioned value writes
	CapImport                     // bulk import from another backend
	CapExport                     // bulk export
	CapACL                        // platform-level access control
	// CapNetworkedFetch indicates the backend makes direct HTTP/network calls
	// (distinct from backends that shell out to CLI tools which may use the network).
	CapNetworkedFetch
)

// ID is an opaque per-path accessor. Audit logs reference it (HMAC'd).
// Generated on first write; stable across reads.
type ID string

// Meta is value-free metadata associated with each secret path for
// manifest-based backends. meta.Meta replaces this at the interface level
// for versioned backends; this type is kept for internal manifest serialisation.
type Meta struct {
	Path       string    `json:"path"`     // canonical, e.g. "default/ai/openrouter/api_key"
	Accessor   ID        `json:"accessor"` // opaque handle
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Version    int       `json:"version"`               // current version
	Backend    string    `json:"backend"`               // "file" | "keychain" | "op" | "bw"
	SafeFields []string  `json:"safe_fields,omitempty"` // field names safe to log in plaintext
}

// Entry is a metadata-only listing element.
type Entry struct {
	Meta
	Exists bool `json:"exists"`
}

// Store is the in-memory representation of a backend snapshot, used by
// load-once-then-iterate operations (import/export). Always small (manifest
// + active values). Secret values are zeroed when (*Store).Close() is called.
type Store struct {
	Backend string
	Entries map[string][]byte
}

// Close zeroes all stored secret byte slices and clears the Entries map.
func (s *Store) Close() {
	for k, v := range s.Entries {
		for i := range v {
			v[i] = 0
		}
		delete(s.Entries, k)
	}
}

// Backend is the abstraction every credential source implements.
//
// Implementations MUST:
//  1. Never print secret values to stdout/stderr.
//  2. Return errors typed enough for the CLI to map to exit codes.
//  3. Hold open OS handles for the minimum time required (unlock → read → lock).
//  4. Check llmcontext.IsLLMSession in any code path that returns plaintext
//     values, and refuse unless caller goes through the runner/gateway path.
//
// The CLI owns user-facing output; backends own data.
type Backend interface {
	// Name returns the backend identifier ("file", "keychain", "op", "bw").
	Name() string

	// Capabilities returns the set of optional capabilities supported.
	Capabilities() []Capability

	// Get returns the plaintext bytes for a canonical path. The caller MUST
	// wipe the buffer when done. Returns ErrNotFound if absent, ErrLocked if
	// the backend cannot decrypt right now (sealed/missing passphrase/etc.).
	Get(ctx context.Context, path string) ([]byte, Meta, error)

	// Set writes a new value at path, creating or updating. The implementation
	// is responsible for atomic write semantics (temp + fsync + rename for
	// file backends; transactional add/update for Keychain).
	Set(ctx context.Context, path string, value []byte, meta Meta) error

	// Delete removes a path (and all versions, if backend supports versions).
	Delete(ctx context.Context, path string) error

	// List returns metadata-only entries under the given prefix. MUST NOT
	// decrypt values; safe to call when the backend is "sealed".
	List(ctx context.Context, prefix string) ([]Entry, error)

	// GetMeta returns value-free metadata only. Non-file backends return
	// ErrNotSupported. MUST NOT decrypt values.
	GetMeta(ctx context.Context, path string) (meta.Meta, error)

	// SetMeta writes value-free metadata atomically. Non-file backends return
	// ErrNotSupported.
	SetMeta(ctx context.Context, path string, m meta.Meta) error

	// ListMeta returns value-free metadata for all paths with the given prefix.
	// An empty prefix returns all metadata. Non-file backends return
	// ErrNotSupported. MUST NOT decrypt values.
	ListMeta(ctx context.Context, prefix string) ([]meta.Meta, error)

	// GetVersioned returns the raw (possibly encrypted) bytes for a specific
	// version of a path. Non-file backends return ErrNotSupported.
	GetVersioned(ctx context.Context, path string, version int) ([]byte, error)

	// SetVersioned writes raw bytes for a specific version of a path.
	// Non-file backends return ErrNotSupported.
	SetVersioned(ctx context.Context, path string, version int, value []byte) error

	// DeleteVersioned removes a specific version of a path. Idempotent.
	// Non-file backends return ErrNotSupported.
	DeleteVersioned(ctx context.Context, path string, version int) error

	// ID returns a stable unique identifier for this backend instance.
	// Used as the BackendID in AADBinding.
	ID() string

	// Close releases any open OS resources (file handles, keychain locks,
	// flocks). Idempotent.
	Close() error
}
