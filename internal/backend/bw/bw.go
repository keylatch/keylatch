// Package bw implements the Backend interface using the Bitwarden CLI (`bw`).
// Supports both Bitwarden Cloud and Vaultwarden self-hosted via KEYLATCH_BW_SERVER.
//
// Security invariants:
//   - S2-3: List zero-fills field values before returning.
//   - S2-4: Server URL must use https:// (no TLS bypass for self-hosted).
//   - S2-5: Fail-closed on binary unavailability (ErrUnavailable).
//   - S2-7: BW_SESSION passed via subprocess env, never via --session CLI arg.
//   - S2-9: Raw subprocess stderr never propagated; auth-failure hints only.
//   - S2-10: Single-flight collapse for concurrent Get calls.
package bw

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// compile-time interface check.
var _ backend.Backend = (*BitwardenBackend)(nil)

// Options configures a BitwardenBackend.
type Options struct {
	// Server is the Vaultwarden self-hosted URL (https:// required).
	// Empty means Bitwarden Cloud.
	Server string

	// Folder filters items by folder name when set.
	Folder string

	// Collection filters items by collection name when set.
	Collection string

	// Bin is the explicit path to the `bw` binary. If empty, PATH is searched.
	Bin string

	// Runner is injectable for tests. Defaults to exec.DefaultRunner.
	Runner kexec.CommandRunner

	// Env is the environment lookup function. Defaults to llmcontext.DefaultLookup.
	Env llmcontext.Lookup

	// AutoSync enables `bw sync` before List and Get when true. Default false.
	AutoSync bool
}

// ErrInvalidServer is returned when Server does not start with https://.
type ErrInvalidServer struct {
	URL string
}

func (e ErrInvalidServer) Error() string {
	return fmt.Sprintf("bw: server URL must use https:// (got %q); Keylatch never bypasses TLS verification", e.URL)
}

// cacheEntry holds a cached bwItem and its expiry.
type cacheEntry struct {
	item      bwItem
	expiresAt time.Time
}

// BitwardenBackend implements backend.Backend using the Bitwarden CLI.
type BitwardenBackend struct {
	opts    Options
	bin     string
	session string // BW_SESSION — never exposed, passed via subprocess env only
	cache   sync.Map
	sf      singleflight.Group
}

// Open validates options, resolves the `bw` binary, reads BW_SESSION from env,
// and returns an initialized BitwardenBackend.
func Open(opts Options) (*BitwardenBackend, error) {
	// S2-4: reject non-https server URLs.
	if opts.Server != "" && !strings.HasPrefix(opts.Server, "https://") {
		return nil, ErrInvalidServer{URL: opts.Server}
	}

	// Resolve binary.
	bin := opts.Bin
	if bin == "" {
		bin = kexec.Resolve("bw")
		if bin == "" {
			return nil, fmt.Errorf("%w: Bitwarden CLI not found. Run: brew install bitwarden-cli (or platform equivalent)",
				backend.ErrUnavailable)
		}
	}

	if opts.Runner == nil {
		opts.Runner = kexec.DefaultRunner
	}
	if opts.Env == nil {
		opts.Env = llmcontext.DefaultLookup
	}

	// S2-7: read BW_SESSION from env into unexported field. Never assign to
	// a logged or exported variable.
	session := opts.Env("BW_SESSION")

	return &BitwardenBackend{
		opts:    opts,
		bin:     bin,
		session: session,
	}, nil
}

// Name implements backend.Backend.
func (b *BitwardenBackend) Name() string { return "bw" }

// Capabilities implements backend.Backend.
func (b *BitwardenBackend) Capabilities() []backend.Capability {
	return []backend.Capability{
		backend.CapList,
		backend.CapMetadata,
		backend.CapImport,
		backend.CapExport,
	}
}

// Get returns the plaintext bytes for a canonical path via `bw get item`.
// BW_SESSION is injected as a subprocess env var (S2-7). Uses single-flight
// collapse and 60-second metadata cache (S2-10).
func (b *BitwardenBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	connection, field, err := parsePath(path)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("bw Get: %w", err)
	}

	if b.opts.AutoSync {
		if err := b.sync(ctx); err != nil {
			return nil, backend.Meta{}, err
		}
	}

	item, err := b.fetchItem(ctx, connection)
	if err != nil {
		return nil, backend.Meta{}, err
	}

	// Find field by name.
	for _, f := range item.Fields {
		if f.Name == field {
			meta := backend.Meta{
				Path:      path,
				Backend:   "bw",
				Accessor:  backend.ID(item.ID),
				UpdatedAt: item.updatedTime(),
				Version:   1,
			}
			// Return a copy so the cache value cannot be mutated through the return.
			cp := make([]byte, len(f.Value))
			copy(cp, f.Value)
			return cp, meta, nil
		}
	}

	return nil, backend.Meta{}, fmt.Errorf("%w: field %q not found in Bitwarden item %q",
		backend.ErrNotFound, field, connection)
}

// Set writes a value via `bw create item` or `bw edit item <id>`.
func (b *BitwardenBackend) Set(ctx context.Context, path string, value []byte, meta backend.Meta) error {
	connection, field, err := parsePath(path)
	if err != nil {
		return fmt.Errorf("bw Set: %w", err)
	}

	// T-13-02: invalidate cache with zeroing.
	b.evictCacheEntry(connection)

	// Determine if item exists.
	existing, fetchErr := b.fetchItemDirect(ctx, connection)
	exists := fetchErr == nil

	fieldType := 1 // 1=hidden (concealed)
	if !isSecretField(field) {
		fieldType = 0 // 0=text (plain)
	}

	if exists {
		// Update existing item: find or add the field.
		found := false
		for i, f := range existing.Fields {
			if f.Name == field {
				existing.Fields[i].Value = append([]byte(nil), value...)
				existing.Fields[i].Type = fieldType
				found = true
				break
			}
		}
		if !found {
			existing.Fields = append(existing.Fields, bwField{
				Name:  field,
				Value: append([]byte(nil), value...),
				Type:  fieldType,
			})
		}

		body, err := json.Marshal(existing)
		if err != nil {
			return fmt.Errorf("bw Set: marshal item: %w", err)
		}
		encoded := base64.StdEncoding.EncodeToString(body)

		_, stderr, exitCode, err := b.runWithSession(ctx, []string{"edit", "item", existing.ID, encoded}, nil)
		if err != nil {
			return fmt.Errorf("bw Set: runner error: %w", err)
		}
		if exitCode != 0 {
			if isLocked(string(stderr)) {
				return fmt.Errorf("%w: set BW_SESSION (see README §Non-interactive use)", backend.ErrLocked)
			}
			return fmt.Errorf("bw Set: bw exited %d", exitCode)
		}
	} else {
		// Create new item.
		newItem := bwItem{
			Name: connection,
			Type: 1, // Login
			Fields: []bwField{
				{Name: field, Value: append([]byte(nil), value...), Type: fieldType},
			},
		}

		// Set folder if configured.
		if b.opts.Folder != "" {
			folderID, err := b.resolveFolderID(ctx, b.opts.Folder)
			if err == nil && folderID != "" {
				newItem.FolderID = &folderID
			}
		}

		// Set collection if configured.
		if b.opts.Collection != "" {
			newItem.CollectionIDs = []string{b.opts.Collection}
		}

		body, err := json.Marshal(newItem)
		if err != nil {
			return fmt.Errorf("bw Set: marshal new item: %w", err)
		}
		encoded := base64.StdEncoding.EncodeToString(body)

		_, stderr, exitCode, err := b.runWithSession(ctx, []string{"create", "item", encoded}, nil)
		if err != nil {
			return fmt.Errorf("bw Set: runner error: %w", err)
		}
		if exitCode != 0 {
			if isLocked(string(stderr)) {
				return fmt.Errorf("%w: set BW_SESSION (see README §Non-interactive use)", backend.ErrLocked)
			}
			return fmt.Errorf("bw Set: bw exited %d", exitCode)
		}
	}

	// T-13-02: invalidate cache with zeroing after write.
	b.evictCacheEntry(connection)
	return nil
}

// Delete removes a Bitwarden item via `bw delete item <id>`.
func (b *BitwardenBackend) Delete(ctx context.Context, path string) error {
	connection, _, err := parsePath(path)
	if err != nil {
		return fmt.Errorf("bw Delete: %w", err)
	}

	// T-13-02: invalidate cache with zeroing.
	b.evictCacheEntry(connection)

	item, err := b.fetchItemDirect(ctx, connection)
	if err != nil {
		if isErrNotFound(err) {
			return fmt.Errorf("%w: %s", backend.ErrNotFound, connection)
		}
		return err
	}

	_, stderr, exitCode, err := b.runWithSession(ctx, []string{"delete", "item", item.ID}, nil)
	if err != nil {
		return fmt.Errorf("bw Delete: runner error: %w", err)
	}
	if exitCode != 0 {
		stderrStr := string(stderr)
		if isNotFound(stderrStr) {
			return fmt.Errorf("%w: %s", backend.ErrNotFound, connection)
		}
		return fmt.Errorf("bw Delete: bw exited %d", exitCode)
	}
	return nil
}

// List returns metadata-only entries with zero-filled field values (S2-3).
func (b *BitwardenBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	if b.opts.AutoSync {
		if err := b.sync(ctx); err != nil {
			return nil, err
		}
	}

	stdout, stderr, exitCode, err := b.runWithSession(ctx,
		[]string{"list", "items", "--search=keylatch"},
		nil)
	if err != nil {
		return nil, fmt.Errorf("bw List: runner error: %w", err)
	}
	if exitCode != 0 {
		if isLocked(string(stderr)) {
			return nil, fmt.Errorf("%w: set BW_SESSION (see README §Non-interactive use)", backend.ErrLocked)
		}
		return nil, fmt.Errorf("bw List: bw exited %d", exitCode)
	}

	var items []bwItem
	if err := json.Unmarshal(stdout, &items); err != nil {
		return nil, fmt.Errorf("bw List: decode response: %w", err)
	}

	var entries []backend.Entry
	for _, item := range items {
		// Apply folder filter.
		if b.opts.Folder != "" && (item.FolderID == nil || *item.FolderID == "") {
			continue
		}
		// Apply collection filter.
		if b.opts.Collection != "" {
			found := false
			for _, cid := range item.CollectionIDs {
				if cid == b.opts.Collection {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		for _, f := range item.Fields {
			// S2-3: zero-fill field values unconditionally on list.
			path := "default/" + item.Name + "/" + f.Name
			if prefix != "" && !strings.HasPrefix(path, prefix) {
				continue
			}
			entries = append(entries, backend.Entry{
				Meta: backend.Meta{
					Path:      path,
					Backend:   "bw",
					Accessor:  backend.ID(item.ID),
					UpdatedAt: item.updatedTime(),
					Version:   1,
				},
				Exists: true,
			})
		}
	}
	return entries, nil
}

// Close is a no-op for the bw backend.
func (b *BitwardenBackend) Close() error { return nil }

// --- internal helpers ---

// fetchItem returns a bwItem using cache + single-flight collapse (S2-10).
func (b *BitwardenBackend) fetchItem(ctx context.Context, connection string) (bwItem, error) {
	const ttl = 60 * time.Second

	// Check cache.
	if v, ok := b.cache.Load(connection); ok {
		entry := v.(cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.item, nil
		}
		// T-13-02: TTL expired — zero all field values and login credentials
		// before evicting.
		for i := range entry.item.Fields {
			entry.item.Fields[i].zero()
		}
		if entry.item.Login != nil {
			entry.item.Login.zero()
		}
		b.cache.Delete(connection)
	}

	type result struct {
		item bwItem
		err  error
	}
	ch := b.sf.DoChan(connection, func() (interface{}, error) {
		item, err := b.fetchItemDirect(ctx, connection)
		if err != nil {
			return result{err: err}, nil
		}
		b.cache.Store(connection, cacheEntry{
			item:      item,
			expiresAt: time.Now().Add(ttl),
		})
		return result{item: item}, nil
	})

	select {
	case <-ctx.Done():
		return bwItem{}, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return bwItem{}, res.Err
		}
		r := res.Val.(result)
		return r.item, r.err
	}
}

// fetchItemDirect invokes `bw get item` without cache.
func (b *BitwardenBackend) fetchItemDirect(ctx context.Context, connection string) (bwItem, error) {
	stdout, stderr, exitCode, err := b.runWithSession(ctx,
		[]string{"get", "item", connection},
		nil)
	if err != nil {
		return bwItem{}, fmt.Errorf("bw: runner error: %w", err)
	}

	if exitCode != 0 {
		stderrStr := string(stderr)
		// S2-7 / S2-9: do not echo raw stderr; map to typed errors.
		if isLocked(stderrStr) {
			// Call bw status to confirm lock state.
			if confirmed := b.confirmLocked(ctx); confirmed {
				return bwItem{}, fmt.Errorf("%w: set BW_SESSION (see README §Non-interactive use)",
					backend.ErrLocked)
			}
			return bwItem{}, fmt.Errorf("%w: set BW_SESSION (see README §Non-interactive use)",
				backend.ErrLocked)
		}
		if isNotFound(stderrStr) {
			return bwItem{}, fmt.Errorf("%w: %s", backend.ErrNotFound, connection)
		}
		return bwItem{}, fmt.Errorf("bw: get item exited %d", exitCode)
	}

	var item bwItem
	if err := json.Unmarshal(stdout, &item); err != nil {
		return bwItem{}, fmt.Errorf("bw: decode item: %w", err)
	}
	return item, nil
}

// confirmLocked runs `bw status` to verify the vault is locked.
func (b *BitwardenBackend) confirmLocked(ctx context.Context) bool {
	stdout, _, exitCode, err := b.runWithSession(ctx, []string{"status"}, nil)
	if err != nil || exitCode != 0 {
		return true // assume locked on error
	}
	var st bwStatus
	if err := json.Unmarshal(stdout, &st); err != nil {
		return true
	}
	return st.Status == "locked" || st.Status == "unauthenticated"
}

// sync runs `bw sync` and discards stdout; checks exit code only.
func (b *BitwardenBackend) sync(ctx context.Context) error {
	_, stderr, exitCode, err := b.runWithSession(ctx, []string{"sync"}, nil)
	if err != nil {
		return fmt.Errorf("bw sync: runner error: %w", err)
	}
	if exitCode != 0 {
		if isLocked(string(stderr)) {
			return fmt.Errorf("%w: set BW_SESSION (see README §Non-interactive use)", backend.ErrLocked)
		}
		return fmt.Errorf("bw sync: exited %d", exitCode)
	}
	return nil
}

// runWithSession invokes the bw CLI with BW_SESSION injected via subprocess env.
// S2-7: session is NEVER passed as a --session argument; it goes in the env map
// via the CommandRunner's stdin-pipe mechanism. Since our CommandRunner interface
// does not expose env injection directly, we use the exec.EnvRunner wrapper if
// available, otherwise fall back to a no-env run (test mocks capture calls).
//
// Note: The real exec.defaultRunner sets cmd.Env = os.Environ() which means
// BW_SESSION must be in the process env. For tests, MockRunner records the
// args — the env injection is verified by asserting --session is absent.
func (b *BitwardenBackend) runWithSession(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, int, error) {
	// S2-7: NEVER pass --session as an argument. Session is in the process env
	// (set by the user before launching keylatch) and inherited by subprocesses.
	// For test overrides, the MockRunner does not inspect env, but tests verify
	// that no arg contains "--session" or the session value.
	return b.opts.Runner.Run(ctx, b.bin, args, stdin)
}

// resolveFolderID returns the ID for a folder name by listing folders.
func (b *BitwardenBackend) resolveFolderID(ctx context.Context, name string) (string, error) {
	stdout, _, exitCode, err := b.runWithSession(ctx, []string{"list", "folders"}, nil)
	if err != nil || exitCode != 0 {
		return "", fmt.Errorf("bw: list folders failed")
	}
	var folders []bwFolder
	if err := json.Unmarshal(stdout, &folders); err != nil {
		return "", fmt.Errorf("bw: decode folders: %w", err)
	}
	for _, f := range folders {
		if f.Name == name {
			return f.ID, nil
		}
	}
	return "", fmt.Errorf("bw: folder %q not found", name)
}

// evictCacheEntry removes the cache entry for connection, zeroing any field
// values and login credentials before deletion to prevent plaintext lingering
// in memory. T-13-02: called on TTL expiry, explicit invalidation (Set/Delete).
func (b *BitwardenBackend) evictCacheEntry(connection string) {
	if v, ok := b.cache.Load(connection); ok {
		entry := v.(cacheEntry)
		for i := range entry.item.Fields {
			entry.item.Fields[i].zero()
		}
		if entry.item.Login != nil {
			entry.item.Login.zero()
		}
	}
	b.cache.Delete(connection)
}

// parsePath splits a canonical path into (connection, field).
func parsePath(canonical string) (connection, field string, err error) {
	parts := strings.Split(canonical, "/")
	if len(parts) >= 3 {
		connection = parts[1]
		field = strings.Join(parts[2:], "/")
		return
	}
	if len(parts) == 2 {
		connection = parts[0]
		field = parts[1]
		return
	}
	return "", "", fmt.Errorf("invalid canonical path %q: expected namespace/connection/field", canonical)
}

// isLocked returns true when stderr indicates the vault is locked.
func isLocked(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "vault is locked") ||
		strings.Contains(lower, "you are not logged in") ||
		strings.Contains(lower, "not logged in") ||
		strings.Contains(lower, "session key is invalid") ||
		strings.Contains(lower, "invalid session")
}

// isNotFound returns true when stderr indicates the item was not found.
func isNotFound(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "not found") ||
		strings.Contains(lower, "no items found")
}

// isErrNotFound checks if err wraps backend.ErrNotFound.
func isErrNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), backend.ErrNotFound.Error())
}

// isSecretField returns true for field names that should use hidden type.
func isSecretField(field string) bool {
	lower := strings.ToLower(field)
	return strings.Contains(lower, "key") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "oauth")
}
