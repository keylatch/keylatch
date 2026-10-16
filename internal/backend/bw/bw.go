// Package bw implements the Backend interface using the Bitwarden CLI (`bw`).
// Supports both Bitwarden Cloud and Vaultwarden self-hosted via KEYLATCH_BW_SERVER.
//
// Security invariants:
//   - List zero-fills field values before returning.
//   - Server URL must use https:// (no TLS bypass for self-hosted), and when a
//     server is configured `bw config server` must name the same server.
//   - Fail-closed on binary unavailability (ErrUnavailable).
//   - BW_SESSION passed via subprocess env, never via --session CLI arg.
//   - Raw subprocess stderr never propagated; auth-failure hints only.
//   - Single-flight collapse for concurrent Get calls.
//   - With organization namespaces configured, a namespace that is not mapped
//     to a collection fails before any `bw` call.
package bw

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// compile-time interface check.
var _ backend.Backend = (*BitwardenBackend)(nil)

// ErrNamespaceUnmapped is returned when namespaces are mapped to organization
// collections and the namespace of a path is not one of them.
var ErrNamespaceUnmapped = errors.New("bw: namespace is not mapped to a collection")

// ErrServerMismatch is returned when `bw config server` names a different
// server than the one configured.
var ErrServerMismatch = errors.New("bw: the bw CLI is configured for a different server")

// defaultNamespace is the namespace of a path that names none.
const defaultNamespace = "default"

// Options configures a BitwardenBackend.
type Options struct {
	// Server is the Vaultwarden self-hosted URL (https:// required).
	// Empty means Bitwarden Cloud. When set, `bw config server` must equal it.
	Server string

	// Folder filters items by folder name when set.
	Folder string

	// Collection filters items by collection name when set.
	Collection string

	// OrganizationID is the organization whose collections hold the items when
	// Namespaces is used.
	OrganizationID string

	// Namespaces maps a namespace to the name of an organization collection
	// (for example "Work/infra"). Items are created in, and looked up from, the
	// mapped collection. A namespace not in the map is refused. It needs
	// OrganizationID and excludes Folder and Collection.
	Namespaces map[string]string

	// Bin is the explicit path to the `bw` binary. If empty, PATH is searched.
	Bin string

	// Runner is injectable for tests. Defaults to exec.DefaultRunner.
	Runner kexec.CommandRunner

	// Env is the environment lookup function. Defaults to llmcontext.DefaultLookup.
	Env llmcontext.Lookup

	// AutoSync enables `bw sync` before List and Get when true. Default false.
	AutoSync bool

	// KEKLoader opens the vault KEK that seals the cached session. Defaults to
	// DefaultKEK(Env). It is called only when a cached session exists.
	KEKLoader func() (kek.KEK, error)
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

	// sessionFromCache is true when session was sourced from the session
	// cache (LoadSession) rather than the ambient BW_SESSION env var. Only
	// cache-sourced sessions are invalidated on an auth failure — an
	// explicit, user-set ambient BW_SESSION is left alone so we never mask
	// the user's own env-var mistake behind a silent cache-clear.
	sessionFromCache bool

	cache sync.Map
	sf    singleflight.Group

	// serverChecked is set once `bw config server` has matched Options.Server.
	serverMu      sync.Mutex
	serverChecked bool

	// collections caches collection name -> ID per organization.
	collMu      sync.Mutex
	collections map[string]string
}

// Open validates options, resolves the `bw` binary, resolves a BW_SESSION
// (ambient env first, then the sealed session cache — see session_cache.go),
// and returns an initialized BitwardenBackend.
func Open(opts Options) (*BitwardenBackend, error) {
	// Reject non-https server URLs.
	if opts.Server != "" && !strings.HasPrefix(opts.Server, "https://") {
		return nil, ErrInvalidServer{URL: opts.Server}
	}
	if len(opts.Namespaces) > 0 {
		if opts.OrganizationID == "" {
			return nil, fmt.Errorf("bw: namespaces need an organization_id")
		}
		if opts.Folder != "" || opts.Collection != "" {
			return nil, fmt.Errorf("bw: namespaces replace folder and collection; set only one way to place items")
		}
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

	// Read BW_SESSION from env into unexported field. Never assign to
	// a logged or exported variable.
	session := opts.Env("BW_SESSION")
	fromCache := false
	if session == "" {
		if cached, ok := cachedSession(opts); ok {
			session = cached
			fromCache = true
		}
	}

	return &BitwardenBackend{
		opts:             opts,
		bin:              bin,
		session:          session,
		sessionFromCache: fromCache,
		collections:      map[string]string{},
	}, nil
}

// cachedSession returns the sealed session when one is cached and unexpired.
// The KEK is opened only then.
func cachedSession(opts Options) (string, bool) {
	status, err := StatSession(opts.Env)
	if err != nil || !status.Present || status.Expired {
		return "", false
	}
	load := opts.KEKLoader
	if load == nil {
		load = func() (kek.KEK, error) { return DefaultKEK(opts.Env) }
	}
	k, err := load()
	if err != nil {
		return "", false
	}
	token, ok, _ := LoadSession(opts.Env, k)
	return token, ok
}

// Unlock runs `bw unlock --raw`, piping masterPassword via stdin (never as an
// argument or env var), and returns the raw session token on success. The
// token is never logged; callers are responsible for persisting it (see
// SaveSession) and for zeroing masterPassword/the returned token once done.
//
// This does not mutate b.session — a fresh BitwardenBackend (or the next
// keylatch invocation) picks up the newly cached token through Open()'s
// session cache seam.
func (b *BitwardenBackend) Unlock(ctx context.Context, masterPassword []byte) (string, error) {
	stdout, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.bin, []string{"unlock", "--raw"}, masterPassword)
	if err != nil {
		return "", fmt.Errorf("bw unlock: runner error: %w", err)
	}
	if exitCode != 0 {
		stderrStr := strings.ToLower(string(stderr))
		// Real bw CLI wording is "Master password is invalid. Try again."
		// (word order: subject first) — match on the fragment shared by any
		// wording, not "invalid master password".
		if isLocked(string(stderr)) || strings.Contains(stderrStr, "master password is invalid") {
			return "", fmt.Errorf("%w: invalid master password (or vault already in an unexpected state)", backend.ErrLocked)
		}
		return "", fmt.Errorf("bw unlock: bw exited %d", exitCode)
	}
	token := strings.TrimSpace(string(stdout))
	if token == "" {
		return "", fmt.Errorf("bw unlock: bw returned an empty session token")
	}
	return token, nil
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

// mapped reports whether items are placed by namespace in organization
// collections.
func (b *BitwardenBackend) mapped() bool {
	return b.opts.OrganizationID != "" || len(b.opts.Namespaces) > 0
}

// collectionFor returns the collection name a namespace is mapped to. It makes
// no bw call, so an unmapped namespace is refused before anything runs.
func (b *BitwardenBackend) collectionFor(namespace string) (string, error) {
	name, ok := b.opts.Namespaces[namespace]
	if !ok || name == "" {
		return "", fmt.Errorf("%w: %q", ErrNamespaceUnmapped, namespace)
	}
	return name, nil
}

// checkServer makes sure the bw CLI talks to the configured server before it
// is handed a secret. The result is remembered once it matches.
func (b *BitwardenBackend) checkServer(ctx context.Context) error {
	if b.opts.Server == "" {
		return nil
	}
	b.serverMu.Lock()
	defer b.serverMu.Unlock()
	if b.serverChecked {
		return nil
	}
	stdout, _, exitCode, err := b.opts.Runner.Run(ctx, b.bin, []string{"config", "server"}, nil)
	if err != nil {
		return fmt.Errorf("bw config server: runner error: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("bw config server: bw exited %d", exitCode)
	}
	want, got := strings.TrimRight(b.opts.Server, "/"), strings.TrimRight(strings.TrimSpace(string(stdout)), "/")
	if !strings.EqualFold(want, got) {
		return fmt.Errorf("%w: configured %q, bw is using %q; run `bw config server %s`", ErrServerMismatch, want, got, want)
	}
	b.serverChecked = true
	return nil
}

// Get returns the plaintext bytes for a canonical path via `bw get item`.
// BW_SESSION is injected as a subprocess env var. Uses single-flight
// collapse and 60-second metadata cache.
func (b *BitwardenBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	namespace, connection, field, err := parsePath(path)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("bw Get: %w", err)
	}
	collection, err := b.placement(namespace)
	if err != nil {
		return nil, backend.Meta{}, err
	}
	if err := b.checkServer(ctx); err != nil {
		return nil, backend.Meta{}, err
	}

	if b.opts.AutoSync {
		if err := b.sync(ctx); err != nil {
			return nil, backend.Meta{}, err
		}
	}

	item, err := b.fetchItem(ctx, collection, connection)
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

// placement returns the collection name for namespace, or "" when items are
// not placed by namespace.
func (b *BitwardenBackend) placement(namespace string) (string, error) {
	if !b.mapped() {
		return "", nil
	}
	return b.collectionFor(namespace)
}

// Set writes a value via `bw create item` or `bw edit item <id>`.
func (b *BitwardenBackend) Set(ctx context.Context, path string, value []byte, meta backend.Meta) error {
	namespace, connection, field, err := parsePath(path)
	if err != nil {
		return fmt.Errorf("bw Set: %w", err)
	}
	collection, err := b.placement(namespace)
	if err != nil {
		return err
	}
	if err := b.checkServer(ctx); err != nil {
		return err
	}

	// Invalidate cache with zeroing.
	b.evictCacheEntry(collection, connection)

	// Determine if item exists.
	existing, fetchErr := b.fetchScoped(ctx, collection, connection)
	exists := fetchErr == nil
	if fetchErr != nil && collection != "" && !isErrNotFound(fetchErr) {
		return fetchErr
	}

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

		_, stderr, exitCode, err := b.runWithSession(ctx, []string{"edit", "item", existing.ID}, []byte(encoded))
		if err != nil {
			return fmt.Errorf("bw Set: runner error: %w", err)
		}
		if exitCode != 0 {
			if isLocked(string(stderr)) {
				return b.lockedGuidance()
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

		if collection != "" {
			cid, err := b.collectionID(ctx, collection)
			if err != nil {
				return err
			}
			newItem.OrganizationID = b.opts.OrganizationID
			newItem.CollectionIDs = []string{cid}
		} else {
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
		}

		body, err := json.Marshal(newItem)
		if err != nil {
			return fmt.Errorf("bw Set: marshal new item: %w", err)
		}
		encoded := base64.StdEncoding.EncodeToString(body)

		_, stderr, exitCode, err := b.runWithSession(ctx, []string{"create", "item"}, []byte(encoded))
		if err != nil {
			return fmt.Errorf("bw Set: runner error: %w", err)
		}
		if exitCode != 0 {
			if isLocked(string(stderr)) {
				return b.lockedGuidance()
			}
			return fmt.Errorf("bw Set: bw exited %d", exitCode)
		}
	}

	// Invalidate cache with zeroing after write.
	b.evictCacheEntry(collection, connection)
	return nil
}

// Delete removes a Bitwarden item via `bw delete item <id>`.
func (b *BitwardenBackend) Delete(ctx context.Context, path string) error {
	namespace, connection, _, err := parsePath(path)
	if err != nil {
		return fmt.Errorf("bw Delete: %w", err)
	}
	collection, err := b.placement(namespace)
	if err != nil {
		return err
	}
	if err := b.checkServer(ctx); err != nil {
		return err
	}

	// Invalidate cache with zeroing.
	b.evictCacheEntry(collection, connection)

	item, err := b.fetchScoped(ctx, collection, connection)
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

// List returns metadata-only entries with zero-filled field values.
func (b *BitwardenBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	if err := b.checkServer(ctx); err != nil {
		return nil, err
	}
	if b.opts.AutoSync {
		if err := b.sync(ctx); err != nil {
			return nil, err
		}
	}
	if b.mapped() {
		return b.listMapped(ctx, prefix)
	}

	stdout, stderr, exitCode, err := b.runWithSession(ctx,
		[]string{"list", "items", "--search=keylatch"},
		nil)
	if err != nil {
		return nil, fmt.Errorf("bw List: runner error: %w", err)
	}
	if exitCode != 0 {
		if isLocked(string(stderr)) {
			return nil, b.lockedGuidance()
		}
		return nil, fmt.Errorf("bw List: bw exited %d", exitCode)
	}

	// See fetchItemDirect: exitCode == 0 with empty stdout indicates a
	// locked/stale session, not valid empty JSON.
	if len(stdout) == 0 {
		return nil, b.lockedGuidance()
	}

	var items []bwItem
	if err := json.Unmarshal(stdout, &items); err != nil {
		return nil, fmt.Errorf("bw List: decode response: %w", err)
	}

	folderID := ""
	if b.opts.Folder != "" {
		// A folder that does not exist holds no items.
		folderID, _ = b.resolveFolderID(ctx, b.opts.Folder)
	}

	var entries []backend.Entry
	for _, item := range items {
		// Apply folder filter: only the configured folder.
		if b.opts.Folder != "" && (folderID == "" || item.FolderID == nil || *item.FolderID != folderID) {
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
		entries = appendEntries(entries, defaultNamespace, item, prefix)
	}
	return entries, nil
}

// listMapped lists the items of every mapped collection.
func (b *BitwardenBackend) listMapped(ctx context.Context, prefix string) ([]backend.Entry, error) {
	namespaces := make([]string, 0, len(b.opts.Namespaces))
	for ns := range b.opts.Namespaces {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	var entries []backend.Entry
	for _, ns := range namespaces {
		cid, err := b.collectionID(ctx, b.opts.Namespaces[ns])
		if err != nil {
			return nil, err
		}
		var items []bwItem
		args := []string{"list", "items", "--organizationid=" + b.opts.OrganizationID, "--collectionid=" + cid}
		if err := b.runJSONNoSync(ctx, args, &items); err != nil {
			return nil, err
		}
		for _, item := range items {
			if item.OrganizationID == b.opts.OrganizationID && containsString(item.CollectionIDs, cid) {
				entries = appendEntries(entries, ns, item, prefix)
			}
		}
	}
	return entries, nil
}

func appendEntries(entries []backend.Entry, namespace string, item bwItem, prefix string) []backend.Entry {
	for _, f := range item.Fields {
		// Field values are never returned from a list.
		path := namespace + "/" + item.Name + "/" + f.Name
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
	return entries
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// Close is a no-op for the bw backend.
func (b *BitwardenBackend) Close() error { return nil }

// --- internal helpers ---

// cacheKey identifies an item by where it lives and its name.
func cacheKey(collection, connection string) string { return collection + "\x00" + connection }

// fetchItem returns a bwItem using cache + single-flight collapse.
func (b *BitwardenBackend) fetchItem(ctx context.Context, collection, connection string) (bwItem, error) {
	const ttl = 60 * time.Second
	key := cacheKey(collection, connection)

	// Check cache.
	if v, ok := b.cache.Load(key); ok {
		entry := v.(cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.item, nil
		}
		// TTL expired — zero all field values and login credentials
		// before evicting.
		for i := range entry.item.Fields {
			entry.item.Fields[i].zero()
		}
		if entry.item.Login != nil {
			entry.item.Login.zero()
		}
		b.cache.Delete(key)
	}

	type result struct {
		item bwItem
		err  error
	}
	ch := b.sf.DoChan(key, func() (interface{}, error) {
		item, err := b.fetchScoped(ctx, collection, connection)
		if err != nil {
			return result{err: err}, nil
		}
		b.cache.Store(key, cacheEntry{
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

// fetchScoped finds the item connection where the backend places it: in the
// named organization collection, or (without namespaces) by name, restricted to
// the configured folder.
func (b *BitwardenBackend) fetchScoped(ctx context.Context, collection, connection string) (bwItem, error) {
	if collection == "" {
		item, err := b.fetchItemDirect(ctx, connection)
		if err != nil {
			return bwItem{}, err
		}
		if b.opts.Folder != "" {
			folderID, ferr := b.resolveFolderID(ctx, b.opts.Folder)
			if ferr != nil || item.FolderID == nil || *item.FolderID != folderID {
				zeroItem(&item)
				return bwItem{}, fmt.Errorf("%w: %s is not in folder %q", backend.ErrNotFound, connection, b.opts.Folder)
			}
		}
		return item, nil
	}

	cid, err := b.collectionID(ctx, collection)
	if err != nil {
		return bwItem{}, err
	}
	var items []bwItem
	args := []string{"list", "items", "--organizationid=" + b.opts.OrganizationID, "--collectionid=" + cid, "--search=" + connection}
	if err := b.runJSONNoSync(ctx, args, &items); err != nil {
		return bwItem{}, err
	}
	var match []bwItem
	for _, it := range items {
		if it.Name == connection && it.OrganizationID == b.opts.OrganizationID && containsString(it.CollectionIDs, cid) {
			match = append(match, it)
		} else {
			zeroItem(&it)
		}
	}
	switch len(match) {
	case 0:
		return bwItem{}, fmt.Errorf("%w: %s", backend.ErrNotFound, connection)
	case 1:
		return match[0], nil
	}
	for i := range match {
		zeroItem(&match[i])
	}
	return bwItem{}, fmt.Errorf("bw: %d items named %q are in collection %q", len(match), connection, collection)
}

// collectionID resolves an organization collection name (or ID) to its ID, once
// per backend.
func (b *BitwardenBackend) collectionID(ctx context.Context, name string) (string, error) {
	b.collMu.Lock()
	defer b.collMu.Unlock()
	if id, ok := b.collections[name]; ok {
		return id, nil
	}
	var cols []bwNamed
	args := []string{"list", "collections", "--organizationid=" + b.opts.OrganizationID}
	if err := b.runJSONNoSync(ctx, args, &cols); err != nil {
		return "", err
	}
	id, err := pickNamed(cols, name, "collection")
	if err != nil {
		return "", err
	}
	b.collections[name] = id
	return id, nil
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
		// Do not echo raw stderr; map to typed errors.
		if isLocked(stderrStr) {
			return bwItem{}, b.lockedGuidance()
		}
		if isNotFound(stderrStr) {
			return bwItem{}, fmt.Errorf("%w: %s", backend.ErrNotFound, connection)
		}
		return bwItem{}, fmt.Errorf("bw: get item exited %d", exitCode)
	}

	// exitCode == 0 with empty stdout happens when the vault is locked or
	// the session is stale — the bw CLI does not always signal this via a
	// non-zero exit + stderr message. Without this guard, json.Unmarshal
	// on empty bytes produces a confusing "unexpected end of JSON input"
	// instead of actionable locked-vault guidance.
	if len(stdout) == 0 {
		return bwItem{}, b.lockedGuidance()
	}

	var item bwItem
	if err := json.Unmarshal(stdout, &item); err != nil {
		return bwItem{}, fmt.Errorf("bw: decode item: %w", err)
	}
	return item, nil
}

// sync runs `bw sync` and discards stdout; checks exit code only.
func (b *BitwardenBackend) sync(ctx context.Context) error {
	_, stderr, exitCode, err := b.runWithSession(ctx, []string{"sync"}, nil)
	if err != nil {
		return fmt.Errorf("bw sync: runner error: %w", err)
	}
	if exitCode != 0 {
		if isLocked(string(stderr)) {
			return b.lockedGuidance()
		}
		return fmt.Errorf("bw sync: exited %d", exitCode)
	}
	return nil
}

// runWithSession invokes the bw CLI with BW_SESSION injected via the
// CommandRunner.RunEnv seam (append-to-inherited semantics: BW_SESSION is
// appended after the inherited process environment, so it overrides any
// ambient BW_SESSION already present). Session is NEVER passed as a
// --session argument and never appears in argv.
//
// b.session is populated once, in Open(), from either an ambient BW_SESSION
// (opts.Env lookup) or — when ambient is absent — a cached session token
// (see session_cache.go). Real subprocess exec no longer depends on
// ambient os.Environ() inheritance alone, so this works under daemon/
// sandboxed exec paths where the parent's env is not implicitly passed
// through.
func (b *BitwardenBackend) runWithSession(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, int, error) {
	var extraEnv []string
	if b.session != "" {
		extraEnv = []string{"BW_SESSION=" + b.session}
	}
	return b.opts.Runner.RunEnv(ctx, b.bin, args, stdin, extraEnv)
}

// lockedGuidance returns the standard ErrLocked guidance error and, when
// this backend instance's session came from the cache rather than an
// explicit ambient BW_SESSION, best-effort invalidates that cache entry so
// a rejected session isn't retried indefinitely. An explicit ambient
// BW_SESSION set by the user is left untouched — we never silently clear a
// cache the user didn't ask us to manage.
func (b *BitwardenBackend) lockedGuidance() error {
	if b.sessionFromCache {
		_ = ClearSession(b.opts.Env)
	}
	return fmt.Errorf("%w: run `keylatch bw unlock` (or set BW_SESSION — see README §Non-interactive use)", backend.ErrLocked)
}

// resolveFolderID returns the ID for a folder name by listing folders.
func (b *BitwardenBackend) resolveFolderID(ctx context.Context, name string) (string, error) {
	stdout, _, exitCode, err := b.runWithSession(ctx, []string{"list", "folders"}, nil)
	if err != nil || exitCode != 0 {
		return "", fmt.Errorf("bw: list folders failed")
	}
	// See fetchItemDirect: exitCode == 0 with empty stdout indicates a
	// locked/stale session, not valid empty JSON.
	if len(stdout) == 0 {
		return "", b.lockedGuidance()
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
// in memory. Called on TTL expiry, explicit invalidation (Set/Delete).
func (b *BitwardenBackend) evictCacheEntry(collection, connection string) {
	key := cacheKey(collection, connection)
	if v, ok := b.cache.Load(key); ok {
		entry := v.(cacheEntry)
		for i := range entry.item.Fields {
			entry.item.Fields[i].zero()
		}
		if entry.item.Login != nil {
			entry.item.Login.zero()
		}
	}
	b.cache.Delete(key)
}

// parsePath splits a canonical path into (namespace, connection, field). A
// path without a namespace is in the default namespace.
func parsePath(canonical string) (namespace, connection, field string, err error) {
	parts := strings.Split(canonical, "/")
	if len(parts) >= 3 {
		return parts[0], parts[1], strings.Join(parts[2:], "/"), nil
	}
	if len(parts) == 2 {
		return defaultNamespace, parts[0], parts[1], nil
	}
	return "", "", "", fmt.Errorf("invalid canonical path %q: expected namespace/connection/field", canonical)
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
	return errors.Is(err, backend.ErrNotFound) || strings.Contains(err.Error(), backend.ErrNotFound.Error())
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
