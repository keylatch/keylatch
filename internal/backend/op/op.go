// Package op implements the Backend interface using the 1Password CLI (`op`).
// It shells out via internal/exec.CommandRunner, stores one 1Password item per
// Keylatch connection, and satisfies all Phase 2 security invariants.
//
// Security invariants:
//   - S2-1: Never print secret values to stdout/stderr.
//   - S2-3: List zero-fills field values before returning.
//   - S2-5: Fail-closed on binary unavailability (ErrUnavailable).
//   - S2-9: Raw subprocess stderr never propagated; auth-failure hints only.
//   - S2-10: Single-flight collapse for concurrent Get calls.
package op

import (
	"context"
	"encoding/json"
	"errors"
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
var _ backend.Backend = (*OnePasswordBackend)(nil)

// Options configures a OnePasswordBackend.
type Options struct {
	// Vault is the 1Password vault name. Defaults to "Keylatch".
	Vault string

	// Bin is the explicit path to the `op` binary. If empty, PATH is searched.
	Bin string

	// Runner is injectable for tests. Defaults to exec.DefaultRunner.
	Runner kexec.CommandRunner

	// Env is the environment lookup function. Defaults to llmcontext.DefaultLookup.
	Env llmcontext.Lookup
}

// cacheEntry holds a cached opItem and its expiry.
type cacheEntry struct {
	item      opItem
	expiresAt time.Time
}

// OnePasswordBackend implements backend.Backend using the 1Password CLI.
type OnePasswordBackend struct {
	opts  Options
	bin   string
	cache sync.Map // map[string]cacheEntry
	sf    singleflight.Group
}

// Open validates options, resolves the `op` binary, and returns an initialized
// OnePasswordBackend. Returns backend.ErrUnavailable if `op` is not found.
func Open(opts Options) (*OnePasswordBackend, error) {
	// Resolve binary.
	bin := opts.Bin
	if bin == "" {
		bin = kexec.Resolve("op")
		if bin == "" {
			return nil, fmt.Errorf("%w: 1Password CLI not found. Run: brew install 1password-cli (or platform equivalent)",
				backend.ErrUnavailable)
		}
	}

	// Defaults.
	if opts.Vault == "" {
		opts.Vault = "Keylatch"
	}
	if opts.Runner == nil {
		opts.Runner = kexec.DefaultRunner
	}
	if opts.Env == nil {
		opts.Env = llmcontext.DefaultLookup
	}

	return &OnePasswordBackend{
		opts: opts,
		bin:  bin,
	}, nil
}

// Name implements backend.Backend.
func (b *OnePasswordBackend) Name() string { return "op" }

// Capabilities implements backend.Backend.
func (b *OnePasswordBackend) Capabilities() []backend.Capability {
	return []backend.Capability{
		backend.CapList,
		backend.CapMetadata,
		backend.CapImport,
		backend.CapExport,
	}
}

// Get returns the plaintext bytes for a canonical path via `op item get`.
// Uses single-flight collapse and a 60-second metadata cache (S2-10).
func (b *OnePasswordBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	connection, field, err := parsePath(path)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("op Get: %w", err)
	}

	item, err := b.fetchItem(ctx, connection)
	if err != nil {
		return nil, backend.Meta{}, err
	}

	// Find field by label.
	for _, f := range item.Fields {
		if f.Label == field {
			meta := backend.Meta{
				Path:      path,
				Backend:   "op",
				Accessor:  backend.ID(item.ID),
				UpdatedAt: item.updatedTime(),
				Version:   1,
			}
			return []byte(f.Value), meta, nil
		}
	}

	return nil, backend.Meta{}, fmt.Errorf("%w: field %q not found in 1Password item %q",
		backend.ErrNotFound, field, connection)
}

// Set writes a value via `op item create` or `op item edit`.
func (b *OnePasswordBackend) Set(ctx context.Context, path string, value []byte, meta backend.Meta) error {
	connection, field, err := parsePath(path)
	if err != nil {
		return fmt.Errorf("op Set: %w", err)
	}

	// Invalidate cache for this connection.
	b.cache.Delete(connection)

	// Check if item exists.
	_, fetchErr := b.fetchItemDirect(ctx, connection)
	exists := fetchErr == nil

	fieldType := classifyFieldType(field)
	fieldArg := fmt.Sprintf("%s[%s]=%s", field, fieldType, string(value))

	var args []string
	if exists {
		args = []string{"item", "edit", connection,
			"--vault=" + b.opts.Vault,
			fieldArg,
			"--format=json",
		}
	} else {
		category := classifyCategory(field)
		args = []string{"item", "create",
			"--category=" + category,
			"--title=" + connection,
			"--vault=" + b.opts.Vault,
			"--tags=keylatch,ns:default",
			fieldArg,
			"--format=json",
		}
	}

	stdout, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.bin, args, nil)
	if err != nil {
		return fmt.Errorf("op Set: runner error: %w", err)
	}
	if exitCode != 0 {
		if isAuthFailure(string(stderr)) {
			return fmt.Errorf("%w: Run: eval $(op signin)", backend.ErrLocked)
		}
		return fmt.Errorf("op Set: op exited %d", exitCode)
	}

	// Parse returned item to get accessor.
	var updated opItem
	if err := json.Unmarshal(stdout, &updated); err != nil {
		// Non-fatal — item was written, we just can't return the accessor.
		return nil
	}

	// Invalidate cache so next Get re-fetches.
	b.cache.Delete(connection)
	return nil
}

// Delete removes a 1Password item via `op item delete`.
func (b *OnePasswordBackend) Delete(ctx context.Context, path string) error {
	connection, _, err := parsePath(path)
	if err != nil {
		return fmt.Errorf("op Delete: %w", err)
	}

	// Invalidate cache.
	b.cache.Delete(connection)

	_, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.bin,
		[]string{"item", "delete", connection, "--vault=" + b.opts.Vault},
		nil)
	if err != nil {
		return fmt.Errorf("op Delete: runner error: %w", err)
	}
	if exitCode != 0 {
		stderrStr := string(stderr)
		if isNotFound(stderrStr) {
			return fmt.Errorf("%w: %s", backend.ErrNotFound, connection)
		}
		return fmt.Errorf("op Delete: op exited %d", exitCode)
	}
	return nil
}

// List returns metadata-only entries with zero-filled field values (S2-3).
func (b *OnePasswordBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	stdout, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.bin,
		[]string{"item", "list",
			"--vault=" + b.opts.Vault,
			"--tags=keylatch",
			"--format=json",
		},
		nil)
	if err != nil {
		return nil, fmt.Errorf("op List: runner error: %w", err)
	}
	if exitCode != 0 {
		if isAuthFailure(string(stderr)) {
			return nil, fmt.Errorf("%w: Run: eval $(op signin)", backend.ErrLocked)
		}
		return nil, fmt.Errorf("op List: op exited %d", exitCode)
	}

	var items []opItem
	if err := json.Unmarshal(stdout, &items); err != nil {
		return nil, fmt.Errorf("op List: decode response: %w", err)
	}

	var entries []backend.Entry
	for _, item := range items {
		for _, f := range item.Fields {
			// S2-3: zero-fill field values unconditionally on list.
			path := "default/" + item.Title + "/" + f.Label
			if prefix != "" && !strings.HasPrefix(path, prefix) {
				continue
			}
			entries = append(entries, backend.Entry{
				Meta: backend.Meta{
					Path:      path,
					Backend:   "op",
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

// Close is a no-op for the op backend (no persistent OS resources).
func (b *OnePasswordBackend) Close() error { return nil }

// --- internal helpers ---

// fetchItem returns an opItem, using cache + single-flight collapse (S2-10).
func (b *OnePasswordBackend) fetchItem(ctx context.Context, connection string) (opItem, error) {
	const ttl = 60 * time.Second

	// Check cache first.
	if v, ok := b.cache.Load(connection); ok {
		entry := v.(cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.item, nil
		}
		// TTL expired — evict.
		b.cache.Delete(connection)
	}

	// Single-flight collapse: concurrent callers for the same connection
	// share one subprocess invocation.
	type result struct {
		item opItem
		err  error
	}
	ch := b.sf.DoChan(connection, func() (interface{}, error) {
		item, err := b.fetchItemDirect(ctx, connection)
		if err != nil {
			return result{err: err}, nil
		}
		// Store in cache.
		b.cache.Store(connection, cacheEntry{
			item:      item,
			expiresAt: time.Now().Add(ttl),
		})
		return result{item: item}, nil
	})

	select {
	case <-ctx.Done():
		return opItem{}, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return opItem{}, res.Err
		}
		r := res.Val.(result)
		return r.item, r.err
	}
}

// fetchItemDirect invokes `op item get` without cache.
// If connection contains a colon (e.g. "openrouter:accountslug"), the account
// slug is passed via --account to disambiguate multi-account vaults.
func (b *OnePasswordBackend) fetchItemDirect(ctx context.Context, connection string) (opItem, error) {
	conn, account := parseConnectionAccount(connection)

	args := []string{"item", "get", conn,
		"--vault=" + b.opts.Vault,
		"--format=json",
	}
	if account != "" {
		args = append(args, "--account="+account)
	}

	stdout, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.bin, args, nil)
	if err != nil {
		return opItem{}, fmt.Errorf("op: runner error: %w", err)
	}

	if exitCode != 0 {
		stderrStr := string(stderr)
		// S2-9: do not echo raw stderr — map to typed errors with hints.
		if isAuthFailure(stderrStr) {
			return opItem{}, fmt.Errorf("%w: Run: eval $(op signin)", backend.ErrLocked)
		}
		if isNotFound(stderrStr) {
			return opItem{}, fmt.Errorf("%w: %s", backend.ErrNotFound, conn)
		}
		// Detect multi-result (ambiguous) response via "More than one item" marker.
		if isAmbiguous(stderrStr) {
			return opItem{}, ErrAmbiguous{Connection: conn, Count: 2}
		}
		// Generic failure — do not expose raw stderr.
		return opItem{}, fmt.Errorf("op: item get exited %d", exitCode)
	}

	// Try to decode as a single item first.
	var item opItem
	if err := json.Unmarshal(stdout, &item); err == nil {
		return item, nil
	}

	// If it decoded as an array (multi-result), return ErrAmbiguous.
	var items []opItem
	if err := json.Unmarshal(stdout, &items); err == nil {
		if len(items) > 1 {
			return opItem{}, ErrAmbiguous{Connection: conn, Count: len(items)}
		}
		if len(items) == 1 {
			return items[0], nil
		}
		return opItem{}, fmt.Errorf("%w: %s", backend.ErrNotFound, conn)
	}

	return opItem{}, fmt.Errorf("op: decode item response: invalid JSON")
}

// isAmbiguous returns true when stderr indicates multiple items match.
func isAmbiguous(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "more than one item") ||
		strings.Contains(lower, "multiple items found")
}

// parsePath splits a canonical path into (connection, field).
// Canonical path: "default/{connection}/{field}" or "{connection}/{field}".
// If the connection segment contains a colon (e.g. "openrouter:accountslug"),
// the account slug is split out for use with --account flag.
func parsePath(canonical string) (connection, field string, err error) {
	parts := strings.Split(canonical, "/")
	// Strip leading namespace segment (e.g. "default").
	if len(parts) >= 3 {
		// "default/connection/field[/...]"
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

// parseConnectionAccount splits "connection:account" into (connection, account).
// Returns (connection, "") if no colon is present.
func parseConnectionAccount(connection string) (conn, account string) {
	if idx := strings.Index(connection, ":"); idx >= 0 {
		return connection[:idx], connection[idx+1:]
	}
	return connection, ""
}

// isAuthFailure returns true when stderr indicates the user is not signed in.
func isAuthFailure(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "not currently signed in") ||
		strings.Contains(lower, "authentication required") ||
		strings.Contains(lower, "authorization required") ||
		strings.Contains(lower, "invalid service account token") ||
		strings.Contains(lower, "session expired") ||
		strings.Contains(lower, "error authenticating") ||
		strings.Contains(lower, "you are not currently signed in")
}

// isNotFound returns true when stderr indicates the item was not found.
func isNotFound(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "isn't an item in the") ||
		strings.Contains(lower, "isn't an item in vault") ||
		strings.Contains(lower, "item not found") ||
		strings.Contains(lower, "could not find item")
}

// classifyFieldType returns the 1Password field type qualifier for a field name.
// oauth fields → "concealed"; api_key/token → "concealed"; rest → "string".
func classifyFieldType(field string) string {
	lower := strings.ToLower(field)
	if strings.Contains(lower, "secret") || strings.Contains(lower, "token") ||
		strings.Contains(lower, "api_key") || strings.Contains(lower, "password") ||
		strings.Contains(lower, "oauth") {
		return "concealed"
	}
	return "string"
}

// classifyCategory returns the 1Password item category for a field name.
func classifyCategory(field string) string {
	lower := strings.ToLower(field)
	if strings.Contains(lower, "oauth") {
		return "Login"
	}
	if strings.Contains(lower, "api_key") || strings.Contains(lower, "token") {
		return "API Credential"
	}
	return "Password"
}

// ErrAmbiguous is returned when multiple 1Password items match a connection name.
type ErrAmbiguous struct {
	Connection string
	Count      int
}

func (e ErrAmbiguous) Error() string {
	return fmt.Sprintf("op: use --account <slug> to disambiguate (found %d items for %q)",
		e.Count, e.Connection)
}

// isErrAmbiguous checks if err wraps ErrAmbiguous.
func isErrAmbiguous(err error) bool {
	var e ErrAmbiguous
	return errors.As(err, &e)
}

// ensure isErrAmbiguous is referenced (avoids "declared and not used" if unused).
var _ = isErrAmbiguous
