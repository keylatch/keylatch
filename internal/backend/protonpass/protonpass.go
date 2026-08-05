// Package protonpass implements the Backend interface using the Proton Pass CLI (`pass-cli`).
// It shells out via internal/exec.CommandRunner and satisfies the following security invariants.
//
// Security invariants:
//   - Never print secret values to stdout/stderr.
//   - List zero-fills field values before returning.
//   - Fail-closed on binary unavailability (ErrUnavailable).
//   - Raw subprocess stderr never propagated; auth-failure hints only.
//   - Single-flight collapse for concurrent Get calls.
package protonpass

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/runner"
)

// compile-time interface check.
var _ backend.Backend = (*ProtonPassBackend)(nil)

// Options configures a ProtonPassBackend.
type Options struct {
	// Vault is the Proton Pass vault name. Optional.
	Vault string

	// Bin is the explicit path to the `pass-cli` binary. If empty, PATH is searched.
	Bin string

	// ItemPrefix is a prefix applied to all item names. Defaults to "keylatch/".
	ItemPrefix string

	// Runner is injectable for tests. Defaults to exec.DefaultRunner.
	Runner kexec.CommandRunner

	// Env is the environment lookup function. Reserved for forward compatibility
	// with gold-standard backends. Defaults to llmcontext.DefaultLookup.
	Env llmcontext.Lookup
}

// cacheEntry holds a cached value and metadata with a TTL expiry.
type cacheEntry struct {
	val       []byte
	meta      backend.Meta
	expiresAt time.Time
}

// ProtonPassBackend implements backend.Backend using the Proton Pass CLI.
type ProtonPassBackend struct {
	opts  Options
	cache sync.Map // map[string]cacheEntry
	sf    singleflight.Group
}

// Open validates options, resolves the `pass-cli` binary, and returns an initialized
// ProtonPassBackend. Returns backend.ErrUnavailable if `pass-cli` is not found.
func Open(opts Options) (*ProtonPassBackend, error) {
	bin := opts.Bin
	if bin == "" {
		bin = kexec.Resolve("pass-cli")
		if bin == "" {
			return nil, fmt.Errorf("%w: Proton Pass CLI not found. Install: brew install proton-pass or https://proton.me/pass/download",
				backend.ErrUnavailable)
		}
	}
	opts.Bin = bin

	if opts.ItemPrefix == "" {
		opts.ItemPrefix = "keylatch/"
	}
	if opts.Runner == nil {
		opts.Runner = kexec.DefaultRunner
	}

	return &ProtonPassBackend{opts: opts}, nil
}

// Name implements backend.Backend.
func (b *ProtonPassBackend) Name() string { return "proton-pass" }

// Capabilities implements backend.Backend.
func (b *ProtonPassBackend) Capabilities() []backend.Capability {
	return []backend.Capability{backend.CapList, backend.CapNetworkedFetch}
}

// Get returns the plaintext bytes for a canonical path via `pass-cli item get`.
// Uses a 60-second TTL cache and single-flight collapse for concurrent calls.
//
// Checks runner.OK before returning plaintext (C2).
func (b *ProtonPassBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	if !runner.OK(ctx) {
		return nil, backend.Meta{}, backend.ErrLocked
	}

	name := b.itemName(path)
	const ttl = 60 * time.Second

	// Check cache first.
	if v, ok := b.cache.Load(name); ok {
		entry := v.(cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.val, entry.meta, nil
		}
		b.cache.Delete(name)
	}

	type result struct {
		val  []byte
		meta backend.Meta
		err  error
	}

	ch := b.sf.DoChan(name, func() (interface{}, error) {
		args := []string{"item", "get", name, "--output", "json"}
		stdout, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, nil)
		if err != nil {
			return result{err: fmt.Errorf("proton-pass: runner error: %w", err)}, nil
		}
		if exitCode != 0 {
			return result{err: b.mapGetError(string(stderr))}, nil
		}

		var item passGetResult
		if err := json.Unmarshal(stdout, &item); err != nil {
			return result{err: fmt.Errorf("%w: proton-pass get failed to parse response", backend.ErrUnavailable)}, nil
		}

		val := []byte(item.Content.Note)
		meta := backend.Meta{
			Path:    path,
			Backend: "proton-pass",
		}
		// Populate cache.
		b.cache.Store(name, cacheEntry{
			val:       val,
			meta:      meta,
			expiresAt: time.Now().Add(ttl),
		})
		return result{val: val, meta: meta}, nil
	})

	select {
	case <-ctx.Done():
		return nil, backend.Meta{}, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, backend.Meta{}, res.Err
		}
		r := res.Val.(result)
		return r.val, r.meta, r.err
	}
}

// Set writes a value via `pass-cli item create`, reading the note from stdin to
// avoid exposing the secret in process arguments.
func (b *ProtonPassBackend) Set(ctx context.Context, path string, value []byte, _ backend.Meta) error {
	name := b.itemName(path)

	args := []string{
		"item", "create",
		"--type", "login",
		"--name", name,
		"--note", "-", // read note from stdin
	}
	_, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, value)
	if err != nil {
		return fmt.Errorf("proton-pass: runner error: %w", err)
	}
	if exitCode != 0 {
		errStr := string(stderr)
		if isProtonAuthFailure(errStr) {
			return fmt.Errorf("%w: not signed in to Proton Pass; run 'pass-cli auth login'", backend.ErrLocked)
		}
		return fmt.Errorf("%w: proton-pass set failed", backend.ErrUnavailable)
	}
	return nil
}

// Delete removes a Proton Pass item via `pass-cli item delete`.
func (b *ProtonPassBackend) Delete(ctx context.Context, path string) error {
	name := b.itemName(path)

	args := []string{"item", "delete", name}
	_, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, nil)
	if err != nil {
		return fmt.Errorf("proton-pass: runner error: %w", err)
	}
	if exitCode != 0 {
		errStr := string(stderr)
		if isProtonNotFound(errStr) {
			return fmt.Errorf("%w: %s", backend.ErrNotFound, name)
		}
		if isProtonAuthFailure(errStr) {
			return fmt.Errorf("%w: not signed in to Proton Pass; run 'pass-cli auth login'", backend.ErrLocked)
		}
		return fmt.Errorf("%w: proton-pass delete failed", backend.ErrUnavailable)
	}
	return nil
}

// List returns metadata-only entries via `pass-cli item list --output json`.
func (b *ProtonPassBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	args := []string{"item", "list", "--output", "json"}
	stdout, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, nil)
	if err != nil {
		return nil, fmt.Errorf("proton-pass: runner error: %w", err)
	}
	if exitCode != 0 {
		if isProtonAuthFailure(string(stderr)) {
			return nil, fmt.Errorf("%w: not signed in to Proton Pass; run 'pass-cli auth login'", backend.ErrLocked)
		}
		return nil, fmt.Errorf("%w: proton-pass list failed", backend.ErrUnavailable)
	}

	var items []passItem
	if err := json.Unmarshal(stdout, &items); err != nil {
		return nil, fmt.Errorf("proton-pass: decode list response: %w", err)
	}

	var entries []backend.Entry
	for _, item := range items {
		// Only include items managed by keylatch (matching prefix).
		if !strings.HasPrefix(item.Name, b.opts.ItemPrefix) {
			continue
		}
		// Convert item name back to a path: strip the prefix.
		path := strings.TrimPrefix(item.Name, b.opts.ItemPrefix)
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			continue
		}
		// Never include value fields in list output.
		entries = append(entries, backend.Entry{
			Meta: backend.Meta{
				Path:    path,
				Backend: "proton-pass",
			},
			Exists: true,
		})
	}
	return entries, nil
}

// Close clears the TTL cache, zeroing cached byte slices before eviction.
func (b *ProtonPassBackend) Close() error {
	b.cache.Range(func(key, value any) bool {
		if entry, ok := value.(cacheEntry); ok {
			for i := range entry.val {
				entry.val[i] = 0
			}
		}
		b.cache.Delete(key)
		return true
	})
	return nil
}

// itemName converts a canonical path to a Proton Pass item name.
func (b *ProtonPassBackend) itemName(path string) string {
	return b.opts.ItemPrefix + path
}

// mapGetError maps pass-cli stderr to typed backend errors.
func (b *ProtonPassBackend) mapGetError(errStr string) error {
	if isProtonNotFound(errStr) {
		return fmt.Errorf("%w: proton-pass item not found", backend.ErrNotFound)
	}
	if isProtonAuthFailure(errStr) {
		return fmt.Errorf("%w: not signed in to Proton Pass; run 'pass-cli auth login'", backend.ErrLocked)
	}
	return fmt.Errorf("%w: proton-pass get failed", backend.ErrUnavailable)
}

// isProtonAuthFailure returns true when stderr indicates the user is not authenticated.
func isProtonAuthFailure(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "not authenticated") ||
		strings.Contains(lower, "not signed in") ||
		strings.Contains(lower, "session expired") ||
		strings.Contains(lower, "authentication required") ||
		strings.Contains(lower, "unauthenticated")
}

// isProtonNotFound returns true when stderr indicates the item was not found.
func isProtonNotFound(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "not found") ||
		strings.Contains(lower, "no item") ||
		strings.Contains(lower, "item does not exist")
}
