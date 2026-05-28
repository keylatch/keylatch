// Package keeper implements the Backend interface using the Keeper Commander CLI (`keeper`).
// It shells out via internal/exec.CommandRunner and satisfies all Phase 2 security invariants.
//
// Security invariants:
//   - S2-1: Never print secret values to stdout/stderr.
//   - S2-3: List zero-fills field values before returning.
//   - S2-5: Fail-closed on binary unavailability (ErrUnavailable).
//   - S2-9: Raw subprocess stderr never propagated; auth-failure hints only.
//   - S2-10: Single-flight collapse for concurrent Get calls.
package keeper

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
)

// compile-time interface check.
var _ backend.Backend = (*KeeperBackend)(nil)

// Options configures a KeeperBackend.
type Options struct {
	// Bin is the explicit path to the `keeper` binary. If empty, PATH is searched.
	Bin string

	// AccountUID is the Keeper account UID for multi-account disambiguation.
	AccountUID string

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

// KeeperBackend implements backend.Backend using the Keeper Commander CLI.
type KeeperBackend struct {
	opts  Options
	cache sync.Map // map[string]cacheEntry
	sf    singleflight.Group
}

// Open validates options, resolves the `keeper` binary (with `ksm` fallback),
// and returns an initialized KeeperBackend. Returns backend.ErrUnavailable if
// neither `keeper` nor `ksm` is found (and opts.Bin is empty).
func Open(opts Options) (*KeeperBackend, error) {
	bin := opts.Bin
	if bin == "" {
		// Try keeper first, then ksm as fallback.
		bin = kexec.Resolve("keeper")
		if bin == "" {
			bin = kexec.Resolve("ksm")
		}
		if bin == "" {
			return nil, fmt.Errorf("%w: Keeper Commander not found. Install: pip install keepercommander",
				backend.ErrUnavailable)
		}
	}
	opts.Bin = bin

	if opts.Runner == nil {
		opts.Runner = kexec.DefaultRunner
	}

	return &KeeperBackend{opts: opts}, nil
}

// Name implements backend.Backend.
func (b *KeeperBackend) Name() string { return "keeper" }

// Capabilities implements backend.Backend.
func (b *KeeperBackend) Capabilities() []backend.Capability {
	return []backend.Capability{backend.CapList}
}

// Get returns the plaintext bytes for a canonical path via `keeper get --format=json`.
// Uses a 60-second TTL cache and single-flight collapse for concurrent calls (S2-10).
func (b *KeeperBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	title := keeperTitle(path)
	const ttl = 60 * time.Second

	// Check cache first.
	if v, ok := b.cache.Load(title); ok {
		entry := v.(cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.val, entry.meta, nil
		}
		b.cache.Delete(title)
	}

	type result struct {
		val  []byte
		meta backend.Meta
		err  error
	}

	ch := b.sf.DoChan(title, func() (interface{}, error) {
		args := []string{"get", "--format=json", title}
		stdout, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, nil)
		if err != nil {
			return result{err: fmt.Errorf("keeper: runner error: %w", err)}, nil
		}
		if exitCode != 0 {
			return result{err: b.mapGetError(string(stderr))}, nil
		}

		var record keeperGetResult
		if err := json.Unmarshal(stdout, &record); err != nil {
			return result{err: fmt.Errorf("%w: keeper get failed to parse response", backend.ErrUnavailable)}, nil
		}

		val := []byte(record.Password)
		meta := backend.Meta{
			Path:     path,
			Backend:  "keeper",
			Accessor: backend.ID(record.RecordUID),
		}
		// Populate cache.
		b.cache.Store(title, cacheEntry{
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

// Set writes a value via `keeper add`, reading the password from stdin to avoid
// exposing the secret in process arguments.
func (b *KeeperBackend) Set(ctx context.Context, path string, value []byte, _ backend.Meta) error {
	title := keeperTitle(path)

	args := []string{
		"add",
		"--title", title,
		"--pass", "-", // read password from stdin
		"--folder", "keylatch",
	}
	_, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, value)
	if err != nil {
		return fmt.Errorf("keeper: runner error: %w", err)
	}
	if exitCode != 0 {
		errStr := string(stderr)
		if isKeeperAuthFailure(errStr) {
			return fmt.Errorf("%w: Keeper session unavailable; run 'keeper login'", backend.ErrLocked)
		}
		return fmt.Errorf("%w: keeper set failed", backend.ErrUnavailable)
	}
	return nil
}

// Delete removes a Keeper record via `keeper delete`.
func (b *KeeperBackend) Delete(ctx context.Context, path string) error {
	title := keeperTitle(path)

	args := []string{"delete", title}
	_, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, nil)
	if err != nil {
		return fmt.Errorf("keeper: runner error: %w", err)
	}
	if exitCode != 0 {
		errStr := string(stderr)
		if isKeeperNotFound(errStr) {
			return fmt.Errorf("%w: %s", backend.ErrNotFound, title)
		}
		if isKeeperAuthFailure(errStr) {
			return fmt.Errorf("%w: Keeper session unavailable; run 'keeper login'", backend.ErrLocked)
		}
		return fmt.Errorf("%w: keeper delete failed", backend.ErrUnavailable)
	}
	return nil
}

// List returns metadata-only entries (S2-3) via `keeper ls --format=json`.
func (b *KeeperBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	args := []string{"ls", "--format=json"}
	stdout, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, nil)
	if err != nil {
		return nil, fmt.Errorf("keeper: runner error: %w", err)
	}
	if exitCode != 0 {
		if isKeeperAuthFailure(string(stderr)) {
			return nil, fmt.Errorf("%w: Keeper session unavailable; run 'keeper login'", backend.ErrLocked)
		}
		return nil, fmt.Errorf("%w: keeper list failed", backend.ErrUnavailable)
	}

	var records []keeperRecord
	if err := json.Unmarshal(stdout, &records); err != nil {
		return nil, fmt.Errorf("keeper: decode list response: %w", err)
	}

	const keeperPathPrefix = "keylatch/"
	var entries []backend.Entry
	for _, rec := range records {
		if !strings.HasPrefix(rec.Title, keeperPathPrefix) {
			continue
		}
		path := strings.TrimPrefix(rec.Title, keeperPathPrefix)
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			continue
		}
		// S2-3: never include value fields in list output.
		entries = append(entries, backend.Entry{
			Meta: backend.Meta{
				Path:     path,
				Backend:  "keeper",
				Accessor: backend.ID(rec.RecordUID),
			},
			Exists: true,
		})
	}
	return entries, nil
}

// Close clears the TTL cache, zeroing cached byte slices before eviction.
func (b *KeeperBackend) Close() error {
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

// keeperTitle converts a canonical path to a Keeper record title.
func keeperTitle(path string) string {
	return "keylatch/" + path
}

// mapGetError maps keeper stderr to typed backend errors (S2-9).
func (b *KeeperBackend) mapGetError(errStr string) error {
	if isKeeperNotFound(errStr) {
		return fmt.Errorf("%w: keeper record not found", backend.ErrNotFound)
	}
	if isKeeperAuthFailure(errStr) {
		return fmt.Errorf("%w: Keeper session unavailable; run 'keeper login'", backend.ErrLocked)
	}
	return fmt.Errorf("%w: keeper get failed", backend.ErrUnavailable)
}

// isKeeperAuthFailure returns true when stderr indicates the user is not logged in.
func isKeeperAuthFailure(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "not logged in") ||
		strings.Contains(lower, "not authenticated") ||
		strings.Contains(lower, "login required") ||
		strings.Contains(lower, "session expired") ||
		strings.Contains(lower, "authentication failed")
}

// isKeeperNotFound returns true when stderr indicates the record was not found.
func isKeeperNotFound(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "not found") ||
		strings.Contains(lower, "no record") ||
		strings.Contains(lower, "record does not exist")
}
