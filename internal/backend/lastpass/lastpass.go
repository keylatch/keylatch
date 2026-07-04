// Package lastpass implements the Backend interface using the LastPass CLI (`lpass`).
// It shells out via internal/exec.CommandRunner and satisfies the following
// security invariants.
//
// Security invariants:
//   - Never print secret values to stdout/stderr.
//   - List zero-fills field values before returning.
//   - Fail-closed on binary unavailability (ErrUnavailable).
//   - Raw subprocess stderr never propagated; auth-failure hints only.
//   - Single-flight collapse for concurrent Get calls.
//
// Security note: LastPass has had significant breach history. WarningMessage()
// returns a notice that is displayed in doctor checks and describe output.
package lastpass

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/sync/singleflight"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
)

// compile-time interface check.
var _ backend.Backend = (*LastPassBackend)(nil)

// Options configures a LastPassBackend.
type Options struct {
	// Bin is the explicit path to the `lpass` binary. If empty, PATH is searched.
	Bin string

	// Username is the LastPass account email. Used for ID hashing.
	Username string

	// Runner is injectable for tests. Defaults to exec.DefaultRunner.
	Runner kexec.CommandRunner
}

// LastPassBackend implements backend.Backend using the LastPass CLI.
type LastPassBackend struct {
	opts Options
	sf   singleflight.Group
}

// Open validates options, resolves the `lpass` binary, and returns an initialized
// LastPassBackend. Returns backend.ErrUnavailable if `lpass` is not found.
func Open(opts Options) (*LastPassBackend, error) {
	bin := opts.Bin
	if bin == "" {
		bin = kexec.Resolve("lpass")
		if bin == "" {
			return nil, fmt.Errorf("%w: LastPass CLI not found. Install: brew install lastpass-cli",
				backend.ErrUnavailable)
		}
	}
	opts.Bin = bin

	if opts.Runner == nil {
		opts.Runner = kexec.DefaultRunner
	}

	return &LastPassBackend{opts: opts}, nil
}

// Name implements backend.Backend.
func (b *LastPassBackend) Name() string { return "lastpass" }

// Capabilities implements backend.Backend.
func (b *LastPassBackend) Capabilities() []backend.Capability {
	return []backend.Capability{backend.CapList}
}

// WarningMessage returns a security notice about LastPass breach history.
// This is not part of the Backend interface — it is used by doctor checks
// and describe output to inform users.
func (b *LastPassBackend) WarningMessage() string {
	return "LastPass has had significant breach history. Migrate to a more modern vault when possible."
}

// Get returns the plaintext bytes for a canonical path via `lpass show --json`.
// Uses single-flight collapse for concurrent identical calls.
func (b *LastPassBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	name := lpassName(path)

	type result struct {
		val  []byte
		meta backend.Meta
		err  error
	}

	ch := b.sf.DoChan(name, func() (interface{}, error) {
		args := []string{"show", "--json", "--field=Password", name}
		stdout, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, nil)
		if err != nil {
			return result{err: fmt.Errorf("lastpass: runner error: %w", err)}, nil
		}
		if exitCode != 0 {
			return result{err: b.mapGetError(string(stderr))}, nil
		}

		// lpass show --json returns an array of items.
		var items []lpassGetResult
		if err := json.Unmarshal(stdout, &items); err != nil {
			return result{err: fmt.Errorf("%w: lastpass get failed to parse response", backend.ErrUnavailable)}, nil
		}
		if len(items) == 0 {
			return result{err: fmt.Errorf("%w: %s", backend.ErrNotFound, name)}, nil
		}

		val := []byte(items[0].Password)
		meta := backend.Meta{
			Path:     path,
			Backend:  "lastpass",
			Accessor: backend.ID(items[0].ID),
		}
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

// Set writes a value via `lpass add --non-interactive`.
func (b *LastPassBackend) Set(ctx context.Context, path string, value []byte, _ backend.Meta) error {
	name := lpassName(path)
	stdin := fmt.Appendf(nil, "Username: keylatch\nPassword: %s\n", value)

	args := []string{"add", "--non-interactive", "--name", name}
	_, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, stdin)
	if err != nil {
		return fmt.Errorf("lastpass: runner error: %w", err)
	}
	if exitCode != 0 {
		errStr := string(stderr)
		if isLpassAuthFailure(errStr) {
			return fmt.Errorf("%w: LastPass session unavailable; run 'lpass login <email>'", backend.ErrLocked)
		}
		return fmt.Errorf("%w: lastpass set failed", backend.ErrUnavailable)
	}
	return nil
}

// Delete removes a LastPass item via `lpass rm`.
func (b *LastPassBackend) Delete(ctx context.Context, path string) error {
	name := lpassName(path)

	args := []string{"rm", name}
	_, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, nil)
	if err != nil {
		return fmt.Errorf("lastpass: runner error: %w", err)
	}
	if exitCode != 0 {
		errStr := string(stderr)
		if isLpassNotFound(errStr) {
			return fmt.Errorf("%w: %s", backend.ErrNotFound, name)
		}
		if isLpassAuthFailure(errStr) {
			return fmt.Errorf("%w: LastPass session unavailable; run 'lpass login <email>'", backend.ErrLocked)
		}
		return fmt.Errorf("%w: lastpass delete failed", backend.ErrUnavailable)
	}
	return nil
}

// List returns metadata-only entries via `lpass ls --json`.
func (b *LastPassBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	args := []string{"ls", "--json", "--sync=no"}
	stdout, stderr, exitCode, err := b.opts.Runner.Run(ctx, b.opts.Bin, args, nil)
	if err != nil {
		return nil, fmt.Errorf("lastpass: runner error: %w", err)
	}
	if exitCode != 0 {
		if isLpassAuthFailure(string(stderr)) {
			return nil, fmt.Errorf("%w: LastPass session unavailable; run 'lpass login <email>'", backend.ErrLocked)
		}
		return nil, fmt.Errorf("%w: lastpass list failed", backend.ErrUnavailable)
	}

	var items []lpassListItem
	if err := json.Unmarshal(stdout, &items); err != nil {
		return nil, fmt.Errorf("lastpass: decode list response: %w", err)
	}

	const lpassPathPrefix = "keylatch/"
	var entries []backend.Entry
	for _, item := range items {
		if !strings.HasPrefix(item.Name, lpassPathPrefix) {
			continue
		}
		path := strings.TrimPrefix(item.Name, lpassPathPrefix)
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			continue
		}
		// Never include value fields in list output.
		entries = append(entries, backend.Entry{
			Meta: backend.Meta{
				Path:     path,
				Backend:  "lastpass",
				Accessor: backend.ID(item.ID),
			},
			Exists: true,
		})
	}
	return entries, nil
}

// Close is a no-op for the lastpass backend.
func (b *LastPassBackend) Close() error { return nil }

// lpassName converts a canonical path to a LastPass item name.
// Strips any existing "keylatch/" prefix before prepending to prevent double-prefixing.
func lpassName(path string) string {
	path = strings.TrimPrefix(path, "keylatch/")
	return "keylatch/" + path
}

// mapGetError maps lpass stderr to typed backend errors.
func (b *LastPassBackend) mapGetError(errStr string) error {
	if isLpassNotFound(errStr) {
		return fmt.Errorf("%w: lastpass item not found", backend.ErrNotFound)
	}
	if isLpassAuthFailure(errStr) {
		return fmt.Errorf("%w: LastPass session unavailable; run 'lpass login <email>'", backend.ErrLocked)
	}
	return fmt.Errorf("%w: lastpass get failed", backend.ErrUnavailable)
}

// isLpassAuthFailure returns true when stderr indicates the user is not logged in.
func isLpassAuthFailure(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "not logged in") ||
		strings.Contains(lower, "please login") ||
		strings.Contains(lower, "session expired") ||
		strings.Contains(lower, "invalid username or password")
}

// isLpassNotFound returns true when stderr indicates the item was not found.
func isLpassNotFound(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "could not find") ||
		strings.Contains(lower, "no results") ||
		strings.Contains(lower, "no matching") ||
		strings.Contains(lower, "not found")
}
