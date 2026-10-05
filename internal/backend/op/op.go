// Package op implements the Backend interface using the 1Password CLI (`op`).
// It shells out via internal/exec.CommandRunner, stores one 1Password item per
// Keylatch connection, and satisfies the following security invariants.
//
// Security invariants:
//   - Never print secret values to stdout/stderr.
//   - List zero-fills field values before returning.
//   - Fail-closed on binary unavailability (ErrUnavailable).
//   - Raw subprocess stderr never propagated; auth-failure hints only.
//   - Single-flight collapse for concurrent Get calls.
package op

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
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
// Uses single-flight collapse and a 60-second metadata cache.
//
// Checks runner.OK before returning plaintext.
func (b *OnePasswordBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	if !runner.OK(ctx) {
		return nil, backend.Meta{}, backend.ErrLocked
	}

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

	// The value travels in a JSON item template on stdin: an assignment
	// statement argument would expose it in the process list.
	conn, account := parseConnectionAccount(connection)
	_, raw, fetchErr := b.fetchItemJSON(ctx, connection)
	exists := fetchErr == nil

	var (
		args     []string
		template []byte
	)
	if exists {
		template, err = editTemplate(raw, field, value)
		if err != nil {
			return fmt.Errorf("op Set: %w", err)
		}
		args = []string{"item", "edit", conn}
		if stdinTemplatePath != "" {
			args = append(args, "--template="+stdinTemplatePath)
		}
		args = append(args, "--vault="+b.opts.Vault, "--format=json")
	} else {
		template, err = createTemplate(field, value)
		if err != nil {
			return fmt.Errorf("op Set: %w", err)
		}
		args = []string{"item", "create", "-",
			"--category=" + classifyCategory(field),
			"--title=" + conn,
			"--vault=" + b.opts.Vault,
			"--tags=keylatch,ns:default",
			"--format=json",
		}
	}
	if account != "" {
		args = append(args, "--account="+account)
	}

	_, stderr, exitCode, err := b.runWithEnv(ctx, args, template)
	if err != nil {
		return fmt.Errorf("op Set: runner error: %w", err)
	}
	if exitCode != 0 {
		if isAuthFailure(string(stderr)) {
			return fmt.Errorf("%w: Run: eval $(op signin)", backend.ErrLocked)
		}
		return fmt.Errorf("op Set: op exited %d", exitCode)
	}

	b.cache.Delete(connection)
	return b.verifyField(ctx, connection, field, value)
}

// ErrWriteNotApplied is returned when op reports success but the item read
// back does not hold the value just written, as when op ignores a template.
var ErrWriteNotApplied = errors.New("op: the item does not hold the value that was written")

// verifyField reads the item back and checks that field holds value. Only
// digests are compared, and neither value appears in the error.
func (b *OnePasswordBackend) verifyField(ctx context.Context, connection, field string, value []byte) error {
	item, _, err := b.fetchItemJSON(ctx, connection)
	if err != nil {
		return fmt.Errorf("op Set: read back %q: %w", connection, err)
	}
	want := sha256.Sum256(value)
	for _, f := range item.Fields {
		if f.Label != field {
			continue
		}
		got := sha256.Sum256([]byte(f.Value))
		if subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
			return nil
		}
		break
	}
	return fmt.Errorf("%w: field %q of %q", ErrWriteNotApplied, field, connection)
}

// Delete removes a 1Password item via `op item delete`.
func (b *OnePasswordBackend) Delete(ctx context.Context, path string) error {
	connection, _, err := parsePath(path)
	if err != nil {
		return fmt.Errorf("op Delete: %w", err)
	}

	// Invalidate cache.
	b.cache.Delete(connection)

	_, stderr, exitCode, err := b.runWithEnv(ctx,
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

// List returns metadata-only entries with zero-filled field values.
func (b *OnePasswordBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	stdout, stderr, exitCode, err := b.runWithEnv(ctx,
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

	// See fetchItemDirect: exitCode == 0 with empty stdout indicates a
	// stale/expired session, not valid empty JSON.
	if len(stdout) == 0 {
		return nil, fmt.Errorf("%w: Run: eval $(op signin)", backend.ErrLocked)
	}

	var items []opItem
	if err := json.Unmarshal(stdout, &items); err != nil {
		return nil, fmt.Errorf("op List: decode response: %w", err)
	}

	var entries []backend.Entry
	for _, item := range items {
		for _, f := range item.Fields {
			// Zero-fill field values unconditionally on list.
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

// fetchItem returns an opItem, using cache + single-flight collapse.
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
	item, _, err := b.fetchItemJSON(ctx, connection)
	return item, err
}

// fetchItemJSON is fetchItemDirect that also returns the item's raw JSON.
func (b *OnePasswordBackend) fetchItemJSON(ctx context.Context, connection string) (opItem, []byte, error) {
	conn, account := parseConnectionAccount(connection)

	args := []string{"item", "get", conn,
		"--vault=" + b.opts.Vault,
		"--format=json",
	}
	if account != "" {
		args = append(args, "--account="+account)
	}

	stdout, stderr, exitCode, err := b.runWithEnv(ctx, args, nil)
	if err != nil {
		return opItem{}, nil, fmt.Errorf("op: runner error: %w", err)
	}

	if exitCode != 0 {
		stderrStr := string(stderr)
		// Do not echo raw stderr — map to typed errors with hints.
		if isAuthFailure(stderrStr) {
			return opItem{}, nil, fmt.Errorf("%w: Run: eval $(op signin)", backend.ErrLocked)
		}
		if isNotFound(stderrStr) {
			return opItem{}, nil, fmt.Errorf("%w: %s", backend.ErrNotFound, conn)
		}
		// Detect multi-result (ambiguous) response via "More than one item" marker.
		if isAmbiguous(stderrStr) {
			return opItem{}, nil, ErrAmbiguous{Connection: conn, Count: 2}
		}
		// Generic failure — do not expose raw stderr.
		return opItem{}, nil, fmt.Errorf("op: item get exited %d", exitCode)
	}

	// exitCode == 0 with empty stdout indicates a stale/expired session
	// that op did not surface as a non-zero exit — without this guard the
	// decode attempts below fail with a confusing "invalid JSON" error
	// instead of actionable signin guidance.
	if len(stdout) == 0 {
		return opItem{}, nil, fmt.Errorf("%w: Run: eval $(op signin)", backend.ErrLocked)
	}

	// Try to decode as a single item first.
	var item opItem
	if err := json.Unmarshal(stdout, &item); err == nil {
		return item, stdout, nil
	}

	// If it decoded as an array (multi-result), return ErrAmbiguous.
	var rawItems []json.RawMessage
	if err := json.Unmarshal(stdout, &rawItems); err == nil {
		if len(rawItems) > 1 {
			return opItem{}, nil, ErrAmbiguous{Connection: conn, Count: len(rawItems)}
		}
		if len(rawItems) == 1 && json.Unmarshal(rawItems[0], &item) == nil {
			return item, rawItems[0], nil
		}
		return opItem{}, nil, fmt.Errorf("%w: %s", backend.ErrNotFound, conn)
	}

	return opItem{}, nil, fmt.Errorf("op: decode item response: invalid JSON")
}

// runWithEnv invokes the op CLI via CommandRunner.RunEnv, explicitly
// forwarding OP_SERVICE_ACCOUNT_TOKEN (when present) through opts.Env rather
// than relying solely on ambient os.Environ() inheritance. Options.Env was
// previously read once at Open() and then never consulted again — every
// op subprocess call now depends on the injected lookup, which matters under
// daemon/sandboxed exec paths where the parent's ambient env is not
// implicitly passed through to the op CLI process.
//
// op's interactive/biometric session state (op signin, Touch ID) is managed
// entirely by op's own daemon — this seam only forwards the service-account
// token; it does not maintain a keylatch-side session cache (see
// newOPSigninCmd's Long help for why op deliberately has no cache).
func (b *OnePasswordBackend) runWithEnv(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, int, error) {
	var extraEnv []string
	if tok := b.opts.Env("OP_SERVICE_ACCOUNT_TOKEN"); tok != "" {
		extraEnv = append(extraEnv, "OP_SERVICE_ACCOUNT_TOKEN="+tok)
	}
	return b.opts.Runner.RunEnv(ctx, b.bin, args, stdin, extraEnv)
}

// stdinTemplatePath names stdin for the edit command's --template flag.
// Windows has no such path; there op reads the piped template without the
// flag, and the read-back in Set catches an edit that was not applied.
var stdinTemplatePath = func() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/dev/stdin"
}()

// createTemplate builds the item template that carries the field for
// `op item create -`.
func createTemplate(field string, value []byte) ([]byte, error) {
	b, err := json.Marshal(map[string]any{"fields": []any{newTemplateField(field, value)}})
	if err != nil {
		return nil, fmt.Errorf("marshal item template: %w", err)
	}
	return b, nil
}

// editTemplate returns the existing item JSON with field set to value. Every
// other property is kept verbatim because op replaces the item with the
// template it is given.
func editTemplate(itemJSON []byte, field string, value []byte) ([]byte, error) {
	var item map[string]any
	if err := json.Unmarshal(itemJSON, &item); err != nil {
		return nil, fmt.Errorf("decode item for edit: %w", err)
	}
	fields, _ := item["fields"].([]any)
	found := false
	for _, f := range fields {
		m, ok := f.(map[string]any)
		if !ok {
			continue
		}
		if label, _ := m["label"].(string); label == field {
			m["value"] = string(value)
			found = true
			break
		}
	}
	if !found {
		fields = append(fields, newTemplateField(field, value))
	}
	item["fields"] = fields
	b, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("marshal item template: %w", err)
	}
	return b, nil
}

func newTemplateField(field string, value []byte) map[string]any {
	return map[string]any{
		"id":    field,
		"label": field,
		"type":  strings.ToUpper(classifyFieldType(field)),
		"value": string(value),
	}
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
