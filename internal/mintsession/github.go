// Package mintsession loads the key material of a GitHub App connection and
// mints scoped installation tokens from it. The command-line mint verb and the
// daemon's placeholder sessions share it.
package mintsession

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/policy/mint"
)

// FieldError reports a connection field that could not be read.
type FieldError struct {
	Field   string
	Missing bool
	Err     error
}

func (e *FieldError) Error() string {
	if e.Missing {
		return fmt.Sprintf("connection has no %s", e.Field)
	}
	return fmt.Sprintf("read %s: %v", e.Field, e.Err)
}

func (e *FieldError) Unwrap() error { return e.Err }

// ErrKey is wrapped when the stored private key cannot be parsed.
var ErrKey = errors.New("github app private key is not usable")

// LoadGitHubApp reads the App ID, the installation of the repository's owner
// and the private key from store and returns a strategy that signs with them.
func LoadGitHubApp(ctx context.Context, store connections.Store, namespace, category, connection, repo, apiBase string) (*strategies.GitHubAppInstallationStrategy, error) {
	owner, _, _ := strings.Cut(repo, "/")
	read := func(path, field string) ([]byte, error) {
		v, _, err := store.Get(ctx, path)
		if errors.Is(err, backend.ErrNotFound) || (err == nil && len(v) == 0) {
			return nil, &FieldError{Field: field, Missing: true, Err: backend.ErrNotFound}
		}
		if err != nil {
			return nil, &FieldError{Field: field, Err: err}
		}
		return v, nil
	}

	instField := "installation_" + strings.ToLower(owner)
	inst, err := read(connections.ConfigFieldPath(namespace, category, connection, instField), instField)
	if err != nil {
		return nil, err
	}
	appID, err := read(connections.ConfigFieldPath(namespace, category, connection, "app_id"), "app_id")
	if err != nil {
		return nil, err
	}
	keyPEM, err := read(connections.SecretFieldPath(namespace, category, connection, "private_key"), "private_key")
	if err != nil {
		return nil, err
	}
	key, err := strategies.ParseGitHubAppPrivateKey(keyPEM)
	clear(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	return strategies.NewGitHubAppInstallationStrategy(
		strings.TrimSpace(string(appID)), strings.TrimSpace(string(inst)), key,
		strategies.WithGitHubAPIBase(apiBase),
	), nil
}

// AuditEvent records one mint without the token.
type AuditEvent struct {
	Connection  string
	Namespace   string
	Repository  string
	Permissions map[string]string
	Caller      mint.CallerKind
	RuntimeMode string
	ExpiresAt   time.Time
	Outcome     audit.Outcome
	Reason      string
}

// Emit writes the event.
func (e AuditEvent) Emit(ctx context.Context, em audit.Emitter) error {
	extra := map[string]any{
		"connection":  e.Connection,
		"namespace":   e.Namespace,
		"repository":  e.Repository,
		"permissions": FormatPermissions(e.Permissions),
		"caller_kind": string(e.Caller),
	}
	if !e.ExpiresAt.IsZero() {
		extra["expires_at"] = e.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if e.Reason != "" {
		extra["reason"] = e.Reason
	}
	return em.Emit(ctx, audit.Event{
		Timestamp:   time.Now().UTC(),
		Action:      audit.ActionMint,
		Outcome:     e.Outcome,
		RuntimeMode: e.RuntimeMode,
		Extra:       extra,
	})
}

// FormatPermissions renders permissions as sorted name=level pairs.
func FormatPermissions(p map[string]string) string {
	keys := slices.Sorted(maps.Keys(p))
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + p[k]
	}
	return strings.Join(parts, ",")
}
