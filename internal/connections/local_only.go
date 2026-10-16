package connections

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/localonly"
	"github.com/keylatch/keylatch/internal/registry"
)

// ErrHumanOnly is returned when a caller that is not a human tries to weaken
// how a field is delivered.
var ErrHumanOnly = errors.New("connections: weakening a local-only mode is human-only")

func validateLocalOnly(tmpl registry.ConnectionTemplate, class localonly.Class, modes map[string]localonly.Mode) error {
	if _, err := localonly.ParseClass(string(class)); err != nil {
		return err
	}
	for name, mode := range modes {
		if _, err := localonly.ParseMode(string(mode)); err != nil {
			return fmt.Errorf("connections: field %q: %w", name, err)
		}
		found := false
		for _, sf := range tmpl.SecretFields {
			if sf.Name == name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("connections: %q is not a secret field of %s", name, tmpl.Provider)
		}
		if err := localonly.CheckConnection(class, mode); err != nil {
			return fmt.Errorf("connections: field %q: %w", name, err)
		}
	}
	return nil
}

// Load reads the stored metadata of a connection.
func Load(ctx context.Context, namespace, provider string, store Store) (*Connection, error) {
	if namespace == "" {
		namespace = "default"
	}
	return loadConnection(ctx, namespace, provider, "default", store)
}

// SetLocalOnly changes the delivery mode of one field. An empty mode clears
// it. Changes that weaken delivery require a human caller. The new mode is
// validated against the connection class.
func SetLocalOnly(ctx context.Context, namespace, provider, field string, mode localonly.Mode, human bool, store Store) error {
	return SetLocalOnlyApproved(ctx, namespace, provider, field, mode, human, nil, store)
}

// ModeApprover decides whether a human accepts a weaker delivery mode. It sees
// the mode before and after, so the approval names exactly the change.
type ModeApprover func(old, next localonly.Mode) error

// SetLocalOnlyApproved is SetLocalOnly that also asks approve, when it is not
// nil, before a change that weakens delivery is written.
func SetLocalOnlyApproved(ctx context.Context, namespace, provider, field string, mode localonly.Mode, human bool, approve ModeApprover, store Store) error {
	if namespace == "" {
		namespace = "default"
	}
	tmpl, err := registry.Get(provider)
	if err != nil {
		return ErrProviderNotFound
	}
	conn, err := loadConnection(ctx, namespace, provider, "default", store)
	if err != nil {
		if errors.Is(err, backend.ErrNotFound) {
			return ErrConnectionNotFound
		}
		return err
	}
	old := conn.LocalOnly[field]
	if localonly.Weakens(old, mode) {
		if !human {
			return ErrHumanOnly
		}
		if approve != nil {
			if err := approve(old, mode); err != nil {
				return err
			}
		}
	}
	next := map[string]localonly.Mode{}
	for k, v := range conn.LocalOnly {
		next[k] = v
	}
	if mode == "" {
		delete(next, field)
	} else {
		next[field] = mode
	}
	if err := validateLocalOnly(tmpl, conn.Class, next); err != nil {
		return err
	}
	conn.LocalOnly = next
	if len(next) == 0 {
		conn.LocalOnly = nil
	}
	conn.UpdatedAt = time.Now().UTC()
	data, err := marshalConnection(conn)
	if err != nil {
		return fmt.Errorf("connections: marshal connection metadata: %w", err)
	}
	category := tmpl.Category
	if category == "" {
		category = "ai"
	}
	metaPath := connectionMetaPath(namespace, category, provider)
	return store.Set(ctx, metaPath, data, backend.Meta{Path: metaPath, Backend: "vault", Version: 1})
}
