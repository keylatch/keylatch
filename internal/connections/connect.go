package connections

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/registry"
)

// Store is the interface that connections uses to read and write to the vault.
// Kept minimal so tests can supply an in-memory implementation.
type Store interface {
	Get(ctx context.Context, path string) ([]byte, backend.Meta, error)
	Set(ctx context.Context, path string, value []byte, meta backend.Meta) error
	List(ctx context.Context, prefix string) ([]backend.Entry, error)
	Delete(ctx context.Context, path string) error
}

// Connect creates a new connection for the given provider.
//
// Steps:
//  1. Look up the registry template.
//  2. For each SecretField: read from opts.Fields or prompt interactively.
//  3. Write each secret to vault under canonical "namespace/category/provider/field" path.
//  4. Zero secret byte slices after write.
//  5. Write connection metadata to vault.
//  6. Return the populated Connection with Status="untested".
//
// Returns ErrAmbiguous when a connection already exists for this provider+namespace
// and opts.Account is empty on a multi-account provider.
func Connect(ctx context.Context, provider string, opts ConnectOptions, store Store) (*Connection, error) {
	// Step 1: look up template.
	tmpl, err := registry.Get(provider)
	if err != nil {
		return nil, ErrProviderNotFound
	}

	// Default namespace.
	ns := opts.Namespace
	if ns == "" {
		ns = "default"
	}

	// Determine account.
	account := opts.Account
	if account == "" {
		account = "default"
	}

	category := tmpl.Category
	if category == "" {
		category = "ai"
	}

	// Check for existing connection.
	metaPath := connectionMetaPath(ns, category, provider)
	_, _, existErr := store.Get(ctx, metaPath)
	if existErr == nil {
		// Connection already exists.
		if tmpl.MultiAccount && opts.Account == "" {
			// Multi-account provider with no account specified — ambiguous.
			return nil, ErrAmbiguous
		}
		// Single-account provider: return ErrConnectionExists.
		return nil, ErrConnectionExists
	}

	// Determine runtime mode.
	mode := opts.Mode
	if mode == "" || !registry.IsValidRuntimeMode(mode) {
		mode = tmpl.RuntimeSupport.Preferred
	}

	// Step 2 & 3: process each secret field.
	fieldNames := make([]string, 0, len(tmpl.SecretFields))
	for _, sf := range tmpl.SecretFields {
		fieldNames = append(fieldNames, sf.Name)

		var value []byte
		if v, ok := opts.Fields[sf.Name]; ok {
			value = v
		} else if !opts.NonInteractive && sf.Required {
			return nil, fmt.Errorf("connections: missing required field %q (use --non-interactive to error instead of prompting)", sf.Name)
		} else if sf.Required {
			return nil, fmt.Errorf("connections: missing required field %q", sf.Name)
		}

		if len(value) > 0 {
			fieldPath := secretFieldPath(ns, category, provider, sf.Name)
			meta := backend.Meta{
				Path:    fieldPath,
				Backend: "vault",
				Version: 1,
			}
			if err := store.Set(ctx, fieldPath, value, meta); err != nil {
				// Zero before returning on error.
				zeroBytes(value)
				return nil, fmt.Errorf("connections: write field %q: %w", sf.Name, err)
			}
			// Step 4: zero secret bytes after write.
			zeroBytes(value)
		}
	}

	// Process config fields (apply defaults).
	for _, cf := range tmpl.ConfigFields {
		val := ""
		if v, ok := opts.Fields[cf.Name]; ok {
			val = string(v)
		}
		if val == "" && cf.Default != "" {
			val = cf.Default
		}
		if val != "" {
			configPath := configFieldPath(ns, category, provider, cf.Name)
			meta := backend.Meta{
				Path:    configPath,
				Backend: "vault",
				Version: 1,
			}
			if err := store.Set(ctx, configPath, []byte(val), meta); err != nil {
				return nil, fmt.Errorf("connections: write config field %q: %w", cf.Name, err)
			}
		}
	}

	now := time.Now().UTC()

	// Step 5: write connection metadata.
	conn := &Connection{
		Provider:  provider,
		Account:   account,
		Namespace: ns,
		Runtime:   mode,
		CreatedAt: now,
		UpdatedAt: now,
		Fields:    fieldNames,
		Status:    "untested",
	}

	connMeta := backend.Meta{
		Path:    metaPath,
		Backend: "vault",
		Version: 1,
	}
	connBytes, err := marshalConnection(conn)
	if err != nil {
		return nil, fmt.Errorf("connections: marshal connection metadata: %w", err)
	}
	if err := store.Set(ctx, metaPath, connBytes, connMeta); err != nil {
		return nil, fmt.Errorf("connections: write connection metadata: %w", err)
	}

	return conn, nil
}

// connectionMetaPath returns the vault path for connection metadata.
// Canonical format: namespace/category/provider/meta
// S-FIND-23: v1.0.0 uses four-segment paths exclusively.
func connectionMetaPath(namespace, category, provider string) string {
	if category == "" {
		category = "ai"
	}
	return fmt.Sprintf("%s/%s/%s/meta", namespace, category, provider)
}

// secretFieldPath returns the vault path for a secret field.
// Canonical format: namespace/category/provider/field
// S-FIND-23: v1.0.0 uses four-segment paths exclusively.
func secretFieldPath(namespace, category, provider, field string) string {
	if category == "" {
		category = "ai"
	}
	return fmt.Sprintf("%s/%s/%s/%s", namespace, category, provider, field)
}

// configFieldPath returns the vault path for a config field.
// Canonical format: namespace/category/provider/config/field
func configFieldPath(namespace, category, provider, field string) string {
	if category == "" {
		category = "ai"
	}
	return fmt.Sprintf("%s/%s/%s/config/%s", namespace, category, provider, field)
}

// Delete removes all stored data for a connection (secret fields, config fields, and metadata).
// It is the inverse of Connect and is used to rollback a failed connection.
// Returns nil if the connection does not exist (idempotent for ErrNotFound).
func Delete(ctx context.Context, provider, account, namespace string, store Store) error {
	tmpl, err := registry.Get(provider)
	if err != nil {
		return ErrProviderNotFound
	}
	if namespace == "" {
		namespace = "default"
	}
	if account == "" {
		account = "default"
	}

	category := tmpl.Category
	if category == "" {
		category = "ai"
	}

	var errs []error

	// Delete secret fields.
	for _, sf := range tmpl.SecretFields {
		path := secretFieldPath(namespace, category, provider, sf.Name)
		if delErr := store.Delete(ctx, path); delErr != nil && !errors.Is(delErr, backend.ErrNotFound) {
			errs = append(errs, delErr)
		}
	}

	// Delete config fields.
	for _, cf := range tmpl.ConfigFields {
		path := configFieldPath(namespace, category, provider, cf.Name)
		if delErr := store.Delete(ctx, path); delErr != nil && !errors.Is(delErr, backend.ErrNotFound) {
			errs = append(errs, delErr)
		}
	}

	// Delete connection metadata.
	metaPath := connectionMetaPath(namespace, category, provider)
	if delErr := store.Delete(ctx, metaPath); delErr != nil && !errors.Is(delErr, backend.ErrNotFound) {
		errs = append(errs, delErr)
	}

	if len(errs) > 0 {
		return fmt.Errorf("delete connection %s/%s: %d errors; first: %w", provider, account, len(errs), errs[0])
	}
	return nil
}

// zeroBytes zeroes a byte slice in place.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
