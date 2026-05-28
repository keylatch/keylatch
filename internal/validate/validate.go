// Package validate provides connection store validation utilities.
// It checks that all required secret fields are present in the vault for each
// stored connection.
package validate

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/registry"
)

// Issue describes a single validation finding for a connection.
type Issue struct {
	Field    string // field name that caused the issue
	Severity string // "error" | "warning"
	Message  string
	IsError  bool
}

// ErrValidationFailed is returned when one or more error-severity issues are found.
var ErrValidationFailed = errors.New("validate: one or more required fields are missing")

// ValidateOptions controls validation behaviour.
type ValidateOptions struct {
	Namespace string
	Strict    bool // treat unknown config keys as error-severity issues
}

// ValidateConnection checks that all required secret fields for the given
// connection are present in the vault.
func ValidateConnection(ctx context.Context, namespace, provider, _ string, store connections.Store) ([]Issue, error) {
	if namespace == "" {
		namespace = "default"
	}

	tmpl, err := registry.Get(provider)
	if err != nil {
		return nil, connections.ErrProviderNotFound
	}

	category := tmpl.Category
	if category == "" {
		category = "ai"
	}

	var issues []Issue

	// Check each required SecretField is present in vault.
	for _, sf := range tmpl.SecretFields {
		if !sf.Required {
			continue
		}
		fieldPath := secretFieldPath(namespace, category, provider, sf.Name)
		_, _, err := store.Get(ctx, fieldPath)
		if err != nil {
			if errors.Is(err, backend.ErrNotFound) {
				issues = append(issues, Issue{
					Field:    sf.Name,
					Severity: "error",
					Message:  "required secret field is not present in vault",
					IsError:  true,
				})
			} else {
				issues = append(issues, Issue{
					Field:    sf.Name,
					Severity: "error",
					Message:  "vault read error",
					IsError:  true,
				})
			}
		}
	}

	// Warn about overbroad scopes.
	for _, scope := range tmpl.OverbroadScopes {
		issues = append(issues, Issue{
			Field:    scope,
			Severity: "warning",
			Message:  "overbroad scope configured; consider restricting access",
			IsError:  false,
		})
	}

	// Strict mode: unknown config keys in vault are treated as errors.
	if false { // placeholder for strict mode config-key check (opts not available here)
		_ = issues
	}

	return issues, nil
}

// ValidateStore validates all connections in the given namespace.
// Returns all issues across all connections.
//
// Canonical path format: namespace/category/provider/meta (S-FIND-23).
// Scans each registered provider's meta path to discover connected providers.
func ValidateStore(ctx context.Context, opts ValidateOptions, store connections.Store) ([]Issue, error) {
	ns := opts.Namespace
	if ns == "" {
		ns = "default"
	}

	// Enumerate all registered templates to discover connected providers.
	type connKey struct {
		category string
		provider string
	}
	seen := map[connKey]struct{}{}

	allTemplates := registry.List()
	for _, tmpl := range allTemplates {
		cat := tmpl.Category
		if cat == "" {
			cat = "ai"
		}
		metaPath := secretFieldPath(ns, cat, tmpl.Provider, "meta")
		// List with exact path prefix to check existence.
		entries, err := store.List(ctx, strings.TrimSuffix(metaPath, "meta"))
		if err != nil {
			slog.Warn("validate: store.List failed; scan may be incomplete",
				"provider", tmpl.Provider, "error", err)
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Path, "/meta") {
				seen[connKey{category: cat, provider: tmpl.Provider}] = struct{}{}
				break
			}
		}
	}

	var allIssues []Issue
	for k := range seen {
		issues, err := ValidateConnection(ctx, ns, k.provider, "default", store)
		if err != nil {
			continue // skip unknown providers
		}

		// Strict mode: flag unknown config keys.
		if opts.Strict {
			configPrefix := ns + "/" + k.category + "/" + k.provider + "/config/"
			cfgEntries, listErr := store.List(ctx, configPrefix)
			if listErr != nil {
				slog.Warn("validate: store.List failed for config keys; strict scan may be incomplete",
					"provider", k.provider, "error", listErr)
			}
			tmpl, regErr := registry.Get(k.provider)
			if regErr == nil {
				knownConfigs := map[string]struct{}{}
				for _, cf := range tmpl.ConfigFields {
					knownConfigs[cf.Name] = struct{}{}
				}
				for _, ce := range cfgEntries {
					key := strings.TrimPrefix(ce.Path, configPrefix)
					if _, ok := knownConfigs[key]; !ok {
						issues = append(issues, Issue{
							Field:    key,
							Severity: "error",
							Message:  "unknown config key (--strict mode)",
							IsError:  true,
						})
					}
				}
			}
		}

		allIssues = append(allIssues, issues...)
	}

	return allIssues, nil
}

// secretFieldPath mirrors the connections package canonical path helper.
// Canonical format: namespace/category/provider/field (S-FIND-23).
func secretFieldPath(namespace, category, provider, field string) string {
	if category == "" {
		category = "ai"
	}
	return namespace + "/" + category + "/" + provider + "/" + field
}
