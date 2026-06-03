package connections

import (
	"context"
	"net/http"
	"strings"

	"github.com/keylatch/keylatch/internal/registry"
)

// Status enumerates all connections in the given namespace and returns their
// status. If opts.Test is true, each connection is health-tested.
//
// Canonical path format: namespace/category/provider/meta (S-FIND-23).
// Scans all registered gateway-supporting categories in the namespace.
func Status(ctx context.Context, opts StatusOptions, store Store) ([]ConnectionStatus, error) {
	ns := opts.Namespace
	if ns == "" {
		ns = "default"
	}

	// Enumerate registered templates to discover all valid category/provider pairs.
	// This avoids a blind prefix scan and works with any backend that supports List.
	type connKey struct{ category, provider string }
	seen := map[connKey]struct{}{}

	allTemplates := registry.List()
	for _, tmpl := range allTemplates {
		cat := tmpl.Category
		if cat == "" {
			cat = "ai"
		}
		metaPath := connectionMetaPath(ns, cat, tmpl.Provider)
		_, _, err := store.Get(ctx, metaPath)
		if err == nil {
			seen[connKey{category: cat, provider: tmpl.Provider}] = struct{}{}
		}
	}

	// Also discover custom connections stored under namespace/custom/<name>/meta.
	// These are not in the registry so the template scan above misses them.
	customPrefix := ns + "/custom/"
	if entries, listErr := store.List(ctx, customPrefix); listErr == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Path, "/meta") {
				// Extract provider name: default/custom/<name>/meta → <name>
				parts := strings.Split(strings.TrimPrefix(e.Path, customPrefix), "/")
				if len(parts) >= 2 && parts[len(parts)-1] == "meta" {
					providerName := parts[0]
					seen[connKey{category: "custom", provider: providerName}] = struct{}{}
				}
			}
		}
	}

	var results []ConnectionStatus

	for k := range seen {
		// v1.0.0 uses a single "default" account per provider; multi-account is not supported.
		// For custom connections, use the category from the key directly so the path is correct.
		var conn *Connection
		var err error
		if k.category == "custom" {
			metaPath := connectionMetaPath(ns, k.category, k.provider)
			data, _, getErr := store.Get(ctx, metaPath)
			if getErr != nil {
				continue
			}
			conn, err = unmarshalConnection(data)
		} else {
			conn, err = loadConnection(ctx, ns, k.provider, "default", store)
		}
		if err != nil {
			continue
		}

		// Look up template for capabilities and gateway support.
		tmpl, err := registry.Get(k.provider)
		if err != nil {
			// Unknown provider; emit minimal status.
			results = append(results, ConnectionStatus{
				Connection: *conn,
			})
			continue
		}

		// Optionally run health test.
		if opts.Test {
			testResult, testErr := Test(ctx, k.provider, "default", ns, store, nil)
			if testErr == nil {
				conn.Status = testResult.Status
			}
		}

		// Populate capabilities by name only (S3-10: no values).
		capNames := make([]string, len(tmpl.Capabilities))
		for i, cap := range tmpl.Capabilities {
			capNames[i] = cap.Name
		}

		results = append(results, ConnectionStatus{
			Connection:       *conn,
			GatewaySupported: tmpl.RuntimeSupport.GatewaySupported,
			Capabilities:     capNames,
		})
	}

	return results, nil
}

// Describe returns the ConnectionTemplate for a provider with all secret field
// values replaced by "****". This is safe to display in any context (S3-10).
func Describe(ctx context.Context, providerOrConnection string, store Store) (*registry.ConnectionTemplate, map[string]string, error) {
	// providerOrConnection can be a provider slug or a "namespace/provider/account" path.
	provider := providerOrConnection
	// Try to resolve as a connection path.
	parts := strings.SplitN(providerOrConnection, "/", 3)
	if len(parts) == 3 {
		provider = parts[1]
	}

	tmpl, err := registry.Get(provider)
	if err != nil {
		return nil, nil, ErrProviderNotFound
	}

	// S3-10: replace all secret field values with "****".
	masked := make(map[string]string, len(tmpl.SecretFields))
	for _, sf := range tmpl.SecretFields {
		masked[sf.Name] = "****"
	}

	// Return a copy of the template (no modification of the registry).
	return &tmpl, masked, nil
}

// httpClientForTest is used in tests to inject a custom http.Client.
// Production code passes nil to use the default.
var _ *http.Client = nil // compile-time check that http.Client is imported
