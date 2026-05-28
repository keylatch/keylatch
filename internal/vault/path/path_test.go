package path_test

import (
	"testing"

	vpath "github.com/keylatch/keylatch/internal/vault/path"
)

// testResolver is a simple map-based CategoryResolver stub.
func testResolver(m map[string]string) vpath.CategoryResolver {
	return func(provider string) (string, error) {
		cat, ok := m[provider]
		if !ok {
			return "", vpath.ErrUnknownProvider
		}
		return cat, nil
	}
}

var defaultResolver = testResolver(map[string]string{
	"openrouter": "ai",
	"sentry":     "observability",
	"dropbox":    "storage",
	"atlassian":  "devtools",
})

var defaultDefaults = vpath.Defaults{Namespace: "default"}

// -----------------------------------------------------------------------
// Canonicalize tests
// -----------------------------------------------------------------------

func TestCanonicalize(t *testing.T) {
	cases := []struct {
		name      string
		shorthand string
		defaults  vpath.Defaults
		resolve   vpath.CategoryResolver
		want      string
		wantErr   error
	}{
		// Form 1: already canonical
		{
			name:      "already canonical",
			shorthand: "default/ai/openrouter/api_key",
			defaults:  defaultDefaults,
			resolve:   defaultResolver,
			want:      "default/ai/openrouter/api_key",
		},
		// Form 2: provider.field
		{
			name:      "provider.field",
			shorthand: "openrouter.api_key",
			defaults:  defaultDefaults,
			resolve:   defaultResolver,
			want:      "default/ai/openrouter/api_key",
		},
		// Form 3: ns:provider.field
		{
			name:      "ns:provider.field",
			shorthand: "personal:openrouter.api_key",
			defaults:  vpath.Defaults{Namespace: "default"},
			resolve:   defaultResolver,
			want:      "personal/ai/openrouter/api_key",
		},
		// Form 4: provider:account.field
		{
			name:      "provider:account.field",
			shorthand: "sentry:acme.auth_token",
			defaults:  defaultDefaults,
			resolve:   defaultResolver,
			want:      "default/observability/sentry:acme/auth_token",
		},
		// Error: provider only (no field)
		{
			name:      "provider only",
			shorthand: "openrouter",
			defaults:  defaultDefaults,
			resolve:   defaultResolver,
			wantErr:   vpath.ErrInvalidPath,
		},
		// Error: unknown provider
		{
			name:      "unknown provider",
			shorthand: "unknownprovider.api_key",
			defaults:  defaultDefaults,
			resolve:   defaultResolver,
			wantErr:   vpath.ErrUnknownProvider,
		},
		// Error: ambiguous — no namespace
		{
			name:      "ambiguous no namespace",
			shorthand: "openrouter.api_key",
			defaults:  vpath.Defaults{}, // no default namespace
			resolve:   defaultResolver,
			wantErr:   vpath.ErrAmbiguous,
		},
		// Error: leading slash
		{
			name:      "leading slash",
			shorthand: "/default/ai/openrouter/api_key",
			defaults:  defaultDefaults,
			resolve:   defaultResolver,
			wantErr:   vpath.ErrInvalidPath,
		},
		// Error: trailing slash
		{
			name:      "trailing slash",
			shorthand: "default/ai/openrouter/api_key/",
			defaults:  defaultDefaults,
			resolve:   defaultResolver,
			wantErr:   vpath.ErrInvalidPath,
		},
		// Error: double dot
		{
			name:      "double dot",
			shorthand: "openrouter..api_key",
			defaults:  defaultDefaults,
			resolve:   defaultResolver,
			wantErr:   vpath.ErrInvalidPath,
		},
		// Error: empty string
		{
			name:      "empty string",
			shorthand: "",
			defaults:  defaultDefaults,
			resolve:   defaultResolver,
			wantErr:   vpath.ErrInvalidPath,
		},
		// Canonical with account
		{
			name:      "already canonical with account",
			shorthand: "default/observability/sentry:acme/auth_token",
			defaults:  defaultDefaults,
			resolve:   defaultResolver,
			want:      "default/observability/sentry:acme/auth_token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := vpath.Canonicalize(tc.shorthand, tc.defaults, tc.resolve)
			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Errorf("want err %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("want %q, got %q", tc.want, got)
			}
		})
	}
}

// -----------------------------------------------------------------------
// Parts tests
// -----------------------------------------------------------------------

func TestParts(t *testing.T) {
	cases := []struct {
		name      string
		canonical string
		want      vpath.PathParts
		wantErr   error
	}{
		{
			name:      "simple canonical",
			canonical: "default/ai/openrouter/api_key",
			want: vpath.PathParts{
				Namespace: "default",
				Category:  "ai",
				Provider:  "openrouter",
				Account:   "",
				Field:     "api_key",
			},
		},
		{
			name:      "canonical with account",
			canonical: "default/observability/sentry:acme/auth_token",
			want: vpath.PathParts{
				Namespace: "default",
				Category:  "observability",
				Provider:  "sentry",
				Account:   "acme",
				Field:     "auth_token",
			},
		},
		{
			name:      "empty string",
			canonical: "",
			wantErr:   vpath.ErrInvalidPath,
		},
		{
			name:      "too few segments",
			canonical: "default/ai/openrouter",
			wantErr:   vpath.ErrInvalidPath,
		},
		{
			name:      "empty segment",
			canonical: "default//openrouter/api_key",
			wantErr:   vpath.ErrInvalidPath,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := vpath.Parts(tc.canonical)
			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Errorf("want err %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("want %+v, got %+v", tc.want, got)
			}
		})
	}
}

// -----------------------------------------------------------------------
// Round-trip test
// -----------------------------------------------------------------------

func TestRoundTrip(t *testing.T) {
	canonicals := []string{
		"default/ai/openrouter/api_key",
		"personal/observability/sentry:acme/auth_token",
		"default/storage/dropbox/access_token",
	}

	for _, canonical := range canonicals {
		t.Run(canonical, func(t *testing.T) {
			parts, err := vpath.Parts(canonical)
			if err != nil {
				t.Fatalf("Parts: %v", err)
			}

			// Reconstruct canonical from parts.
			providerSegment := parts.Provider
			if parts.Account != "" {
				providerSegment += ":" + parts.Account
			}
			reconstructed := parts.Namespace + "/" + parts.Category + "/" + providerSegment + "/" + parts.Field

			if reconstructed != canonical {
				t.Errorf("round-trip failed: %q != %q", reconstructed, canonical)
			}
		})
	}
}
