package path_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	vpath "github.com/keylatch/keylatch/internal/vault/path"
)

// FuzzCanonicalize verifies that Canonicalize never panics, never returns
// output with ".." segments, and always returns valid UTF-8.
func FuzzCanonicalize(f *testing.F) {
	// Seed corpus.
	seeds := []string{
		"",
		".",
		"../etc",
		"a/b/c",
		"a\x00b",
		"openrouter.api_key",
		"default/ai/openrouter/api_key",
		"personal:openrouter.api_key",
		"sentry:acme.auth_token",
		"../../../etc/passwd",
		"openrouter",
		"/leading/slash",
		"trailing/slash/",
		"ns:provider.field.extra",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// Resolver that knows a handful of providers.
	fuzzResolver := vpath.CategoryResolver(func(provider string) (string, error) {
		known := map[string]string{
			"openrouter": "ai",
			"sentry":     "observability",
			"dropbox":    "storage",
		}
		cat, ok := known[provider]
		if !ok {
			return "", vpath.ErrUnknownProvider
		}
		return cat, nil
	})
	defaults := vpath.Defaults{Namespace: "default"}

	f.Fuzz(func(t *testing.T, data string) {
		// Must not panic.
		result, err := vpath.Canonicalize(data, defaults, fuzzResolver)
		if err != nil {
			// Error path is fine — just no panic.
			return
		}

		// Output must be valid UTF-8.
		if !utf8.ValidString(result) {
			t.Errorf("Canonicalize(%q) returned invalid UTF-8: %q", data, result)
		}

		// Output must never contain ".." segments.
		for _, seg := range strings.Split(result, "/") {
			if seg == ".." {
				t.Errorf("Canonicalize(%q) returned path with '..' segment: %q", data, result)
			}
		}
	})
}
