package path

import (
	"strings"
	"unicode/utf8"
)

// Canonicalize converts a shorthand secret identifier to a canonical
// four-segment path: namespace/category/provider[":"+account]/field.
//
// Recognised shorthand forms:
//
//  1. Already canonical:   "default/ai/openrouter/api_key"
//  2. provider.field:      "openrouter.api_key"
//  3. ns:provider.field:   "personal:openrouter.api_key"
//  4. prov:account.field:  "sentry:acme.auth_token"
//  5. provider only:       currently returns ErrInvalidPath (no field)
func Canonicalize(shorthand string, defaults Defaults, resolve CategoryResolver) (string, error) {
	if shorthand == "" {
		return "", ErrInvalidPath
	}

	// Reject invalid UTF-8.
	if !utf8.ValidString(shorthand) {
		return "", ErrInvalidPath
	}

	// Reject forbidden sequences.
	if strings.ContainsRune(shorthand, '\x00') {
		return "", ErrInvalidPath
	}
	if strings.Contains(shorthand, "..") {
		return "", ErrInvalidPath
	}
	if strings.HasPrefix(shorthand, "/") || strings.HasSuffix(shorthand, "/") {
		return "", ErrInvalidPath
	}

	// Case 1: already canonical — four slash-separated segments.
	slashCount := strings.Count(shorthand, "/")
	if slashCount == 3 {
		parts := strings.SplitN(shorthand, "/", 4)
		for _, p := range parts {
			if p == "" {
				return "", ErrInvalidPath
			}
		}
		return shorthand, nil
	}
	if slashCount > 0 {
		return "", ErrInvalidPath
	}

	// No slashes — shorthand form.
	// Check for a leading namespace prefix: "ns:..." where the part after ":"
	// contains a dot (otherwise it looks like "provider:account.field").
	ns := defaults.Namespace
	rest := shorthand

	// Check if the shorthand has a colon that could be a namespace prefix.
	// Heuristic: if there's a colon and the right-hand side contains a dot,
	// it's either "ns:provider.field" or "provider:account.field".
	// We distinguish by checking if the left side matches a known provider;
	// if not, we treat it as a namespace override.
	if colonIdx := strings.Index(shorthand, ":"); colonIdx != -1 {
		left := shorthand[:colonIdx]
		right := shorthand[colonIdx+1:]

		if strings.Contains(right, ".") {
			// Could be "ns:provider.field" or "provider:account.field".
			// Try to resolve left as a provider. If found, it's provider:account.field.
			// If not found, treat left as namespace.
			dotIdx := strings.Index(right, ".")
			possibleProvider := right[:dotIdx]
			possibleField := right[dotIdx+1:]

			if possibleProvider == "" || possibleField == "" {
				return "", ErrInvalidPath
			}

			_, provErr := resolve(left)
			if provErr == nil {
				// Left is a provider slug → "provider:account.field" form.
				provider := left
				account := possibleProvider
				field := possibleField

				category, err := resolve(provider)
				if err != nil {
					return "", ErrUnknownProvider
				}

				if ns == "" {
					return "", ErrAmbiguous
				}

				segment := provider + ":" + account
				return assemble(ns, category, segment, field)
			}

			// Left is not a known provider → treat as namespace override.
			ns = left
			// right is "provider.field"
			dotIdx2 := strings.Index(right, ".")
			provider := right[:dotIdx2]
			field := right[dotIdx2+1:]

			if provider == "" || field == "" {
				return "", ErrInvalidPath
			}

			category, err := resolve(provider)
			if err != nil {
				return "", ErrUnknownProvider
			}

			return assemble(ns, category, provider, field)
		}

		// Colon with no dot in right side — not a valid shorthand.
		return "", ErrInvalidPath
	}

	// No colon — "provider.field" form.
	dotIdx := strings.Index(rest, ".")
	if dotIdx == -1 {
		// provider only — no field.
		return "", ErrInvalidPath
	}

	provider := rest[:dotIdx]
	field := rest[dotIdx+1:]

	if provider == "" || field == "" {
		return "", ErrInvalidPath
	}

	category, err := resolve(provider)
	if err != nil {
		return "", ErrUnknownProvider
	}

	if ns == "" {
		return "", ErrAmbiguous
	}

	return assemble(ns, category, provider, field)
}

// assemble builds "ns/category/providerSegment/field" and validates that no
// segment is empty.
func assemble(ns, category, providerSegment, field string) (string, error) {
	if ns == "" || category == "" || providerSegment == "" || field == "" {
		return "", ErrInvalidPath
	}
	return ns + "/" + category + "/" + providerSegment + "/" + field, nil
}
