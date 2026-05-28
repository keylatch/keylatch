// Package path provides canonical four-segment path construction and parsing
// for keylatch secret identifiers. It is a pure, stateless package — no IO,
// no backend calls, no crypto.
package path

import "errors"

// PathParts holds the four canonical segments of a resolved secret path.
type PathParts struct {
	Namespace string
	Category  string
	Provider  string
	Account   string // optional — present when path segment contains ":"
	Field     string
}

// Defaults provides fallback namespace and category when the shorthand omits them.
type Defaults struct {
	Namespace string
	Category  string
}

// CategoryResolver is an injected function that maps a provider slug to its
// canonical category. It returns ErrUnknownProvider when the provider is not
// in the registry.
type CategoryResolver func(provider string) (category string, err error)

// Sentinel errors.
var (
	// ErrAmbiguous is returned when the namespace cannot be determined from the
	// shorthand and no default namespace is configured.
	ErrAmbiguous = errors.New("path: ambiguous — namespace cannot be determined")

	// ErrInvalidPath is returned when the path string is structurally invalid
	// (empty segments, wrong segment count, forbidden sequences).
	ErrInvalidPath = errors.New("path: invalid path")

	// ErrUnknownProvider is returned when the CategoryResolver cannot find the
	// provider slug in the registry.
	ErrUnknownProvider = errors.New("path: unknown provider")
)
