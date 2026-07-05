package api

import (
	"fmt"
	"regexp"
	"strings"
)

// RefURIPattern is the canonical regex for valid provider-reference URIs.
// It is kept as a named constant so the frontend can import the equivalent
// string via the /api/provider-templates endpoint.
//
// Pattern breakdown:
// - Scheme: op | aws-sm | hashivault
// - Must have :// followed by at least two non-slash characters (vault segment)
// - Then a literal '/' separator
// - Then at least one more non-slash character (item segment)
// - Minimum valid form: op://vault/item
const RefURIPattern = `^(op|aws-sm|hashivault)://[^/][^/]*/[^/].*`

var refURIRe = regexp.MustCompile(RefURIPattern)

// FieldValidationError records a per-field URI validation failure.
type FieldValidationError struct {
	Field   string `json:"field"`
	Message string `json:"error"`
}

func (e *FieldValidationError) Error() string {
	return fmt.Sprintf("field %q: %s", e.Field, e.Message)
}

// ValidateRefURI returns nil when rawURI is a valid provider-reference URI,
// or a descriptive error otherwise. Used by both the server-side POST handler
// and in tests to verify the shared logic.
func ValidateRefURI(fieldName, rawURI string) *FieldValidationError {
	uri := strings.TrimSpace(rawURI)
	if uri == "" {
		return &FieldValidationError{Field: fieldName, Message: "reference URI must not be empty"}
	}
	if !refURIRe.MatchString(uri) {
		return &FieldValidationError{
			Field:   fieldName,
			Message: "invalid reference URI — expected op://vault/item/field, aws-sm://region/secret-id, or hashivault://mount/path#field",
		}
	}
	return nil
}
