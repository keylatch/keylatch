package meta

import (
	"errors"
	"unicode"
)

// Sentinel errors returned by Meta.Validate.
var (
	ErrMissingPath              = errors.New("meta: path is required")
	ErrMissingAccessor          = errors.New("meta: accessor is required")
	ErrUnsupportedSchemaVersion = errors.New("meta: unsupported schema version")
	ErrInvalidVersion           = errors.New("meta: current_version must be >= 1")
	ErrInvalidMaxVersions       = errors.New("meta: max_versions must be >= 0")
	ErrExpiresBeforeIssued      = errors.New("meta: expires_at must not be before issued_at")
	ErrInvalidVersionEntry      = errors.New("meta: version entry has version < 1")
	ErrCustomContainsSecret     = errors.New("meta: custom map may contain a secret value")
)

// Validate checks that the Meta is well-formed. Returns the first sentinel
// error found; no error accumulation.
func (m Meta) Validate() error {
	if m.Path == "" {
		return ErrMissingPath
	}
	if m.Accessor.IsZero() {
		return ErrMissingAccessor
	}
	if m.SchemaVersion != CurrentSchemaVersion {
		return ErrUnsupportedSchemaVersion
	}
	if m.CurrentVersion < 1 {
		return ErrInvalidVersion
	}
	if m.MaxVersions < 0 {
		return ErrInvalidMaxVersions
	}
	if m.IssuedAt != nil && m.ExpiresAt != nil && m.ExpiresAt.Before(*m.IssuedAt) {
		return ErrExpiresBeforeIssued
	}
	for _, vm := range m.Versions {
		if vm.Version < 1 {
			return ErrInvalidVersionEntry
		}
	}
	for _, v := range m.Custom {
		if looksLikeSecret(v) {
			return ErrCustomContainsSecret
		}
	}
	return nil
}

// looksLikeSecret is intentionally conservative: it requires both uppercase
// and digit characters. All-lowercase tokens (e.g. some GitHub PATs) are not
// flagged. This avoids false positives on human-readable strings.
//
// Heuristic: length > 20, no spaces, contains uppercase and digits.
func looksLikeSecret(s string) bool {
	if len(s) <= 20 {
		return false
	}
	hasUpper := false
	hasDigit := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			return false
		}
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsDigit(r) {
			hasDigit = true
		}
	}
	return hasUpper && hasDigit
}
