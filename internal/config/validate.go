package config

import (
	"fmt"
	"regexp"
	"strings"
)

// blockedKeywords is the case-insensitive list of key name fragments that
// indicate the user is trying to store a credential in config (which must
// never happen). Security note S05-4: this is a UX hint, NOT a security
// control — values must be stored via `keylatch set` / backend write paths.
var blockedKeywords = []string{
	"password", "secret", "token", "key", "dek", "wrap", "salt", "nonce",
}

// BlockedConfigKey is returned when ValidateSetKey rejects a key name.
type BlockedConfigKey struct {
	Key     string
	Matched string // the blocked keyword that matched
}

func (e *BlockedConfigKey) Error() string {
	return fmt.Sprintf(
		"config key %q looks like a credential (matched %q); "+
			"use `keylatch set` or `keylatch connect` to store secret values",
		e.Key, e.Matched,
	)
}

// ValidateSetKey returns an error if key matches the credential-like blocklist.
// The check is case-insensitive.
func ValidateSetKey(key string) error {
	lower := strings.ToLower(key)
	for _, kw := range blockedKeywords {
		if strings.Contains(lower, kw) {
			return &BlockedConfigKey{Key: key, Matched: kw}
		}
	}
	return nil
}

// credentialShapePatterns matches common credential value shapes.
var credentialShapePatterns = []*regexp.Regexp{
	// JWT: three base64url segments separated by dots.
	regexp.MustCompile(`^[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}$`),
	// OpenAI-style secret key (sk- prefix followed by alphanumeric/hyphen segments).
	regexp.MustCompile(`^sk-[A-Za-z0-9][A-Za-z0-9-]{19,}$`),
	// GitHub personal access token.
	regexp.MustCompile(`^ghp_[A-Za-z0-9]{20,}$`),
	// 40-char hex string (e.g. Git SHA used as secret, legacy API token).
	regexp.MustCompile(`^[0-9a-fA-F]{40}$`),
}

// DetectCredentialShape returns true if value resembles a credential.
// Used by `doctor` to warn when a config value bypassed the key blocklist.
func DetectCredentialShape(value string) bool {
	for _, re := range credentialShapePatterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}
