// Package redact provides leakage-reduction helpers for the keylatch gateway.
//
// Every redaction.Body() comment includes
// "leakage reduction only, not a primary security control".
//
// Security note: these functions reduce the probability of accidental credential
// leakage in responses and logs. They are leakage reduction only, not a primary
// security control. Defense-in-depth requires vault isolation, policy enforcement,
// and capability scoping as the primary controls.
package redact

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// MaskingProfile controls response body filtering.
type MaskingProfile string

const (
	ProfileBasic        MaskingProfile = "basic"
	ProfileStrict       MaskingProfile = "strict"
	ProfileMetadataOnly MaskingProfile = "metadata_only"
)

// sensitiveHeaderNames lists headers that must always be stripped.
// Leakage reduction only, not a primary security control.
var sensitiveHeaderNames = map[string]struct{}{
	"authorization":       {},
	"set-cookie":          {},
	"x-auth-token":        {},
	"x-api-key":           {},
	"cookie":              {},
	"x-api-secret":        {},
	"x-secret-key":        {},
	"proxy-authorization": {},
}

// tokenPatterns are regexes that match common credential patterns in header values.
// Leakage reduction only, not a primary security control.
var tokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}`),
	regexp.MustCompile(`(?i)^[A-Za-z0-9\-_]{32,}$`),
	regexp.MustCompile(`(?i)^sk-[A-Za-z0-9\-_]{20,}$`),
	regexp.MustCompile(`(?i)^sk-or-[A-Za-z0-9\-_]{20,}$`),
	regexp.MustCompile(`(?i)^sntrys_[A-Za-z0-9]{20,}$`),
	regexp.MustCompile(`(?i)^ghp_[A-Za-z0-9]{36,}$`),
	regexp.MustCompile(`(?i)^xoxb-[A-Za-z0-9\-]{20,}$`),
}

// Headers returns a copy of h with auth/secret headers stripped.
// Removes: Authorization, Set-Cookie, X-Auth-Token, X-Api-Key, Cookie,
// and any header whose value matches a known token-pattern regex.
// Leakage reduction only, not a primary security control.
func Headers(h http.Header) http.Header {
	if h == nil {
		return http.Header{}
	}
	out := h.Clone()
	for name := range out {
		lower := strings.ToLower(name)
		if _, blocked := sensitiveHeaderNames[lower]; blocked {
			out.Del(name)
			continue
		}
		// Check values against token patterns.
		values := out.Values(name)
		for _, v := range values {
			for _, re := range tokenPatterns {
				if re.MatchString(v) {
					out.Del(name)
					break
				}
			}
		}
	}
	return out
}

// providerPatterns holds per-provider credential redaction regexes.
// Leakage reduction only, not a primary security control.
var providerPatterns = map[string][]*regexp.Regexp{
	"openrouter": {
		regexp.MustCompile(`sk-or-[A-Za-z0-9\-_]{20,}`),
		regexp.MustCompile(`sk-[A-Za-z0-9\-_]{20,}`),
	},
	"sentry": {
		regexp.MustCompile(`sntrys_[A-Za-z0-9]{32,}`),
	},
	"cloudflare": {
		regexp.MustCompile(`[A-Za-z0-9_-]{37}`), // CF token shape
	},
	"github": {
		regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
		regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`),
	},
}

// commonPatterns are applied regardless of provider.
// Leakage reduction only, not a primary security control.
var commonPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"api[_-]?key"\s*:\s*"[^"]{8,}"`),
	regexp.MustCompile(`(?i)"access[_-]?token"\s*:\s*"[^"]{8,}"`),
	regexp.MustCompile(`(?i)"secret"\s*:\s*"[^"]{8,}"`),
	regexp.MustCompile(`(?i)"password"\s*:\s*"[^"]{3,}"`),
	regexp.MustCompile(`(?i)"auth[_-]?token"\s*:\s*"[^"]{8,}"`),
	regexp.MustCompile(`(?i)"bearer[^"]*"\s*:\s*"[^"]{8,}"`),
}

// Body applies provider-specific redaction patterns + masking profile
// to a response body. Basic pattern redaction always applied;
// strict/metadata_only honoured when declared.
// Leakage reduction only, not a primary security control.
func Body(provider string, body []byte, profile MaskingProfile, patterns []string) []byte {
	if len(body) == 0 {
		return body
	}

	result := string(body)

	// Apply common patterns (basic, always).
	for _, re := range commonPatterns {
		result = re.ReplaceAllStringFunc(result, func(match string) string {
			// Keep the key name, redact the value.
			colonIdx := strings.Index(match, ":")
			if colonIdx < 0 {
				return "****"
			}
			return match[:colonIdx] + `: "****"`
		})
	}

	// Apply provider-specific patterns.
	if pats, ok := providerPatterns[provider]; ok {
		for _, re := range pats {
			result = re.ReplaceAllString(result, "****")
		}
	}

	// Apply caller-supplied patterns (from registry.RedactionRule).
	for _, pat := range patterns {
		if re, err := regexp.Compile(pat); err == nil {
			result = re.ReplaceAllString(result, "****")
		}
	}

	// Strict profile: redact all string values that look like tokens.
	if profile == ProfileStrict {
		strictRe := regexp.MustCompile(`"[A-Za-z0-9\-_\.]{32,}"`)
		result = strictRe.ReplaceAllString(result, `"****"`)
	}

	// Metadata-only profile: strip response body entirely, return empty object.
	if profile == ProfileMetadataOnly {
		return []byte(`{}`)
	}

	return []byte(result)
}

// Error returns a value-free version of err (strips any credential-shaped strings).
// Leakage reduction only, not a primary security control.
func Error(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	// Strip common credential patterns from error messages.
	for _, re := range tokenPatterns {
		msg = re.ReplaceAllString(msg, "****")
	}
	if msg == err.Error() {
		return err
	}
	return errors.New(msg)
}

// LabelUntrustedContent wraps body in an untrusted-content envelope.
// Forward-compat stub for a future redaction mode — returns body unchanged with a
// "untrusted-source" wrapper comment.
// Leakage reduction only, not a primary security control.
func LabelUntrustedContent(body []byte, source string) []byte {
	if len(body) == 0 {
		return body
	}
	// Prefix with a safe metadata wrapper indicating untrusted source.
	// A future version will replace this with a structured envelope.
	prefix := []byte("/* keylatch:untrusted-source:" + sanitiseSource(source) + " */\n")
	return append(prefix, body...)
}

// sanitiseSource strips non-alphanumeric characters from a source label.
func sanitiseSource(source string) string {
	var sb strings.Builder
	for _, r := range source {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
