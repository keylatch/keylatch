package masking

import "regexp"

// logSensitivePatterns are patterns applied to log message strings before output.
// Conservative: replaces known token formats with [REDACTED].
var logSensitivePatterns = []*regexp.Regexp{
	// Bearer tokens.
	regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9\-._~+/]+=*`),
	// sk-* keys (OpenAI, Anthropic, etc.)
	regexp.MustCompile(`\bsk-(?:proj-|ant-|or-)?[A-Za-z0-9\-_]{16,}`),
	// Slack bot tokens xoxb-*, xoxp-*, xoxa-*, xoxr-*.
	regexp.MustCompile(`\bxox[bpar]-[A-Za-z0-9\-]+`),
	// AWS AKIA* access key IDs.
	regexp.MustCompile(`\bAKIA[A-Z0-9]{16}\b`),
	// api_key=VALUE in query/form strings.
	regexp.MustCompile(`(?i)(api[_-]?key\s*=\s*)[A-Za-z0-9\-._~+/]{8,}`),
	// GitHub personal access tokens ghp_* / github_pat_*.
	regexp.MustCompile(`\b(ghp_|github_pat_)[A-Za-z0-9]{16,}`),
	// Generic "token": "value" JSON patterns.
	regexp.MustCompile(`(?i)("(?:access_token|refresh_token|id_token|token)"\s*:\s*")[^"]{8,}"`),
}

// RedactForLog applies Basic patterns to a log message string.
// Non-sensitive messages are returned unmodified.
// This function is safe to call on any string — it never panics.
func RedactForLog(message string) string {
	out := message
	for _, re := range logSensitivePatterns {
		out = re.ReplaceAllStringFunc(out, func(match string) string {
			// Preserve the non-sensitive prefix (e.g. "Bearer " or "api_key=").
			loc := re.FindStringSubmatchIndex(match)
			if len(loc) >= 4 && loc[2] >= 0 {
				// Group 1 exists — preserve it, redact the rest.
				// loc[2] is the start index of group 1, loc[3] is the end index.
				prefix := match[loc[2]:loc[3]] // actual group 1 content (M-6)
				return match[:loc[2]] + prefix + "[REDACTED]"
			}
			// No capturing group — redact entire match.
			return "[REDACTED]"
		})
	}
	return out
}
