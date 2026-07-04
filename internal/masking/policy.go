// Package masking implements response body masking, DLP controls,
// and prompt-injection labeling for .
package masking

import "regexp"

// MaskingLevel describes the aggressiveness of response redaction.
type MaskingLevel string

const (
	MaskingBasic        MaskingLevel = "basic"
	MaskingStrict       MaskingLevel = "strict"
	MaskingMetadataOnly MaskingLevel = "metadata_only"
	MaskingBlockBody    MaskingLevel = "block_body"
)

// MaskingPolicy configures how responses are redacted before delivery.
type MaskingPolicy struct {
	Level                  MaskingLevel
	AllowFields            []string
	MaxBodyChars           int
	BlockAttachments       bool
	RequireApprovalForBody bool
}

// SensitiveDataClasses is the registry of 15 compiled regex patterns.
// Classes: api_key, auth_header, oauth_code, refresh_token, access_token,
// presigned_url, password, private_key, email, phone, customer_id,
// payment_id, provider_account_id, attachment_url, prompt_injection_pattern.
var SensitiveDataClasses = map[string]*regexp.Regexp{
	// API keys — common patterns (sk-*, AKIA*, etc.)
	// Matches standalone tokens or JSON field values.
	"api_key": regexp.MustCompile(`(sk-(?:proj-|ant-|or-|)[A-Za-z0-9\-_]+|AKIA[A-Z0-9]+|AIza[A-Za-z0-9\-_]+|ya29\.[A-Za-z0-9\-_]+)`),

	// Authorization header value — Bearer/Basic/Token schemes.
	"auth_header": regexp.MustCompile(`(?i)Bearer [A-Za-z0-9\-._~+/]+=*`),

	// OAuth authorization codes.
	"oauth_code": regexp.MustCompile(`(?i)"code"\s*:\s*"[A-Za-z0-9\-._~+/]{20,}"`),

	// Refresh tokens — JSON field name + value.
	"refresh_token": regexp.MustCompile(`(?i)"refresh_token"\s*:\s*"[A-Za-z0-9\-._~+/]{20,}"`),

	// Access tokens — JSON field name + value.
	"access_token": regexp.MustCompile(`(?i)"access_token"\s*:\s*"[A-Za-z0-9\-._~+/]{20,}"`),

	// Pre-signed URLs (AWS S3, GCS, etc.)
	"presigned_url": regexp.MustCompile(`(?i)(https://[a-z0-9\-]+\.(s3|storage\.googleapis)\.com[^\s"'<>]{1,500}X-[Aa]mz-[Ss]ignature=[A-Za-z0-9%]+)`),

	// Passwords in JSON/query format.
	"password": regexp.MustCompile(`(?i)(["']?password["']?\s*[:=]\s*["']?[^\s"',\]}{]{6,}["']?)`),

	// Private keys (PEM format).
	"private_key": regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----`),

	// Email addresses.
	"email": regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),

	// Phone numbers (E.164 and common formats).
	"phone": regexp.MustCompile(`(\+?[1-9]\d{7,14}|\(\d{3}\)\s*\d{3}[\-\s]\d{4})`),

	// Customer IDs (UUID and common formats).
	"customer_id": regexp.MustCompile(`(?i)(["']?customer[_-]?id["']?\s*[:=]\s*["']?[A-Za-z0-9\-]{6,}["']?)`),

	// Payment IDs (Stripe, etc.)
	"payment_id": regexp.MustCompile(`(?i)(["']?(ch|pi|pay|txn|sub|in|re)_[A-Za-z0-9]{10,}["']?)`),

	// Provider account IDs.
	"provider_account_id": regexp.MustCompile(`(?i)(["']?(account[_-]?id|account[_-]?number)["']?\s*[:=]\s*["']?[A-Za-z0-9\-]{4,}["']?)`),

	// Attachment URLs.
	"attachment_url": regexp.MustCompile(`(?i)(https?://[a-zA-Z0-9.\-/]+/attachments/[A-Za-z0-9\-_/?=&%]+)`),

	// Prompt injection patterns.
	"prompt_injection_pattern": regexp.MustCompile(`(?i)(ignore\s+previous\s+instructions?|system\s*prompt\s*[:=]|<\|im_start\|>|<\|system\|>|\[INST\])`),
}
