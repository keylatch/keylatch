package masking

import (
	"encoding/json"
	"fmt"
)

// redactedPlaceholder replaces matched sensitive strings.
const redactedPlaceholder = "[REDACTED]"

// basicClasses are the data classes applied at MaskingBasic level.
var basicClasses = []string{"api_key", "auth_header", "oauth_code", "access_token", "refresh_token", "private_key"}

// strictClasses adds additional classes on top of basic.
var strictClasses = []string{"email", "phone", "customer_id", "payment_id", "presigned_url"}

// Redactor applies masking policies to response bodies.
type Redactor struct{}

// Redact applies the masking policy to body and returns the redacted bytes.
//
//   - Basic: redacts basicClasses patterns.
//   - Strict: redacts basicClasses + strictClasses patterns.
//   - MetadataOnly: retains only AllowFields keys from a JSON object; strips content.
//   - BlockBody: returns "{}".
//   - MaxBodyChars > 0: truncates body before redaction.
//   - BlockAttachments: removes attachment_url pattern matches.
func (r *Redactor) Redact(body []byte, policy MaskingPolicy) ([]byte, error) {
	// Truncate first.
	if policy.MaxBodyChars > 0 && len(body) > policy.MaxBodyChars {
		body = body[:policy.MaxBodyChars]
	}

	switch policy.Level {
	case MaskingBlockBody:
		return []byte("{}"), nil

	case MaskingMetadataOnly:
		return r.redactToAllowFields(body, policy.AllowFields), nil

	case MaskingStrict:
		out := r.applyClasses(body, basicClasses)
		out = r.applyClasses(out, strictClasses)
		if policy.BlockAttachments {
			out = r.applyClass(out, "attachment_url")
		}
		return out, nil

	case MaskingBasic, "":
		out := r.applyClasses(body, basicClasses)
		if policy.BlockAttachments {
			out = r.applyClass(out, "attachment_url")
		}
		return out, nil

	default:
		return nil, fmt.Errorf("redactor: unknown masking level %q", policy.Level)
	}
}

// applyClasses applies all named data classes to body.
func (r *Redactor) applyClasses(body []byte, classes []string) []byte {
	out := body
	for _, class := range classes {
		out = r.applyClass(out, class)
	}
	return out
}

// applyClass applies a single data class regex to body.
func (r *Redactor) applyClass(body []byte, class string) []byte {
	re, ok := SensitiveDataClasses[class]
	if !ok {
		return body
	}
	return re.ReplaceAll(body, []byte(redactedPlaceholder))
}

// redactToAllowFields parses body as JSON and returns an object
// containing only the keys listed in allowFields.
func (r *Redactor) redactToAllowFields(body []byte, allowFields []string) []byte {
	if len(allowFields) == 0 {
		return []byte("{}")
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		// Not valid JSON — return empty object.
		return []byte("{}")
	}
	allowed := make(map[string]any, len(allowFields))
	fieldSet := make(map[string]bool, len(allowFields))
	for _, f := range allowFields {
		fieldSet[f] = true
	}
	for k, v := range m {
		if fieldSet[k] {
			allowed[k] = v
		}
	}
	out, err := json.Marshal(allowed)
	if err != nil {
		return []byte("{}")
	}
	return out
}
