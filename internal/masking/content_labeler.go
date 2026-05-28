package masking

import (
	"encoding/json"
)

// summarizationPlaceholder is returned when handling == ContentHandlingSummarize.
const summarizationPlaceholder = "__keylatch_content_stripped_pending_summarization__"

// ContentLabeler labels, strips, or summarizes content from untrusted providers.
type ContentLabeler struct{}

// LabelResponse processes a response body from providerID.
// Non-content providers are returned unmodified.
//
//   - Label: wraps content fields with UntrustedContentLabel in the response envelope.
//   - Strip: removes content fields, returns metadata only.
//   - Summarize: returns {"content": "__keylatch_content_stripped_pending_summarization__"}.
func (cl *ContentLabeler) LabelResponse(providerID string, body []byte, policy UntrustedContentPolicy) ([]byte, error) {
	if !UntrustedContentProviders[providerID] {
		// Not an untrusted-content provider — return unmodified.
		return body, nil
	}

	// Truncate if configured.
	if policy.MaxContentChars > 0 && len(body) > policy.MaxContentChars {
		body = body[:policy.MaxContentChars]
	}

	switch policy.Handling {
	case ContentHandlingSummarize:
		m := map[string]string{"content": summarizationPlaceholder}
		return json.Marshal(m)

	case ContentHandlingStrip:
		// Remove content-like fields from the JSON response.
		return stripContentFields(body), nil

	case ContentHandlingLabel, "":
		// Wrap content fields with the untrusted label.
		return labelContentFields(body), nil

	default:
		return body, nil
	}
}

// labelContentFields wraps known content fields in the UntrustedContentLabel envelope.
func labelContentFields(body []byte) []byte {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		// Not JSON — wrap the entire body.
		wrapped := map[string]any{
			UntrustedContentLabel: string(body),
		}
		out, _ := json.Marshal(wrapped)
		return out
	}

	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		if isContentField(k) {
			out[UntrustedContentLabel+":"+k] = v
		} else {
			out[k] = v
		}
	}
	result, err := json.Marshal(out)
	if err != nil {
		return body
	}
	return result
}

// stripContentFields removes content-like fields from the JSON body.
func stripContentFields(body []byte) []byte {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		// Not JSON — return empty object.
		return []byte("{}")
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if !isContentField(k) {
			out[k] = v
		}
	}
	result, err := json.Marshal(out)
	if err != nil {
		return []byte("{}")
	}
	return result
}

// contentFieldNames are JSON field names considered to contain user content.
var contentFieldNames = map[string]bool{
	"body": true, "content": true, "text": true, "message": true,
	"snippet": true, "description": true, "html": true, "plain": true,
	"payload": true, "data": true,
}

// isContentField returns true if the field name is a known content field.
func isContentField(name string) bool {
	return contentFieldNames[name]
}
