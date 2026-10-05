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
//   - Any other handling value is treated as Summarize: content from an
//     untrusted provider is never returned unprocessed.
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
	case ContentHandlingStrip:
		return stripContentFields(body), nil
	case ContentHandlingLabel, "":
		return labelContentFields(body), nil
	default:
		return json.Marshal(map[string]string{"content": summarizationPlaceholder})
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

	result, err := json.Marshal(labelFields(m))
	if err != nil {
		out, _ := json.Marshal(map[string]any{UntrustedContentLabel: string(body)})
		return out
	}
	return result
}

// labelFields renames content fields at every depth: providers nest user
// content (messages[].body, blocks[].text), not just at the top level.
func labelFields(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			if isContentField(k) {
				out[UntrustedContentLabel+":"+k] = child
			} else {
				out[k] = labelFields(child)
			}
		}
		return out
	case []any:
		for i, child := range t {
			t[i] = labelFields(child)
		}
		return t
	}
	return v
}

// stripContentFields removes content-like fields from the JSON body.
func stripContentFields(body []byte) []byte {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		// Not JSON — return empty object.
		return []byte("{}")
	}
	result, err := json.Marshal(stripFields(m))
	if err != nil {
		return []byte("{}")
	}
	return result
}

func stripFields(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			if !isContentField(k) {
				out[k] = stripFields(child)
			}
		}
		return out
	case []any:
		for i, child := range t {
			t[i] = stripFields(child)
		}
		return t
	}
	return v
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
