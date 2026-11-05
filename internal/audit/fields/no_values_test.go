package fields

import (
	"regexp"
	"testing"
)

// No allowlisted field of any event can carry a value, key or token: names
// that suggest one are refused, and anything not allowlisted is replaced by
// its keyed hash.
func TestAuditNoValues(t *testing.T) {
	valueLike := regexp.MustCompile(`(?i)(^|_)(value|secret|password|passphrase|credential|private|plaintext|bearer|jwt|api_key|apikey)(_|$)`)
	// token_id and token_type are opaque identifiers; any other *token* field
	// is refused.
	tokenLike := regexp.MustCompile(`(?i)token`)
	allowedTokenNames := map[string]bool{"token_id": true, "token_type": true}

	for action, keys := range safeLogFields {
		for _, k := range keys {
			if valueLike.MatchString(k) {
				t.Errorf("%s: allowlisted field %q looks like a value", action, k)
			}
			if tokenLike.MatchString(k) && !allowedTokenNames[k] {
				t.Errorf("%s: allowlisted field %q looks like a token", action, k)
			}
		}
	}

	salt := []byte("no-values")
	out := Redact(salt, "run", map[string]any{
		"connection": "openrouter",
		"value":      "sk-live-0123456789",
		"api_key":    "sk-live-0123456789",
	})
	for k, v := range out {
		if s, _ := v.(string); s == "sk-live-0123456789" {
			t.Errorf("value leaked through field %q", k)
		}
	}
	if out["connection"] != "openrouter" {
		t.Errorf("allowlisted name was altered: %v", out["connection"])
	}
}
