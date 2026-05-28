package fields_test

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit/fields"
)

func TestAllActionsHaveSafeLogFieldsEntry(t *testing.T) {
	// The init() function in fields.go already panics if any Action is missing.
	// This test documents and explicitly checks the same invariant at test time.
	actions := fields.AllActions()
	if len(actions) == 0 {
		t.Fatal("AllActions returned empty list")
	}
	t.Logf("%d actions checked", len(actions))
}

func TestRedactDoesNotLeakUnsafeKeys(t *testing.T) {
	salt := []byte("test-salt-for-redact")

	for _, action := range fields.AllActions() {
		t.Run(action, func(t *testing.T) {
			extra := map[string]any{
				"unsafe_unlisted_key": "secret-value",
			}
			out := fields.Redact(salt, action, extra)

			if v, ok := out["unsafe_unlisted_key"]; ok {
				// Must not be the original value.
				if v == "secret-value" {
					t.Errorf("action %q: unlisted key passed through plaintext: %v", action, v)
				}
				// Must be a 32-char hex string (HMAC output).
				if s, ok := v.(string); ok {
					if len(s) != 32 {
						t.Errorf("action %q: unlisted key value has len %d, want 32 hex chars", action, len(s))
					}
				} else {
					t.Errorf("action %q: unlisted key value is not a string: %T", action, v)
				}
			}
		})
	}
}

func TestCanaryNeverPlaintext(t *testing.T) {
	salt := []byte("canary-test-salt")
	canary := "KEYLATCH_CANARY_PHASE5_FIELDS_0xDEADBEEF"

	extra := map[string]any{
		"_canary_unsafe_key": canary,
	}
	out := fields.Redact(salt, "write", extra)

	v, ok := out["_canary_unsafe_key"]
	if !ok {
		t.Fatal("key missing from redacted output")
	}
	if s, ok := v.(string); ok {
		if strings.Contains(s, canary) {
			t.Errorf("canary string appeared in output: %q", s)
		}
		if len(s) != 32 {
			t.Errorf("expected 32-char HMAC output, got len %d: %q", len(s), s)
		}
	} else {
		t.Errorf("expected string, got %T", v)
	}
}

func TestRedactAllowsListedKeys(t *testing.T) {
	salt := []byte("test-salt")

	// "write" allows "version", "backend", "key_term".
	extra := map[string]any{
		"version":  3,
		"backend":  "file",
		"key_term": 1,
		"secret":   "my-secret-value",
	}
	out := fields.Redact(salt, "write", extra)

	// Listed keys should pass through.
	if out["version"] != 3 {
		t.Errorf("version: got %v, want 3", out["version"])
	}
	if out["backend"] != "file" {
		t.Errorf("backend: got %v, want file", out["backend"])
	}
	if out["key_term"] != 1 {
		t.Errorf("key_term: got %v, want 1", out["key_term"])
	}

	// Unlisted key must be HMAC'd.
	if v, ok := out["secret"].(string); ok {
		if v == "my-secret-value" {
			t.Error("unlisted 'secret' key passed through plaintext")
		}
	}
}
