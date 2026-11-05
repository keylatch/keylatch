package redact_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/redact"
)

func TestBody_EmptyBodyUnchanged(t *testing.T) {
	for _, in := range [][]byte{nil, {}} {
		if got := redact.Body("openai", in, redact.ProfileMetadataOnly, nil); len(got) != 0 {
			t.Fatalf("empty body became %q", got)
		}
	}
}

func TestBody_StrictProfileMasksLongTokens(t *testing.T) {
	long := strings.Repeat("Ab9_", 10)
	body := []byte(`{"id":"short","blob":"` + long + `"}`)

	strict := string(redact.Body("unknown", body, redact.ProfileStrict, nil))
	if strings.Contains(strict, long) {
		t.Fatalf("strict profile left long token: %s", strict)
	}
	if !strings.Contains(strict, `"short"`) {
		t.Fatalf("strict profile over-redacted short value: %s", strict)
	}

	basic := string(redact.Body("unknown", body, redact.MaskingProfile("basic"), nil))
	if !strings.Contains(basic, long) {
		t.Fatalf("basic profile should not apply strict masking: %s", basic)
	}
}

func TestBody_CommonPatternsKeepKeyName(t *testing.T) {
	body := []byte(`{"password":"hunter2","auth_token":"abcdefghijkl"}`)
	got := string(redact.Body("unknown", body, "", nil))
	if strings.Contains(got, "hunter2") || strings.Contains(got, "abcdefghijkl") {
		t.Fatalf("values not redacted: %s", got)
	}
	if !strings.Contains(got, `"password"`) || !strings.Contains(got, `"auth_token"`) || strings.Count(got, "****") != 2 {
		t.Fatalf("key names not preserved: %s", got)
	}
}

func TestBody_InvalidCallerPatternIgnored(t *testing.T) {
	body := []byte(`{"v":"keep-me"}`)
	got := string(redact.Body("unknown", body, "", []string{"(unclosed", "keep"}))
	if strings.Contains(got, "keep-me") || !strings.Contains(got, "****-me") {
		t.Fatalf("valid pattern after invalid one not applied: %s", got)
	}
}

func TestError_NilAndCleanPassthrough(t *testing.T) {
	if redact.Error(nil) != nil {
		t.Fatal("nil error not preserved")
	}
	orig := errors.New("connection refused")
	if got := redact.Error(orig); got != orig {
		t.Fatalf("clean error should be returned as-is, got %v", got)
	}
}
