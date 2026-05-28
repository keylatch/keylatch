package masking

import (
	"bytes"
	"testing"
)

var testRedactor = &Redactor{}

// TestRedactBasic verifies api_key and bearer tokens are redacted at Basic level.
func TestRedactBasic(t *testing.T) {
	body := []byte(`{"query":"hello","api_key":"sk-proj-ABC123","message":"Bearer sk-ant-def456"}`)
	policy := MaskingPolicy{Level: MaskingBasic}

	result, err := testRedactor.Redact(body, policy)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	canaries := []string{"sk-proj-ABC123", "sk-ant-def456"}
	for _, c := range canaries {
		if bytes.Contains(result, []byte(c)) {
			t.Errorf("Basic: canary %q found in redacted output: %s", c, result)
		}
	}
}

// TestRedactStrict verifies email and phone are also redacted at Strict level.
func TestRedactStrict(t *testing.T) {
	body := []byte(`{"email":"user@example.com","phone":"+14155552671","token":"sk-proj-ZZZ"}`)
	policy := MaskingPolicy{Level: MaskingStrict}

	result, err := testRedactor.Redact(body, policy)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	canaries := []string{"user@example.com", "sk-proj-ZZZ"}
	for _, c := range canaries {
		if bytes.Contains(result, []byte(c)) {
			t.Errorf("Strict: canary %q found in redacted output: %s", c, result)
		}
	}
}

// TestRedactMetadataOnly verifies only AllowFields keys are retained.
func TestRedactMetadataOnly(t *testing.T) {
	body := []byte(`{"id":"123","body":"secret content","created_at":"2026-01-01"}`)
	policy := MaskingPolicy{
		Level:       MaskingMetadataOnly,
		AllowFields: []string{"id", "created_at"},
	}

	result, err := testRedactor.Redact(body, policy)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	if bytes.Contains(result, []byte("secret content")) {
		t.Error("MetadataOnly: body field should be absent")
	}
	if !bytes.Contains(result, []byte("123")) {
		t.Error("MetadataOnly: id field should be present")
	}
}

// TestRedactBlockBody verifies BlockBody returns empty object.
func TestRedactBlockBody(t *testing.T) {
	body := []byte(`{"everything":"valuable","sk-proj-TOP-SECRET":"yes"}`)
	policy := MaskingPolicy{Level: MaskingBlockBody}

	result, err := testRedactor.Redact(body, policy)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	if string(result) != "{}" {
		t.Errorf("BlockBody: expected {}, got %s", result)
	}
}

// TestRedactMaxBodyChars verifies truncation happens before redaction.
func TestRedactMaxBodyChars(t *testing.T) {
	longBody := bytes.Repeat([]byte("x"), 200)
	policy := MaskingPolicy{Level: MaskingBasic, MaxBodyChars: 100}

	result, err := testRedactor.Redact(longBody, policy)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	if len(result) > 100 {
		t.Errorf("expected result to be <= 100 chars; got %d", len(result))
	}
}

// TestRedactBlockAttachments verifies attachment URLs are removed when BlockAttachments=true.
func TestRedactBlockAttachments(t *testing.T) {
	body := []byte(`{"file":"https://example.com/attachments/abc123?sig=xyz","name":"doc"}`)
	policy := MaskingPolicy{Level: MaskingBasic, BlockAttachments: true}

	result, err := testRedactor.Redact(body, policy)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	if bytes.Contains(result, []byte("attachments/abc123")) {
		t.Error("BlockAttachments: attachment URL should be redacted")
	}
}

// TestLogRedactor_BearerToken verifies Bearer token is redacted in log messages.
func TestLogRedactor_BearerToken(t *testing.T) {
	msg := "Authorization: Bearer sk-proj-abc123def456"
	result := RedactForLog(msg)

	if bytes.Contains([]byte(result), []byte("sk-proj-abc123def456")) {
		t.Errorf("RedactForLog: Bearer token not redacted: %s", result)
	}
	if !bytes.Contains([]byte(result), []byte("[REDACTED]")) {
		t.Errorf("RedactForLog: expected [REDACTED] marker, got: %s", result)
	}
}

// TestLogRedactor_NonSensitiveUnchanged verifies non-sensitive messages are unmodified.
func TestLogRedactor_NonSensitiveUnchanged(t *testing.T) {
	msg := "gateway started on port 7878"
	result := RedactForLog(msg)

	if result != msg {
		t.Errorf("RedactForLog modified non-sensitive message: got %q", result)
	}
}

// TestLogRedactor_SlackToken verifies xoxb-* tokens are redacted.
func TestLogRedactor_SlackToken(t *testing.T) {
	msg := "slack token: xoxb-1234567890-abcdefghij"
	result := RedactForLog(msg)

	if bytes.Contains([]byte(result), []byte("xoxb-1234567890-abcdefghij")) {
		t.Errorf("RedactForLog: Slack token not redacted: %s", result)
	}
}
