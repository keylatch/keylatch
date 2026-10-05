package masking

import (
	"encoding/json"
	"strings"
	"testing"
)

const leaked = "hunter2-Leak9"

func TestIsSensitiveKey(t *testing.T) {
	sensitive := []string{
		"password", "Password", "PASSWORD", "db_password", "db.password", "user-password",
		"passwd", "pwd", "passphrase", "secret", "client_secret", "clientSecret",
		"token", "access_token", "id_token", "X-Auth-Token", "api_key", "apiKey",
		"api-key", "X-Api-Key", "apikey", "private_key", "privateKey",
		"Authorization", "proxy-authorization", "cookie", "Set-Cookie",
		"credential", "credentials",
	}
	for _, k := range sensitive {
		if !IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = false, want true", k)
		}
	}
	benign := []string{
		"max_tokens", "token_type", "tokens_used", "next_page_token", "nextPageToken",
		"continuation-token", "cursor_token", "sync_token", "id", "name", "secret_id",
	}
	for _, k := range benign {
		if IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = true, want false", k)
		}
	}
}

func TestRedactSecretFieldsFormats(t *testing.T) {
	cases := []struct {
		name string
		body string
		keep []string
	}{
		{"flat json", `{"user":"ann","password":"` + leaked + `"}`, []string{`"user":"ann"`}},
		{"nested json", `{"data":{"items":[{"db":{"Passwd":"` + leaked + `"}}]}}`, nil},
		{"numeric value", `{"pin":1,"pwd":12345678901}`, []string{`"pin":1`}},
		{"object value", `{"credentials":{"user":"a","key":"` + leaked + `"}}`, nil},
		{"json array root", `[{"client_secret":"` + leaked + `"}]`, nil},
		{"malformed json", `{"password": "` + leaked + `", "x": [`, []string{`"x": [`}},
		{"truncated json", `{"items":[{"api_key":"` + leaked, nil},
		{"form encoded", "user=ann&password=" + leaked + "&remember=1", []string{"user=ann", "remember=1"}},
		{"query string", "/cb?code=1&access_token=" + leaked, []string{"code=1"}},
		{"header block", "Content-Type: text/plain\r\nAuthorization: Bearer " + leaked + "\r\nSet-Cookie: s=" + leaked + "; Path=/\r\n", []string{"Content-Type: text/plain"}},
		{"yaml-ish", "db:\n  passphrase: " + leaked + "\n", []string{"db:"}},
		{"single quoted", `{'secret': '` + leaked + `'}`, nil},
		{"unknown format", "<x><token>abc</token>password=" + leaked + "</x>", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := string(RedactSecretFields([]byte(tc.body), redactedPlaceholder))
			if strings.Contains(out, leaked) {
				t.Fatalf("secret survived: %s", out)
			}
			if !strings.Contains(out, redactedPlaceholder) {
				t.Fatalf("no placeholder in %s", out)
			}
			for _, k := range tc.keep {
				if !strings.Contains(out, k) {
					t.Errorf("lost non-secret %q: %s", k, out)
				}
			}
		})
	}
}

func TestRedactSecretFieldsLeavesBenignContentAlone(t *testing.T) {
	bodies := []string{
		`{"max_tokens":100,"token_type":"bearer","next_page_token":"abc123","has_password":true}`,
		"plain text with no credentials",
		"",
	}
	for _, b := range bodies {
		if got := string(RedactSecretFields([]byte(b), redactedPlaceholder)); got != b {
			t.Errorf("RedactSecretFields(%q) = %q, want unchanged", b, got)
		}
	}
}

func TestRedactSecretFieldsKeepsJSONValid(t *testing.T) {
	out := RedactSecretFields([]byte(`{"a":"<b>&","n":12345678901234567890,"token":"`+leaked+`"}`), redactedPlaceholder)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("output is not JSON: %v: %s", err, out)
	}
	if !strings.Contains(string(out), `"<b>&"`) || !strings.Contains(string(out), "12345678901234567890") {
		t.Errorf("unrelated values altered: %s", out)
	}
}
