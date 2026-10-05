package redact

import (
	"strings"
	"testing"
)

func TestBody_InlineSecretsInEveryProfile(t *testing.T) {
	const secret = "Qw8rT2yU6iO0pA4s"
	bodies := map[string]string{
		"url userinfo": `{"database_url":"postgres://app:` + secret + `@db:5432/app"}`,
		"pem":          `{"note":"-----BEGIN PRIVATE KEY-----\nMIIE` + secret + `\n-----END PRIVATE KEY-----"}`,
		"name value":   `{"vars":[{"name":"STRIPE_SECRET","value":"` + secret + `"}]}`,
		"aws key":      `{"aws_secret_access_key":"` + secret + `"}`,
		"xml":          `<auth><token>` + secret + `</token></auth>`,
	}
	for _, profile := range []MaskingProfile{"", ProfileBasic, ProfileStrict} {
		for name, body := range bodies {
			if out := string(Body("generic", []byte(body), profile, nil)); strings.Contains(out, secret) {
				t.Errorf("profile %q, %s: secret survived: %s", profile, name, out)
			}
		}
	}
}

func TestBody_StrictCoversStandardBase64(t *testing.T) {
	tok := "aB3+dE6/gH9+jK2/mN5+pQ8/sT1+vW4/yZ7="
	out := string(Body("generic", []byte("token is "+tok), ProfileStrict, nil))
	if strings.Contains(out, "+") || strings.Contains(out, "gH9") {
		t.Fatalf("standard base64 token survived strict masking: %s", out)
	}
}
