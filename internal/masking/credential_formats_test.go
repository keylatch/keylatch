package masking

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	fmtSecret = "Zx9QvR7mK2pL5tW8"
	fmtPEM    = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + fmtSecret + "\n-----END RSA PRIVATE KEY-----"
)

func TestIsSensitiveKeyCredentialNames(t *testing.T) {
	sensitive := []string{
		"aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", "secretKey", "secret_key",
		"accessKey", "access_key", "jwt", "id_jwt", "signature", "X-Signature",
		"db_password_prod", "client_secret_value", "passwordHash",
	}
	for _, k := range sensitive {
		if !IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = false", k)
		}
	}
	benign := []string{
		"secret_name", "SecretId", "secretArn", "password_updated_at", "passwordPolicy",
		"secret_version", "signature_version", "access_key_id", "token_type", "max_tokens",
		"next_page_token", "name", "value",
	}
	for _, k := range benign {
		if IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = true", k)
		}
	}
}

func TestRedactSecretFieldsMoreFormats(t *testing.T) {
	cases := []struct {
		name, in string
		keep     []string
	}{
		{"aws json", `{"AccessKeyId":"AKIAEXAMPLE","aws_secret_access_key":"` + fmtSecret + `"}`, []string{"AKIAEXAMPLE"}},
		{"camel case secret key", `{"secretKey":"` + fmtSecret + `","region":"eu"}`, []string{`"eu"`}},
		{"jwt field", `{"jwt":"eyJhbGciOi.` + fmtSecret + `.sig"}`, nil},
		{"name value pairs", `{"env":[{"name":"DB_PASSWORD","value":"` + fmtSecret + `"},{"name":"LOG_LEVEL","value":"debug"}]}`, []string{`"debug"`, "DB_PASSWORD"}},
		{"key value pairs", `[{"Key":"api_token","Value":"` + fmtSecret + `"}]`, []string{"api_token"}},
		{"name value text", `{"name": "DB_PASSWORD", "value": "` + fmtSecret + `"`, []string{"DB_PASSWORD"}},
		{"url userinfo json", `{"database_url":"postgres://app:` + fmtSecret + `@db.internal:5432/app"}`, []string{"postgres://app:", "@db.internal"}},
		{"url userinfo text", "connect to mysql://root:" + fmtSecret + "@10.0.0.5/db now", []string{"mysql://root:", "@10.0.0.5"}},
		{"pem in json string", `{"cert_pem":"` + strings.ReplaceAll(fmtPEM, "\n", `\n`) + `"}`, []string{"cert_pem"}},
		{"pem in yaml block scalar", "tls:\n  key: |\n    " + strings.ReplaceAll(fmtPEM, "\n", "\n    ") + "\n  port: 443\n", []string{"port: 443"}},
		{"xml element", `<config><user>bob</user><password>` + fmtSecret + `</password></config>`, []string{"<user>bob</user>", "<password>"}},
		{"xml namespaced element", `<s:Creds><s:SecretAccessKey>` + fmtSecret + `</s:SecretAccessKey></s:Creds>`, []string{"<s:SecretAccessKey>"}},
		{"multi word env value", "DB_PASSWORD=correct horse " + fmtSecret + "\nLOG_LEVEL=debug\n", []string{"LOG_LEVEL=debug"}},
		{"export line", "export API_TOKEN=" + fmtSecret + "\n", []string{"export API_TOKEN="}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := string(RedactSecretFields([]byte(tc.in), "[REDACTED]"))
			if strings.Contains(out, fmtSecret) {
				t.Fatalf("secret survived: %s", out)
			}
			for _, k := range tc.keep {
				if !strings.Contains(out, k) {
					t.Errorf("lost %q: %s", k, out)
				}
			}
			if strings.HasPrefix(strings.TrimSpace(tc.in), "{") && json.Valid([]byte(tc.in)) && !json.Valid([]byte(out)) {
				t.Errorf("valid JSON became invalid: %s", out)
			}
		})
	}
}

func TestRedactSecretFieldsLeavesMetadataAlone(t *testing.T) {
	in := `{"SecretId":"prod/db","secret_name":"prod/db","env":[{"name":"LOG_LEVEL","value":"debug"}],"url":"https://example.com/a?b=c"}`
	if out := string(RedactSecretFields([]byte(in), "[REDACTED]")); out != in {
		t.Fatalf("benign content changed: %s", out)
	}
}

func TestStrictTokenRegexCoversStandardBase64(t *testing.T) {
	tok := "aB3+dE6/gH9+jK2/mN5+pQ8/sT1+vW4/yZ7=="
	if got := StrictTokenRe.ReplaceAllString("key "+tok+" end", "****"); strings.Contains(got, "+") || strings.Contains(got, "/") {
		t.Fatalf("standard base64 token survived: %s", got)
	}
}
