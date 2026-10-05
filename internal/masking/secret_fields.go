package masking

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// sensitiveKeySuffixes are normalised field-name endings (lower case, no
// separators) whose values are credentials. Matching on the ending keeps
// "max_tokens" and "token_type" out while catching "client_secret",
// "X-Api-Key" and "db.password".
var sensitiveKeySuffixes = []string{
	"password", "passwd", "pwd", "passphrase",
	"secret", "token", "apikey", "privatekey",
	"secretkey", "accesskey", "jwt", "signature",
	"authorization", "cookie", "credential", "credentials",
}

// sensitiveKeyWords mark a credential anywhere in the name
// ("db_password_prod", "client_secret_value").
var sensitiveKeyWords = []string{"password", "passwd", "passphrase", "secret"}

// identifierKeySuffixes name metadata about a credential rather than the
// credential itself ("secret_name", "password_updated_at", "SecretId").
var identifierKeySuffixes = []string{
	"id", "ids", "name", "names", "arn", "ref", "version", "type", "count",
	"length", "enabled", "required", "policy", "at", "date", "expiry", "expires",
}

// paginationKeySuffixes are opaque cursors that end in "token" but grant
// nothing; redacting them would break paging through responses.
var paginationKeySuffixes = []string{
	"pagetoken", "nexttoken", "continuationtoken", "cursortoken", "synctoken",
}

// IsSensitiveKey reports whether a field, header or parameter name carries a
// credential value.
func IsSensitiveKey(name string) bool {
	n := normaliseKey(name)
	for _, p := range paginationKeySuffixes {
		if strings.HasSuffix(n, p) {
			return false
		}
	}
	for _, s := range sensitiveKeySuffixes {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	for _, w := range sensitiveKeyWords {
		if strings.Contains(n, w) && !hasIdentifierSuffix(n, w) {
			return true
		}
	}
	return false
}

// hasIdentifierSuffix reports whether the part of n after word ends in an
// identifier suffix ("secretname", "passwordupdatedat").
func hasIdentifierSuffix(n, word string) bool {
	rest := n[strings.LastIndex(n, word)+len(word):]
	for _, s := range identifierKeySuffixes {
		if strings.HasSuffix(rest, s) {
			return true
		}
	}
	return false
}

func normaliseKey(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range strings.ToLower(name) {
		switch r {
		case '_', '-', '.', ' ':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

const sensitiveKeyPattern = `[A-Za-z0-9_.\-]*(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key|secret[_-]?key|access[_-]?key|jwt|signature|authorization|cookie|credentials?)[A-Za-z0-9_.\-]*`

// StrictTokenRe matches credential-shaped runs (URL-safe and standard
// base64, hex, dotted JWTs), quoted or not, for strict masking in any format.
var StrictTokenRe = regexp.MustCompile(`[A-Za-z0-9+/_.\-]{32,}={0,2}`)

// privateKeyBlockRe matches PEM private keys, including ones indented in a
// YAML block scalar or embedded in a JSON string with escaped newlines.
var privateKeyBlockRe = regexp.MustCompile(`(?s)-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)

// urlUserinfoRe matches the password in scheme://user:password@host.
var urlUserinfoRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@"'<>]*:)([^\s/@"'<>]+)(@)`)

// envLineRe matches KEY=value lines (dotenv, shell exports); the value runs
// to the end of the line, so multi-word values are covered.
var envLineRe = regexp.MustCompile(`(?m)^([ \t]*(?:export[ \t]+)?)([A-Za-z_][A-Za-z0-9_.\-]*)(=)([^\r\n]*)$`)

// xmlElementRe matches <name attr…>text</name> elements without children.
var xmlElementRe = regexp.MustCompile(`<([A-Za-z_][\w.:\-]*)((?:\s[^<>]*)?)>([^<]*)</([A-Za-z_][\w.:\-]*)>`)

// nameValueRe matches {"name": "DB_PASSWORD", "value": "…"} pairs in text
// that is not valid JSON.
var nameValueRe = regexp.MustCompile(`(?i)("(?:name|key)"\s*:\s*")([^"]*)("\s*,\s*"value"\s*:\s*)("(?:[^"\\]|\\.)*(?:"|$))`)

// headerLineRe matches "Name: value" lines; the whole rest of the line is the
// value, so "Authorization: Bearer x" loses both scheme and token.
var headerLineRe = regexp.MustCompile(`(?im)^([ \t]*)(` + sensitiveKeyPattern + `)([ \t]*:[ \t]*)([^\r\n]+)`)

// pairRe matches key/value pairs in query strings, form bodies, quoted
// key/value text and malformed or truncated JSON; a quoted value cut off
// by truncation runs to the end of the input.
var pairRe = regexp.MustCompile(`(?i)(["']?)(` + sensitiveKeyPattern + `)(["']?)(\s*[:=]\s*)("(?:[^"\\]|\\.)*(?:"|$)|'[^']*(?:'|$)|[^\s&,;}\]"']+)`)

// RedactSecretFields replaces the values of credential-named fields with
// placeholder. Valid JSON is walked structurally, so nested objects and
// arrays are covered; anything else (form bodies, headers, malformed JSON,
// unknown formats) goes through the text patterns. The input is returned
// unchanged when nothing matched.
//
// Private-key blocks and passwords in URLs are redacted in every format.
func RedactSecretFields(body []byte, placeholder string) []byte {
	if len(body) == 0 {
		return body
	}
	out, ok := redactJSONSecretFields(body, placeholder)
	if !ok {
		out = redactTextSecretFields(body, placeholder)
	}
	return redactInlineSecrets(out, placeholder)
}

func redactInlineSecrets(body []byte, placeholder string) []byte {
	out := privateKeyBlockRe.ReplaceAll(body, []byte(placeholder))
	return urlUserinfoRe.ReplaceAllFunc(out, func(m []byte) []byte {
		sub := urlUserinfoRe.FindSubmatch(m)
		return concat(sub[1], []byte(placeholder), sub[3])
	})
}

func redactJSONSecretFields(body []byte, placeholder string) ([]byte, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') || !json.Valid(trimmed) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	v, changed := redactValue(v, placeholder)
	if !changed {
		return body, true
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, false
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), true
}

func redactValue(v any, placeholder string) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		changed := redactNameValuePair(t, placeholder)
		for k, child := range t {
			if IsSensitiveKey(k) && redactableValue(child) {
				t[k] = placeholder
				changed = true
				continue
			}
			nv, c := redactValue(child, placeholder)
			if c {
				t[k] = nv
				changed = true
			}
		}
		return t, changed
	case []any:
		changed := false
		for i, child := range t {
			nv, c := redactValue(child, placeholder)
			if c {
				t[i] = nv
				changed = true
			}
		}
		return t, changed
	}
	return v, false
}

// redactNameValuePair redacts the value of {"name": "DB_PASSWORD",
// "value": "…"} style entries (Kubernetes env, CI variables, parameter
// stores), where the credential name is data rather than a key.
func redactNameValuePair(m map[string]any, placeholder string) bool {
	var name string
	for k, v := range m {
		switch strings.ToLower(k) {
		case "name", "key":
			if s, ok := v.(string); ok {
				name = s
			}
		}
	}
	if name == "" || !IsSensitiveKey(name) {
		return false
	}
	changed := false
	for k, v := range m {
		if strings.ToLower(k) == "value" && redactableValue(v) && v != placeholder {
			m[k] = placeholder
			changed = true
		}
	}
	return changed
}

// redactableValue leaves booleans and nulls alone: "has_password": true
// reveals nothing and keeping the type avoids breaking clients.
func redactableValue(v any) bool {
	switch v.(type) {
	case bool, nil:
		return false
	}
	return true
}

func redactTextSecretFields(body []byte, placeholder string) []byte {
	out := headerLineRe.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := headerLineRe.FindSubmatch(m)
		if !IsSensitiveKey(string(sub[2])) {
			return m
		}
		return concat(sub[1], sub[2], sub[3], []byte(placeholder))
	})
	out = envLineRe.ReplaceAllFunc(out, func(m []byte) []byte {
		sub := envLineRe.FindSubmatch(m)
		if !IsSensitiveKey(string(sub[2])) || len(bytes.TrimSpace(sub[4])) == 0 {
			return m
		}
		return concat(sub[1], sub[2], sub[3], []byte(placeholder))
	})
	out = xmlElementRe.ReplaceAllFunc(out, func(m []byte) []byte {
		sub := xmlElementRe.FindSubmatch(m)
		if !bytes.Equal(sub[1], sub[4]) || !IsSensitiveKey(xmlLocalName(sub[1])) || len(bytes.TrimSpace(sub[3])) == 0 {
			return m
		}
		return concat([]byte("<"), sub[1], sub[2], []byte(">"+placeholder+"</"), sub[4], []byte(">"))
	})
	out = nameValueRe.ReplaceAllFunc(out, func(m []byte) []byte {
		sub := nameValueRe.FindSubmatch(m)
		if !IsSensitiveKey(string(sub[2])) {
			return m
		}
		return concat(sub[1], sub[2], sub[3], []byte(`"`+placeholder+`"`))
	})
	return pairRe.ReplaceAllFunc(out, func(m []byte) []byte {
		sub := pairRe.FindSubmatch(m)
		if !IsSensitiveKey(string(sub[2])) || bytes.HasPrefix([]byte(placeholder), sub[5]) {
			return m
		}
		value := []byte(placeholder)
		if q := sub[5]; len(q) > 0 && (q[0] == '"' || q[0] == '\'') {
			value = concat(q[:1], value, q[:1])
		}
		return concat(sub[1], sub[2], sub[3], sub[4], value)
	})
}

func xmlLocalName(name []byte) string {
	if i := bytes.LastIndexByte(name, ':'); i >= 0 {
		return string(name[i+1:])
	}
	return string(name)
}

func concat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}
