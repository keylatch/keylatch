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
	"authorization", "cookie", "credential", "credentials",
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

const sensitiveKeyPattern = `[A-Za-z0-9_.\-]*(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key|authorization|cookie|credentials?)`

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
func RedactSecretFields(body []byte, placeholder string) []byte {
	if len(body) == 0 {
		return body
	}
	if out, ok := redactJSONSecretFields(body, placeholder); ok {
		return out
	}
	return redactTextSecretFields(body, placeholder)
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
		changed := false
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

func concat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}
