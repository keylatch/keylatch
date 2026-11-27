package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/keylatch/keylatch/internal/registry"
)

const scrubMask = "****"

// credentialScrubber masks a credential the gateway injected if the upstream
// echoes it back (an error page, a debug endpoint, a redirect Location). It
// covers the raw value and the encodings the injection itself can produce.
type credentialScrubber struct{ variants [][]byte }

func newCredentialScrubber(placement registry.AuthPlacement, cred []byte) *credentialScrubber {
	if len(cred) == 0 {
		return &credentialScrubber{}
	}
	seen := map[string]bool{}
	var out [][]byte
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, []byte(v))
		}
	}
	c := string(cred)
	add(c)
	for _, esc := range []string{url.QueryEscape(c), url.PathEscape(c)} {
		add(esc)
		add(lowerPercentHex(esc))
	}
	// JSON string forms: with and without Go's \u003c style HTML escaping, and
	// with escaped slashes (\/) as PHP and some other encoders write them.
	for _, escapeHTML := range []bool{true, false} {
		if j, ok := jsonEscaped(c, escapeHTML); ok {
			add(j)
			add(strings.ReplaceAll(j, "/", `\/`))
		}
	}
	add(html.EscapeString(c))
	enc := func(raw string) {
		b := []byte(raw)
		add(base64.StdEncoding.EncodeToString(b))
		add(base64.RawStdEncoding.EncodeToString(b))
		add(base64.URLEncoding.EncodeToString(b))
		add(base64.RawURLEncoding.EncodeToString(b))
	}
	enc(c)
	if placement.In == "basic" {
		enc(placement.Name + ":" + c)
	}
	// Longest first, so a variant that contains another is masked whole.
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return &credentialScrubber{variants: out}
}

// lowerPercentHex lowercases the hex digits of every %XX escape.
func lowerPercentHex(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] = byte(strings.ToLower(string(b[i+1]))[0])
			b[i+2] = byte(strings.ToLower(string(b[i+2]))[0])
			i += 2
		}
	}
	return string(b)
}

// jsonEscaped returns s as it appears inside a JSON string, without the quotes.
func jsonEscaped(s string, escapeHTML bool) (string, bool) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(s); err != nil {
		return "", false
	}
	out := strings.TrimSuffix(buf.String(), "\n")
	if len(out) < 2 {
		return "", false
	}
	return out[1 : len(out)-1], true
}

// bytes masks every variant in b. The gateway buffers the whole response before
// this runs, so a match cannot straddle a read boundary.
func (s *credentialScrubber) bytes(b []byte) []byte {
	for _, v := range s.variants {
		if bytes.Contains(b, v) {
			b = bytes.ReplaceAll(b, v, []byte(scrubMask))
		}
	}
	return b
}

// headers masks every value of every header.
func (s *credentialScrubber) headers(h http.Header) {
	for _, vv := range h {
		for i, v := range vv {
			vv[i] = string(s.bytes([]byte(v)))
		}
	}
}
