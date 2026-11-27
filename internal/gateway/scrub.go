package gateway

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"

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
	add(url.QueryEscape(c))
	add(url.PathEscape(c))
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

// bytes masks every variant in b. The gateway buffers the whole response before
// this runs, so a match cannot straddle a read boundary.
func (s *credentialScrubber) bytes(b []byte) []byte {
	for _, v := range s.variants {
		b = bytes.ReplaceAll(b, v, []byte(scrubMask))
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
