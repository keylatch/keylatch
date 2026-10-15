package placeholder

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
)

var markerRE = regexp.MustCompile(`klph_[a-z2-7]{26}`)

// errLeak is returned by a scanning reader that met a placeholder.
var errLeak = errors.New("placeholder: found outside a bound slot")

// forms returns the byte patterns a placeholder takes after the encodings a
// client could apply before sending it: raw, hex, and base64 at each of the
// three alignments it can have inside a longer encoded string.
func forms(v string) [][]byte {
	out := [][]byte{[]byte(v), []byte(hex.EncodeToString([]byte(v))), []byte(strings.ToUpper(hex.EncodeToString([]byte(v))))}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for k := 0; k < 3; k++ {
			s := enc.EncodeToString(append(make([]byte, k), v...))
			from, to := (8*k+5)/6, 8*(k+len(v))/6
			if to > from {
				out = append(out, []byte(s[from:to]))
			}
		}
	}
	return out
}

// finder reports whether bytes contain any placeholder, including ones from
// other sessions and ones in an encoded form.
type finder struct {
	patterns [][]byte
	window   int
}

func newFinder(values []string) *finder {
	f := &finder{window: len(marker) + tokenLen}
	for _, v := range values {
		for _, p := range forms(v) {
			f.patterns = append(f.patterns, p)
			f.window = max(f.window, len(p))
		}
	}
	return f
}

func (f *finder) in(b []byte) bool {
	if bytes.Contains(b, []byte(marker)) && markerRE.Match(b) {
		return true
	}
	for _, p := range f.patterns {
		if bytes.Contains(b, p) {
			return true
		}
	}
	return false
}

// inString checks s as sent and as percent-decoded.
func (f *finder) inString(s string) bool {
	if f.in([]byte(s)) {
		return true
	}
	if d, err := url.PathUnescape(s); err == nil && d != s && f.in([]byte(d)) {
		return true
	}
	if d, err := url.QueryUnescape(s); err == nil && d != s && f.in([]byte(d)) {
		return true
	}
	return false
}

// scanReader fails a read as soon as a placeholder appears in the stream,
// including one split across two reads.
type scanReader struct {
	r    io.Reader
	f    *finder
	tail []byte
	hit  bool
}

func (s *scanReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		win := append(s.tail, p[:n]...)
		if s.f.in(win) {
			s.hit = true
			return 0, errLeak
		}
		keep := min(s.f.window-1, len(win))
		s.tail = append([]byte(nil), win[len(win)-keep:]...)
	}
	return n, err
}
