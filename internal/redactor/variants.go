package redactor

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	minSecretLen  = 4
	minVariantLen = 4
)

type variant struct {
	name string
	data []byte
}

type variantSet struct {
	seen map[string]struct{}
	out  []variant
}

func (s *variantSet) add(name string, data []byte) {
	if len(data) < minVariantLen {
		return
	}
	if _, dup := s.seen[string(data)]; dup {
		return
	}
	s.seen[string(data)] = struct{}{}
	s.out = append(s.out, variant{name: name, data: data})
}

func (s *variantSet) addString(name, v string) { s.add(name, []byte(v)) }

// variantsOf returns every byte sequence under which a child could print
// secret: raw, base64 (std and url alphabets, padded and unpadded, at each of
// the three alignments within a larger base64 stream), hex, percent-encoding
// and JSON string escaping.
func variantsOf(secret []byte) []variant {
	s := &variantSet{seen: map[string]struct{}{}}
	s.add("raw", bytes.Clone(secret))
	addBase64(s, secret)
	h := hex.EncodeToString(secret)
	s.addString("hex", h)
	s.addString("hex", strings.ToUpper(h))
	addPercent(s, secret)
	addJSON(s, secret)
	return s.out
}

// base64 alignment: when the secret sits at byte offset k (mod 3) inside a
// larger encoded stream, the first encoded character mixes bits of the
// preceding bytes, so each possible value of those bits is enumerated. The
// last partial character is only deterministic at the end of the stream, so
// both the trimmed and the complete forms are included.
func addBase64(s *variantSet, secret []byte) {
	type lead struct {
		prefix []byte
		start  int
	}
	leads := []lead{{nil, 0}}
	for j := 0; j < 4; j++ {
		leads = append(leads, lead{[]byte{byte(j)}, 1})
	}
	for j := 0; j < 16; j++ {
		leads = append(leads, lead{[]byte{0, byte(j)}, 2})
	}
	for _, enc := range []struct {
		name string
		e    *base64.Encoding
	}{{"base64", base64.StdEncoding}, {"base64url", base64.URLEncoding}} {
		raw := enc.e.WithPadding(base64.NoPadding)
		for _, l := range leads {
			buf := append(bytes.Clone(l.prefix), secret...)
			e := raw.EncodeToString(buf)
			determined := len(buf) * 8 / 6
			s.addString(enc.name, e[l.start:determined])
			s.addString(enc.name, e[l.start:])
			s.addString(enc.name, e[l.start:]+strings.Repeat("=", (4-len(e)%4)%4))
		}
	}
}

func addPercent(s *variantSet, secret []byte) {
	all := make([]byte, 0, len(secret)*3)
	for _, b := range secret {
		all = append(all, '%', "0123456789ABCDEF"[b>>4], "0123456789ABCDEF"[b&15])
	}
	forms := []string{string(all), url.QueryEscape(string(secret)), url.PathEscape(string(secret))}
	for _, f := range forms {
		s.addString("percent", f)
		s.addString("percent", lowerPercentHex(f))
	}
}

func lowerPercentHex(v string) string {
	b := []byte(v)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			b[i+1] = lowerHex(b[i+1])
			b[i+2] = lowerHex(b[i+2])
			i += 2
		}
	}
	return string(b)
}

func lowerHex(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + 32
	}
	return c
}

func addJSON(s *variantSet, secret []byte) {
	for _, escapeHTML := range []bool{true, false} {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(escapeHTML)
		if err := enc.Encode(string(secret)); err != nil {
			continue
		}
		e := strings.TrimSuffix(buf.String(), "\n")
		e = e[1 : len(e)-1]
		s.addString("json", e)
		s.addString("json", upperUnicodeEscapes(e))
	}
	if ascii, ok := jsonASCII(secret); ok {
		s.addString("json", ascii)
		s.addString("json", upperUnicodeEscapes(ascii))
	}
}

func jsonASCII(secret []byte) (string, bool) {
	if !utf8.Valid(secret) {
		return "", false
	}
	var b strings.Builder
	for _, r := range string(secret) {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r > 0x7e:
			writeUnicodeEscape(&b, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), true
}

func writeUnicodeEscape(b *strings.Builder, r rune) {
	const digits = "0123456789abcdef"
	put := func(u rune) {
		b.WriteString(`\u`)
		b.WriteByte(digits[u>>12&15])
		b.WriteByte(digits[u>>8&15])
		b.WriteByte(digits[u>>4&15])
		b.WriteByte(digits[u&15])
	}
	if r1, r2 := utf16.EncodeRune(r); r1 != utf8.RuneError && r >= 0x10000 {
		put(r1)
		put(r2)
		return
	}
	put(r)
}

func upperUnicodeEscapes(v string) string {
	b := []byte(v)
	for i := 0; i+5 < len(b); i++ {
		if b[i] == '\\' && b[i+1] == 'u' {
			for j := i + 2; j < i+6; j++ {
				if b[j] >= 'a' && b[j] <= 'f' {
					b[j] -= 32
				}
			}
			i += 5
		}
	}
	return string(b)
}
