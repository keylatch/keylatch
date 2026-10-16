package redactor

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/url"
	"strings"
	"testing"
)

var testSecret = []byte("sk-live-Zq8/x+Yw3Rt5Uv7Bn9Cm1Dk2Fh4Gj6")

func redactChunks(t *testing.T, m *Matcher, input []byte, sizes func(i int) int) []byte {
	t.Helper()
	var out bytes.Buffer
	w := m.NewWriter(&out)
	for i, off := 0, 0; off < len(input); i++ {
		n := min(max(sizes(i), 1), len(input)-off)
		if _, err := w.Write(input[off : off+n]); err != nil {
			t.Fatal(err)
		}
		off += n
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func encodings(secret []byte) map[string]string {
	s := string(secret)
	return map[string]string{
		"raw":          s,
		"b64-std":      base64.StdEncoding.EncodeToString(secret),
		"b64-std-raw":  base64.RawStdEncoding.EncodeToString(secret),
		"b64-url":      base64.URLEncoding.EncodeToString(secret),
		"b64-url-raw":  base64.RawURLEncoding.EncodeToString(secret),
		"hex-lower":    hex.EncodeToString(secret),
		"hex-upper":    strings.ToUpper(hex.EncodeToString(secret)),
		"url-query":    url.QueryEscape(s),
		"url-path":     url.PathEscape(s),
		"json":         strings.Trim(mustJSON(s), `"`),
		"json-unicode": `sk-live`,
		"percent-all":  "%" + strings.Join(strings.Split(strings.ToUpper(hex.EncodeToString(secret)), ""), "%"),
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestWriterRedactsEveryEncodingAcrossChunkBoundaries(t *testing.T) {
	m := NewMatcher(testSecret)
	for name, enc := range encodings(testSecret) {
		if name == "json-unicode" || name == "percent-all" {
			continue
		}
		input := []byte("before " + enc + " after\n")
		for size := 1; size <= len(input); size++ {
			got := redactChunks(t, m, input, func(int) int { return size })
			if bytes.Contains(got, []byte(enc)) || !bytes.Contains(got, []byte(Marker)) {
				t.Fatalf("%s size %d: not redacted: %q", name, size, got)
			}
			if want := "before " + Marker + " after\n"; string(got) != want {
				t.Fatalf("%s size %d: got %q want %q", name, size, got, want)
			}
		}
	}
}

func TestWriterBase64AllAlignments(t *testing.T) {
	m := NewMatcher(testSecret)
	for _, prefix := range []string{"", "a", "ab", "abc", "abcd", "xy", "Authorization: Basic user:"} {
		for _, suffix := range []string{"", "!", "\n", ":pw", "zz"} {
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
				blob := enc.EncodeToString([]byte(prefix + string(testSecret) + suffix))
				got := m.Redact([]byte(blob))
				lo := (len(prefix)*8 + 5) / 6
				hi := (len(prefix) + len(testSecret)) * 8 / 6
				if bytes.Contains(got, []byte(blob[lo:hi])) {
					t.Fatalf("prefix %q suffix %q: secret visible in %q", prefix, suffix, got)
				}
			}
		}
	}
}

func TestWriterLeavesUnrelatedOutputUntouched(t *testing.T) {
	m := NewMatcher(testSecret)
	in := []byte(strings.Repeat("plain output line sk-live not the key\n", 1000))
	if got := redactChunks(t, m, in, func(i int) int { return 7 + i%13 }); !bytes.Equal(got, in) {
		t.Fatal("unrelated output modified")
	}
}

func TestWriterAdjacentAndOverlappingMatches(t *testing.T) {
	m := NewMatcher([]byte("secretvalue"), []byte("valuesecret"))
	if got := string(m.Redact([]byte("secretvaluesecret!"))); got != Marker+"!" {
		t.Fatalf("got %q", got)
	}
	if got := string(m.Redact([]byte("a secretvalue b secretvalue"))); got != "a "+Marker+" b "+Marker {
		t.Fatalf("got %q", got)
	}
}

func TestWriterReleasesCompletedMatchWithoutWaiting(t *testing.T) {
	m := NewMatcher(testSecret)
	var out bytes.Buffer
	w := m.NewWriter(&out)
	_, _ = w.Write([]byte("key=" + string(testSecret) + "\n"))
	if got := out.String(); got != "key="+Marker+"\n" {
		t.Fatalf("held back too much: %q", got)
	}
}

func TestWriterHoldbackIsOnlyAPrefixOfASecret(t *testing.T) {
	m := NewMatcher(testSecret)
	var out bytes.Buffer
	w := m.NewWriter(&out)
	_, _ = w.Write([]byte("hello world\n"))
	if out.String() != "hello world\n" {
		t.Fatalf("unrelated bytes held: %q", out.String())
	}
	_, _ = w.Write([]byte("sk-liv"))
	if out.String() != "hello world\n" {
		t.Fatalf("expected only the secret prefix held: %q", out.String())
	}
	_ = w.Close()
	if out.String() != "hello world\nsk-liv" {
		t.Fatalf("close did not flush: %q", out.String())
	}
}

func TestWriterMemoryIsBounded(t *testing.T) {
	m := NewMatcher(testSecret)
	w := m.NewWriter(io.Discard)
	chunk := bytes.Repeat([]byte("sk-live-Zq8/ noise "), 1<<14)
	for range 50 {
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if cap(w.pending) > 8*sliceSize {
		t.Fatalf("pending grew to %d", cap(w.pending))
	}
}

type failWriter struct{ n int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.n--; f.n < 0 {
		return 0, errors.New("boom")
	}
	return len(p), nil
}

func TestWriterPropagatesErrors(t *testing.T) {
	m := NewMatcher(testSecret)
	w := m.NewWriter(&failWriter{n: 0})
	if _, err := w.Write([]byte("plain text here")); err == nil {
		t.Fatal("expected error")
	}
	if _, err := w.Write([]byte("more")); err == nil {
		t.Fatal("error not sticky")
	}
	if w.Close() == nil {
		t.Fatal("close should report error")
	}
	if _, err := m.NewWriter(io.Discard).Write(nil); err != nil {
		t.Fatal(err)
	}
}

func TestWriterWriteAfterClose(t *testing.T) {
	w := NewMatcher(testSecret).NewWriter(io.Discard)
	_ = w.Close()
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("expected error")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyMatcherPassesThrough(t *testing.T) {
	var out bytes.Buffer
	w := NewMatcher([]byte("ab")).NewWriter(&out)
	_, _ = w.Write([]byte("ab data"))
	_ = w.Close()
	if out.String() != "ab data" {
		t.Fatal(out.String())
	}
}

func TestMatchesCount(t *testing.T) {
	m := NewMatcher(testSecret)
	var out bytes.Buffer
	w := m.NewWriter(&out)
	_, _ = w.Write([]byte(string(testSecret) + " " + string(testSecret)))
	_ = w.Close()
	if w.Matches() != 2 {
		t.Fatalf("matches = %d", w.Matches())
	}
}

func TestContains(t *testing.T) {
	m := NewMatcher(testSecret)
	if !m.Contains([]byte("x "+hex.EncodeToString(testSecret))) || m.Contains([]byte("nothing here")) {
		t.Fatal("Contains wrong")
	}
}

func TestRandomChunkingMatchesWholeBuffer(t *testing.T) {
	m := NewMatcher(testSecret, []byte("another-credential-9f8e"))
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 300; i++ {
		var in bytes.Buffer
		for in.Len() < 2000 {
			encs := encodings(testSecret)
			switch rng.Intn(4) {
			case 0:
				for _, e := range encs {
					in.WriteString(e)
					break
				}
			case 1:
				in.WriteString("another-credential-9f8e")
			default:
				fmt.Fprintf(&in, "line %d\n", rng.Int())
			}
		}
		whole := m.Redact(in.Bytes())
		split := redactChunks(t, m, in.Bytes(), func(int) int { return 1 + rng.Intn(50) })
		if !bytes.Equal(whole, split) {
			t.Fatal("chunked output differs from whole-buffer output")
		}
	}
}
