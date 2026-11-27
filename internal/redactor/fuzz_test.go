package redactor

import (
	"bytes"
	"testing"
)

// oracleRedact is an independent quadratic reference: every occurrence of any
// variant marks its bytes, and each marked run becomes one Marker.
func oracleRedact(input []byte, secrets ...[]byte) []byte {
	covered := make([]bool, len(input))
	for _, s := range secrets {
		if len(s) < minSecretLen {
			continue
		}
		for _, v := range variantsOf(s) {
			for off := 0; off+len(v.data) <= len(input); off++ {
				if bytes.Equal(input[off:off+len(v.data)], v.data) {
					for i := off; i < off+len(v.data); i++ {
						covered[i] = true
					}
				}
			}
		}
	}
	var out []byte
	for i := 0; i < len(input); i++ {
		if !covered[i] {
			out = append(out, input[i])
			continue
		}
		for i < len(input) && covered[i] {
			i++
		}
		i--
		out = append(out, Marker...)
	}
	return out
}

func FuzzRedactorStream(f *testing.F) {
	f.Add(testSecret, []byte("pre "), []byte(" post\n"), []byte{1, 2, 3}, uint8(0))
	f.Add([]byte("abcd"), []byte("abc"), []byte("dabcd"), []byte{1}, uint8(9))
	f.Add([]byte("AAAAAAAA"), []byte("AAA"), []byte("AAAA"), []byte{2, 5}, uint8(40))
	f.Add([]byte("p@ss w/rd\"\\<>é"), []byte(""), []byte("x"), []byte{7}, uint8(77))
	f.Add([]byte{0, 1, 2, 3, 0xff, 0xfe}, []byte{0xff}, []byte{}, []byte{3}, uint8(3))

	f.Fuzz(func(t *testing.T, secret, prefix, suffix, sizes []byte, pick uint8) {
		if len(secret) > 64 || len(prefix) > 256 || len(suffix) > 256 {
			t.Skip()
		}
		vs := variantsOf(secret)
		var middle []byte
		if len(vs) > 0 {
			middle = vs[int(pick)%len(vs)].data
		}
		input := append(append(append([]byte{}, prefix...), middle...), suffix...)
		m := NewMatcher(secret)
		want := oracleRedact(input, secret)

		var out bytes.Buffer
		w := m.NewWriter(&out)
		for i, off := 0, 0; off < len(input); i++ {
			n := 1
			if len(sizes) > 0 {
				n = 1 + int(sizes[i%len(sizes)])%17
			}
			n = min(n, len(input)-off)
			if _, err := w.Write(input[off : off+n]); err != nil {
				t.Fatal(err)
			}
			off += n
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), want) {
			t.Fatalf("stream output differs from oracle\ninput %q\ngot   %q\nwant  %q", input, out.Bytes(), want)
		}
		if len(secret) >= minSecretLen && len(vs) > 0 && !bytes.Contains(want, []byte(Marker)) {
			t.Fatalf("variant %q in input was not redacted", middle)
		}
	})
}
