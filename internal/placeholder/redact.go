package placeholder

import (
	"bytes"
	"io"
	"strings"
)

// swap replaces a real credential with its placeholder in a response, so an
// upstream that echoes the credential back never shows it to the child.
type swap struct{ old, new []byte }

func replaceAll(s string, swaps []swap) string {
	for _, w := range swaps {
		if len(w.old) > 0 {
			s = strings.ReplaceAll(s, string(w.old), string(w.new))
		}
	}
	return s
}

// swapReader applies swaps to a stream, holding back enough of the tail that
// a value split across two reads is still replaced.
type swapReader struct {
	r     io.Reader
	swaps []swap
	keep  int
	carry []byte
	out   []byte
	err   error
}

func newSwapReader(r io.Reader, swaps []swap) *swapReader {
	keep := 0
	for _, w := range swaps {
		keep = max(keep, len(w.old)-1)
	}
	return &swapReader{r: r, swaps: swaps, keep: keep}
}

func (s *swapReader) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		chunk := make([]byte, 32<<10)
		n, err := s.r.Read(chunk)
		data := append(s.carry, chunk[:n]...)
		for _, w := range s.swaps {
			if len(w.old) > 0 {
				data = bytes.ReplaceAll(data, w.old, w.new)
			}
		}
		if err != nil {
			s.out, s.carry, s.err = data, nil, err
			continue
		}
		cut := max(len(data)-s.keep, 0)
		s.out = data[:cut]
		s.carry = append([]byte(nil), data[cut:]...)
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}
