package control

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzControlFrame feeds arbitrary bytes to the framing every control request
// passes through. Reading must not panic or buffer more than the frame bound,
// and a frame that decodes into a request must classify without panicking.
func FuzzControlFrame(f *testing.F) {
	f.Add([]byte(`{"op":"exec","verb":"status"}` + "\n"))
	f.Add([]byte(`{"op":"run_session","run":{"connection":"github","command":["true"]}}` + "\n"))
	f.Add([]byte(`{"op":`))
	f.Add(bytes.Repeat([]byte("a"), 4096))
	f.Add([]byte("\x00\xff\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		line, err := readLine(bufio.NewReader(bytes.NewReader(data)), 1<<10)
		if err != nil {
			return
		}
		if len(line) > 1<<10 {
			t.Fatalf("readLine returned %d bytes past its limit", len(line))
		}
		var req Request
		if err := decodeFrame(line, &req); err != nil {
			return
		}
		_ = gated(req)
		_ = IsServedVerb(req.Verb)
	})
}
