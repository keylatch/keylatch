package redactor

import "io"

const sliceSize = 4096

type span struct{ start, end int }

// Writer redacts a stream before forwarding it. Bytes that could still
// become part of a match are held back; the amount held depends only on how
// much of the trailing output is a prefix of some secret encoding, which is
// the minimum needed for correctness. Memory is bounded by the slice size
// plus the longest pattern, regardless of stream length.
type Writer struct {
	m       *Matcher
	w       io.Writer
	state   int32
	pending []byte
	spans   []span
	matches int
	err     error
	closed  bool
	// afterMarker collapses adjacent spans into one Marker regardless of how
	// the stream was chunked.
	afterMarker bool
}

// NewWriter returns a Writer that forwards redacted output to w. Close must
// be called to release the held-back tail.
func (m *Matcher) NewWriter(w io.Writer) *Writer {
	return &Writer{m: m, w: w}
}

// Matches returns how many redacted spans have been produced so far.
func (w *Writer) Matches() int { return w.matches }

func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if w.m.Empty() {
		return w.w.Write(p)
	}
	total := len(p)
	for len(p) > 0 {
		n := min(len(p), sliceSize)
		w.consume(p[:n])
		p = p[n:]
		if err := w.release(false); err != nil {
			w.err = err
			return total - len(p), err
		}
	}
	return total, nil
}

func (w *Writer) consume(chunk []byte) {
	for _, b := range chunk {
		w.state = w.m.step(w.state, b)
		w.pending = append(w.pending, b)
		if n := int(w.m.nodes[w.state].match); n > 0 {
			w.addSpan(len(w.pending)-n, len(w.pending))
		}
	}
}

func (w *Writer) addSpan(start, end int) {
	for len(w.spans) > 0 && w.spans[len(w.spans)-1].start >= start {
		w.spans = w.spans[:len(w.spans)-1]
		w.matches--
	}
	if k := len(w.spans); k > 0 && w.spans[k-1].end >= start {
		w.spans[k-1].end = end
		return
	}
	w.spans = append(w.spans, span{start, end})
	w.matches++
}

func (w *Writer) release(final bool) error {
	safe := len(w.pending)
	if !final {
		safe -= int(w.m.nodes[w.state].hold)
	}
	var out []byte
	i, used := 0, 0
	for _, s := range w.spans {
		if s.end <= safe {
			if s.start > i {
				out = append(out, w.pending[i:s.start]...)
				w.afterMarker = false
			}
			if !w.afterMarker {
				out = append(out, Marker...)
				w.afterMarker = true
			}
			i, used = s.end, used+1
			continue
		}
		if s.start < safe {
			safe = s.start
		}
		break
	}
	if safe > i {
		out = append(out, w.pending[i:safe]...)
		w.afterMarker = false
	}
	if len(out) > 0 {
		if _, err := w.w.Write(out); err != nil {
			return err
		}
	}
	w.spans = w.spans[used:]
	for j := range w.spans {
		w.spans[j].start -= safe
		w.spans[j].end -= safe
	}
	w.pending = append(w.pending[:0], w.pending[safe:]...)
	return nil
}

// Close flushes everything still held back.
func (w *Writer) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err != nil || w.m.Empty() {
		return w.err
	}
	w.err = w.release(true)
	return w.err
}
