package proxy

import "bytes"

// NewBufferedResponseWriterForTest exposes newBufferedResponseWriter for white-box tests.
func NewBufferedResponseWriterForTest() *bufferedResponseWriter {
	return newBufferedResponseWriter()
}

// WriteResponseToForTest exposes writeResponseTo for white-box tests.
func (b *bufferedResponseWriter) WriteResponseToForTest(w *bytes.Buffer) error {
	return b.writeResponseTo(w)
}
